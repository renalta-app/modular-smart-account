// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Ownable as SoladyOwnable} from "solady/auth/Ownable.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibCall} from "solady/utils/LibCall.sol";
import {
    IERC7579Execution,
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";

import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {BaseAccount} from "../core/BaseAccount.sol";
import {ModuleStorage} from "./ModuleStorage.sol";
import {ERC7579HookLib} from "../libraries/ERC7579HookLib.sol";
import {ERC7579ExecutionLib} from "../libraries/ERC7579ExecutionLib.sol";
import {ERC7579ModuleLib} from "../libraries/ERC7579ModuleLib.sol";
import {ERC7579FallbackLib} from "../libraries/ERC7579FallbackLib.sol";
import {SignatureValidationLib} from "../libraries/SignatureValidationLib.sol";
import {ERC7780PolicyLib} from "../libraries/ERC7780PolicyLib.sol";
import {ERC7780SignerLib} from "../libraries/ERC7780SignerLib.sol";
import {MODULE_TYPE_STATELESS_VALIDATOR} from "../interfaces/IERC7780.sol";

/// @title ModularSmartAccount
/// @notice ERC-4337 / EIP-7702 compatible account with ERC-7579 module lifecycle support
/// @dev Dual-mode operation:
///      - Normal mode: Full ERC-7579 modular account with validator/executor/hook/fallback modules
///      - EIP-7702 delegate mode: When set as EOA delegate, uses EOA (address(this)) for signature
///        validation fallback and direct execution authorization
///      Supports all ERC-7579 module types and execution modes (single, batch, delegatecall, staticcall)
contract ModularSmartAccount is
    BaseAccount,
    SoladyOwnable,
    UUPSUpgradeable,
    Initializable,
    ReentrancyGuard,
    EIP712,
    IERC721Receiver,
    IERC1155Receiver,
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    IERC7579Execution
{
    using ModuleStorage for ModuleStorage.Layout;
    using ERC7579HookLib for ModuleStorage.Layout;
    using ERC7579ExecutionLib for ModuleStorage.Layout;
    using ERC7579ModuleLib for ModuleStorage.Layout;
    using ERC7579FallbackLib for ModuleStorage.Layout;
    using SignatureValidationLib for ModuleStorage.Layout;
    using ERC7780PolicyLib for ModuleStorage.Layout;
    using ERC7780SignerLib for ModuleStorage.Layout;

    /// @dev The immutable EntryPoint contract for ERC-4337
    IEntryPoint private immutable ENTRY_POINT;

    /// @notice Thrown when the attestation threshold is invalid
    error InvalidThreshold();

    /// @notice Thrown when UserOperation callData is missing / too short
    error InvalidUserOpCallData();

    /// @notice Emitted when the module registry is configured
    /// @param registry The address of the module registry
    event ModuleRegistryConfigured(address indexed registry);

    /// @notice Emitted when attesters are configured
    /// @param attesters The array of trusted attester addresses
    /// @param threshold The minimum number of attestations required
    event AttestersConfigured(address[] attesters, uint8 threshold);

    /// @notice Constructs the account implementation with the EntryPoint
    /// @param anEntryPoint The ERC-4337 EntryPoint contract
    constructor(IEntryPoint anEntryPoint) EIP712("ModularSmartAccount", "1") {
        ENTRY_POINT = anEntryPoint;
        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Authorization modifier that allows both owner and EntryPoint
    ///      Required for functions callable via UserOperations, since msg.sender
    ///      will be the EntryPoint during UserOp execution, not the owner
    modifier onlyOwnerOrEntryPoint() {
        _onlyOwnerOrEntryPoint();
        _;
    }

    /// @dev Internal function to reduce contract size by wrapping modifier logic
    function _onlyOwnerOrEntryPoint() internal view {
        if (msg.sender != owner() && msg.sender != address(entryPoint())) {
            revert Unauthorized();
        }
    }

    /// @notice Allows the account to receive ETH
    receive() external payable {}

    /// @notice Initializes the account with an owner
    /// @dev The ENTRY_POINT member is immutable, to reduce gas consumption. To upgrade EntryPoint,
    ///      a new implementation of ModularSmartAccount must be deployed with the new EntryPoint address,
    ///      then upgrading the implementation by calling `upgradeTo()`
    /// @param anOwner The owner (signer) of this account
    function initialize(address anOwner) external virtual initializer {
        _initializeOwner(anOwner);
    }

    /// @notice Check current account deposit in the EntryPoint
    /// @return The current deposit balance
    function getDeposit() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @notice Deposit more funds for this account in the EntryPoint
    function addDeposit() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw value from the account's deposit
    /// @param withdrawAddress Target to send to
    /// @param amount Amount to withdraw
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) external onlyOwnerOrEntryPoint {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /// @dev Authorization check for UUPS upgrades, restrict to owner
    /// @param newImplementation The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {}

    // ------------------------------------------------------------------------
    // ERC-7579 metadata
    // ------------------------------------------------------------------------

    /// @notice Returns the account ID string
    /// @return The account implementation identifier
    function accountId() external pure override returns (string memory) {
        return "renalta.modular-smart-account.0.1.0";
    }

    /// @notice Checks if an execution mode is supported
    /// @param mode The encoded execution mode
    /// @return True if the execution mode is supported
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);

        bool validCallType = callType == LibERC7579.CALLTYPE_SINGLE || callType == LibERC7579.CALLTYPE_BATCH
            || callType == LibERC7579.CALLTYPE_DELEGATECALL || callType == LibERC7579.CALLTYPE_STATICCALL;

        bool validExecType = execType == LibERC7579.EXECTYPE_DEFAULT || execType == LibERC7579.EXECTYPE_TRY;

        return validCallType && validExecType;
    }

    /// @notice Checks if a module type is supported
    /// @dev Supports ERC-7579 types (1-4) and ERC-7780 types (5-7)
    /// @param moduleTypeId The module type ID to check
    /// @return True if the module type is supported
    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId >= MODULE_TYPE_VALIDATOR && moduleTypeId <= MODULE_TYPE_STATELESS_VALIDATOR;
    }

    // ------------------------------------------------------------------------
    // Module lifecycle
    // ------------------------------------------------------------------------

    /// @notice Installs a module with validation and lifecycle management
    /// @dev Checks module attestation if registry is configured
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to install
    /// @param initData Initialization data to pass to the module
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        override
        onlyOwnerOrEntryPoint
    {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        ERC7579ModuleLib.checkModuleAttestation($, module, moduleTypeId);
        $.installModule(moduleTypeId, module, initData);
    }

    /// @notice Uninstalls a module with cleanup
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to uninstall
    /// @param deInitData De-initialization data to pass to the module
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        override
        onlyOwnerOrEntryPoint
    {
        ModuleStorage.layout().uninstallModule(moduleTypeId, module, deInitData);
    }

    /// @notice Checks if a module is installed
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to check
    /// @param additionalContext Additional context data for the check
    /// @return True if the module is installed
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        return ModuleStorage.layout().isModuleInstalled(moduleTypeId, module, additionalContext);
    }

    // ------------------------------------------------------------------------
    // Module enumeration
    // ------------------------------------------------------------------------

    /// @notice Returns all installed modules of a given type
    /// @param moduleTypeId The module type to query
    /// @return modules Array of installed module addresses
    function getInstalledModules(uint256 moduleTypeId) external view returns (address[] memory modules) {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        uint256 count = $.moduleCount(moduleTypeId);
        modules = new address[](count);
        for (uint256 i = 0; i < count;) {
            modules[i] = $.moduleAt(moduleTypeId, i);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Returns the count of installed modules of a given type
    /// @param moduleTypeId The module type to query
    /// @return The number of installed modules of the given type
    function getModuleCount(uint256 moduleTypeId) external view returns (uint256) {
        return ModuleStorage.layout().moduleCount(moduleTypeId);
    }

    /// @notice Returns the fallback handler for a specific function selector
    /// @param selector The function selector to query
    /// @return The fallback handler address (address(0) if not configured)
    function getFallbackHandler(bytes4 selector) external view returns (address) {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        return $.fallbackHandlers[selector];
    }

    // ------------------------------------------------------------------------
    // ERC-7484 Module Registry Integration
    // ------------------------------------------------------------------------

    /// @notice Configures the ERC-7484 Module Registry for attestation checks
    /// @param registry The registry contract address (address(0) to disable)
    function configureModuleRegistry(address registry) external onlyOwnerOrEntryPoint {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        $.moduleRegistry = registry;
        emit ModuleRegistryConfigured(registry);
    }

    /// @notice Configures trusted attesters and threshold for registry checks
    /// @param attesters Array of trusted attester addresses
    /// @param threshold Minimum number of attestations required
    function configureAttesters(address[] calldata attesters, uint8 threshold) external onlyOwnerOrEntryPoint {
        if (threshold == 0 || threshold > attesters.length) {
            revert InvalidThreshold();
        }
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        $.attesters = attesters;
        $.attestationThreshold = threshold;
        emit AttestersConfigured(attesters, threshold);
    }

    /// @notice Returns the configured module registry address
    /// @return The registry address (address(0) if not configured)
    function getModuleRegistry() external view returns (address) {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        return $.moduleRegistry;
    }

    /// @notice Returns the configured attesters and threshold
    /// @return attesters Array of trusted attester addresses
    /// @return threshold Minimum attestations required
    function getAttesters() external view returns (address[] memory attesters, uint8 threshold) {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        return ($.attesters, $.attestationThreshold);
    }

    // ------------------------------------------------------------------------
    // ERC-165 Interface Support
    // ------------------------------------------------------------------------

    /// @notice Query if a contract implements an interface
    /// @dev Extends to include ERC-1271, ERC-7579, and token receiver interfaces
    /// @param interfaceId The interface identifier, as specified in ERC-165
    /// @return True if the contract implements `interfaceId`
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC1271).interfaceId
            || interfaceId == type(IERC7579AccountConfig).interfaceId
            || interfaceId == type(IERC7579ModuleConfig).interfaceId
            || interfaceId == type(IERC7579Execution).interfaceId || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC1155Receiver).interfaceId;
    }

    // ------------------------------------------------------------------------
    // Execution helpers
    // ------------------------------------------------------------------------

    /// @dev Internal authorization check for execute functions
    ///      In EIP-7702 mode: allows calls from address(this) (the EOA) or EntryPoint
    ///      In normal mode: allows calls from owner or EntryPoint
    function _requireForExecute() internal view override {
        IEntryPoint ep = entryPoint();
        if (EIP7702Utils.fetchDelegate(address(this)) != address(0)) {
            if (msg.sender != address(this) && msg.sender != address(ep)) {
                revert Unauthorized();
            }
            return;
        }
        if (msg.sender != address(ep) && msg.sender != owner()) {
            revert Unauthorized();
        }
    }

    /// @notice Disabled for security - use execute(bytes32,bytes) instead
    /// @dev This inherited function from BaseAccount bypasses ERC-7579 hooks.
    ///      All execution must go through execute(bytes32,bytes) to ensure hooks are invoked.
    function execute(address, uint256, bytes calldata) external override {
        revert("ModularSmartAccount: use execute(bytes32,bytes)");
    }

    /// @notice Disabled for security - use execute(bytes32,bytes) in batch mode instead
    /// @dev This inherited function from BaseAccount bypasses ERC-7579 hooks.
    ///      Use execute(bytes32,bytes) with CALLTYPE_BATCH mode to ensure hooks are invoked.
    function executeBatch(Call[] calldata) external override {
        revert("ModularSmartAccount: use execute(bytes32,bytes) in batch mode");
    }

    /// @notice Executes a UserOperation on behalf of the account
    /// @dev ERC-4337 executeUserOp according to ERC-4337 v0.7 and ERC-7579.
    ///      This function is intended to be called by ERC-4337 EntryPoint.sol.
    ///      Executes userOp.callData[4:] via delegatecall to preserve msg.sender context.
    ///      This enables modules (especially hooks and validators) to access the full
    ///      UserOperation context when needed for advanced validation/tracking.
    /// @param userOp The PackedUserOperation struct (see ERC-4337 v0.7+)
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* _userOpHash */
    )
        external
        payable
    {
        _requireFromEntryPoint();

        if (userOp.callData.length < 4) {
            revert InvalidUserOpCallData();
        }

        // Execute userOp.callData[4:] via delegatecall per ERC-7579 recommendation
        // This preserves the original msg.sender to the account
        (bool success, bytes memory result) = address(this).delegatecall(userOp.callData[4:]);
        if (!success) {
            LibCall.bubbleUpRevert(result);
        }
    }

    /// @notice Executes a transaction on behalf of the account
    /// @dev User-facing execute with no return data per ERC-7579 spec.
    ///      Uses _dispatchExecuteNoReturn() for gas optimization since return data
    ///      is not needed for EntryPoint or owner-initiated calls.
    ///      Supports all execution modes: single call, batch, delegatecall, and staticcall.
    ///      Runs installed hooks (if any) before and after execution.
    ///      Authorization:
    ///      - Normal mode: Only callable by account owner or EntryPoint
    ///      - EIP-7702 mode: Only callable by the EOA (address(this)) or EntryPoint
    /// @param mode The encoded execution mode (callType in upper byte). See LibERC7579 for encoding
    /// @param executionCalldata The encoded execution data (target, value, calldata).
    ///                          Format depends on mode (single vs batch)
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable override nonReentrant {
        _requireForExecute();

        // Run hooks with full msg.data per ERC-7579 spec
        (address[] memory hooks, bytes[] memory contexts) = _runHooksPre(msg.sender, msg.value, msg.data);

        _dispatchExecuteNoReturn(mode, executionCalldata);

        _runHooksPost(hooks, contexts);
    }

    /// @notice Executes a transaction on behalf of the account from an executor module
    /// @dev Module-facing execute that returns call data per ERC-7579 spec.
    ///      This enables executor modules to make decisions based on return values.
    ///      Only callable by installed executor modules. Uses _dispatchExecute()
    ///      which collects and returns execution results.
    ///      Supports all execution modes and runs hooks like execute()
    /// @param mode The encoded execution mode (callType in upper byte)
    /// @param executionCalldata The encoded execution data
    /// @return returnData Array of return data from each executed call.
    ///                    Single calls return array of length 1, batch calls return multiple
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        override
        returns (bytes[] memory)
    {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        if (!$.isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender)) {
            revert ModuleStorage.ModuleNotInstalled(MODULE_TYPE_EXECUTOR, msg.sender);
        }

        // Run hooks with full msg.data per ERC-7579 spec
        (address[] memory hooks, bytes[] memory contexts) = _runHooksPre(msg.sender, msg.value, msg.data);

        bytes[] memory results = _dispatchExecute(mode, executionCalldata);

        _runHooksPost(hooks, contexts);

        return results;
    }

    /// @dev Dispatches execution with return data collection
    /// @param mode The execution mode
    /// @param executionCalldata The execution data
    /// @return Array of return data from executed calls
    function _dispatchExecute(bytes32 mode, bytes calldata executionCalldata) internal returns (bytes[] memory) {
        return ERC7579ExecutionLib.dispatchExecute(mode, executionCalldata);
    }

    /// @dev Dispatches execution without return data (gas optimized)
    /// @param mode The execution mode
    /// @param executionCalldata The execution data
    function _dispatchExecuteNoReturn(bytes32 mode, bytes calldata executionCalldata) internal {
        ERC7579ExecutionLib.dispatchExecuteNoReturn(mode, executionCalldata);
    }

    /// @dev Runs preCheck on all installed hooks before execution
    /// @param caller The caller address
    /// @param value The ETH value
    /// @param callData The call data
    /// @return hooks Array of hook addresses that were called
    /// @return contexts Array of context data from each hook
    function _runHooksPre(address caller, uint256 value, bytes calldata callData)
        internal
        returns (address[] memory hooks, bytes[] memory contexts)
    {
        return ModuleStorage.layout().runHooksPre(caller, value, callData);
    }

    /// @dev Runs postCheck on all hooks after execution
    /// @param hooks Array of hook addresses to call
    /// @param contexts Array of context data for each hook
    function _runHooksPost(address[] memory hooks, bytes[] memory contexts) internal {
        ERC7579HookLib.runHooksPost(hooks, contexts);
    }

    // ------------------------------------------------------------------------
    // Fallback handling
    // ------------------------------------------------------------------------

    /// @notice Fallback function to handle calls to non-existent functions
    /// @dev Routes calls to registered fallback handler modules
    fallback() external payable {
        ModuleStorage.Layout storage $ = ModuleStorage.layout();
        $.handleFallback(msg.data);
    }

    // ------------------------------------------------------------------------
    // Validation overrides
    // ------------------------------------------------------------------------

    /// @notice Validates signature for ERC-4337 UserOperation
    /// @dev Performs complete validation: authentication (signature) + authorization (policies)
    /// @param userOp The user operation to validate
    /// @param userOpHash The hash of the user operation
    /// @return validationData 0 for valid signature, 1 for invalid
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256)
    {
        return ModuleStorage.layout()._validateUserOp(owner(), userOp, userOpHash);
    }

    /// @notice ERC-1271 signature validation with EIP-7739 support
    /// @dev Supports EIP-7739 discovery via magic hash and empty signature
    /// @param hash The hash to validate
    /// @param signature The signature bytes
    /// @return magicValue ERC-1271 magic value if valid, 0xffffffff otherwise, or 0x77390001 for EIP-7739 detection
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        // EIP-7739: Support detection
        // When queried with the magic hash and empty signature, return 0x77390001 to indicate EIP-7739 support
        if (hash == 0x7739773977397739773977397739773977397739773977397739773977397739 && signature.length == 0) {
            return bytes4(0x77390001);
        }

        if (ModuleStorage.layout().isValidSignature(owner(), hash, signature, msg.sender, _domainSeparatorV4())) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }

    // ------------------------------------------------------------------------
    // Token callback handlers
    // ------------------------------------------------------------------------

    /// @notice ERC-721 token receiver callback
    /// @return The function selector to confirm receipt
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /// @notice ERC-1155 single token receiver callback
    /// @return The function selector to confirm receipt
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    /// @notice ERC-1155 batch token receiver callback
    /// @return The function selector to confirm receipt
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }
}
