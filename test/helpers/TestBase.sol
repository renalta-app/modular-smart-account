// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";

/// @title ModularAccountTestBase
/// @notice Base contract for all tests, providing common utilities and helpers
abstract contract ModularAccountTestBase is Test {
    // Common test constants
    address internal constant ADDRESS_ZERO = address(0);
    bytes32 internal constant HASH_ZERO = bytes32(0);
    uint256 internal constant ONE_ETH = 1 ether;
    uint256 internal constant TWO_ETH = 2 ether;
    uint256 internal constant FIVE_ETH = 5 ether;

    // EntryPoint v0.8 address (canonical deployment)
    // For unit tests, we just need an address - tests don't actually call EntryPoint methods
    address internal constant ENTRYPOINT_V08 = address(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);

    // ERC-7579 Module Type Constants
    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    uint256 internal constant MODULE_TYPE_EXECUTOR = 2;
    uint256 internal constant MODULE_TYPE_FALLBACK = 3;
    uint256 internal constant MODULE_TYPE_HOOK = 4;

    // Validation Constants
    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    // ERC-165 Interface IDs
    bytes4 internal constant INTERFACE_ID_ERC165 = 0x01ffc9a7;
    bytes4 internal constant INTERFACE_ID_ERC1271 = 0x1626ba7e;

    // ERC-7579 / Solady LibERC7579 Call Type Constants
    // Note: These must match LibERC7579 from Solady
    uint8 internal constant CALLTYPE_SINGLE = 0x00;
    uint8 internal constant CALLTYPE_BATCH = 0x01;
    uint8 internal constant CALLTYPE_DELEGATECALL = 0xFF;
    uint8 internal constant CALLTYPE_STATICCALL = 0xFE;

    // ERC-7579 Execution Mode Constants (callType in the first/leftmost byte of bytes32)
    bytes32 internal constant MODE_DEFAULT = bytes32(uint256(CALLTYPE_SINGLE) << 248);
    bytes32 internal constant MODE_BATCH = bytes32(uint256(CALLTYPE_BATCH) << 248);
    bytes32 internal constant MODE_DELEGATE = bytes32(uint256(CALLTYPE_DELEGATECALL) << 248);
    bytes32 internal constant MODE_STATIC = bytes32(uint256(CALLTYPE_STATICCALL) << 248);

    // Counter for deterministic account creation
    uint256 private accountCounter = 0;

    /// @notice Create a deterministic account owner
    /// @return account The created account address
    /// @return key The private key
    function createAccountOwner() internal returns (address account, uint256 key) {
        accountCounter++;
        key = uint256(keccak256(abi.encodePacked("test-account", accountCounter)));
        account = vm.addr(key);

        // When running on a fork, ensure the generated address has no code
        // (it might collide with an existing contract on the fork)
        if (account.code.length > 0) {
            vm.etch(account, "");
        }
    }

    /// @notice Create a deterministic address without returning the key
    function createAddress() internal returns (address) {
        (address account,) = createAccountOwner();
        return account;
    }

    /// @notice Fund an address with ETH
    function fund(address target) internal {
        fund(target, ONE_ETH);
    }

    /// @notice Fund an address with specific amount of ETH
    function fund(address target, uint256 amount) internal {
        vm.deal(target, amount);
    }

    /// @notice Get balance of an address
    function getBalance(address target) internal view returns (uint256) {
        return target.balance;
    }

    /// @notice Calculate calldata cost (4 gas for zero bytes, 16 gas for non-zero)
    function callDataCost(bytes memory data) internal pure returns (uint256) {
        uint256 cost = 0;
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] == 0) {
                cost += 4;
            } else {
                cost += 16;
            }
        }
        return cost;
    }

    /// @notice Helper to expect revert with specific error
    function expectRevertWithError(bytes4 errorSelector) internal {
        vm.expectRevert(errorSelector);
    }

    /// @notice Helper to expect revert with error and data
    function expectRevertWithError(bytes memory errorData) internal {
        vm.expectRevert(errorData);
    }

    /// @notice Helper to check if an array contains a specific address
    /// @param array Array of addresses to search
    /// @param target Address to find
    /// @return true if array contains target
    function arrayContains(address[] memory array, address target) internal pure returns (bool) {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == target) return true;
        }
        return false;
    }

    /// @notice Encode a single execution using ERC-7579 spec-compliant packed encoding
    /// @dev Uses abi.encodePacked as specified in the standard for single calls
    function encodeExecution(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(target, value, data);
    }

    /// @notice Encode a delegate call execution using ERC-7579 spec-compliant packed encoding
    /// @dev Delegate calls don't support value, so this only encodes target and data
    function encodeDelegateExecution(address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(target, data);
    }

    /// @notice Execution struct for batch operations
    struct Execution {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Encode a batch execution using ERC-7579 spec-compliant ABI encoding
    /// @dev Uses abi.encode for the array of execution tuples
    function encodeExecutionBatch(Execution[] memory execs) internal pure returns (bytes memory) {
        return abi.encode(execs);
    }

    /// @notice Alias for encodeExecution (for compatibility with fork tests)
    function encodeSingleExecution(address target, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return encodeExecution(target, value, data);
    }

    /// @notice Alias for encodeExecutionBatch that takes separate arrays
    function encodeBatchExecution(address[] memory targets, uint256[] memory values, bytes[] memory datas)
        internal
        pure
        returns (bytes memory)
    {
        require(targets.length == values.length && values.length == datas.length, "Length mismatch");
        Execution[] memory executions = new Execution[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            executions[i] = Execution({target: targets[i], value: values[i], data: datas[i]});
        }
        return encodeExecutionBatch(executions);
    }

    /// @notice Helper to find specific event in recorded logs
    /// @param logs Array of recorded logs from vm.getRecordedLogs()
    /// @param eventSignature Event signature to search for
    /// @return found Whether the event was found
    /// @return logIndex Index of the found log (0 if not found)
    function findEventInLogs(Vm.Log[] memory logs, bytes32 eventSignature)
        internal
        pure
        returns (bool found, uint256 logIndex)
    {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                return (true, i);
            }
        }
        return (false, 0);
    }

    /// @notice Helper to collect all events of a specific type from logs
    /// @param logs Array of recorded logs
    /// @param eventSignature Event signature to filter by
    /// @return matchingLogs Array of matching log entries
    function collectEventLogs(Vm.Log[] memory logs, bytes32 eventSignature)
        internal
        pure
        returns (Vm.Log[] memory matchingLogs)
    {
        // Count matches first
        uint256 matchCount = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                matchCount++;
            }
        }

        // Allocate and populate result array
        matchingLogs = new Vm.Log[](matchCount);
        uint256 index = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                matchingLogs[index] = logs[i];
                index++;
            }
        }
    }

    /// @notice Helper to extract event emitter addresses in order from logs
    /// @param logs Array of recorded logs
    /// @param eventSignature Event signature to filter by
    /// @return emitters Array of emitter addresses in order
    function extractEventEmitters(Vm.Log[] memory logs, bytes32 eventSignature)
        internal
        pure
        returns (address[] memory emitters)
    {
        Vm.Log[] memory matchingLogs = collectEventLogs(logs, eventSignature);
        emitters = new address[](matchingLogs.length);
        for (uint256 i = 0; i < matchingLogs.length; i++) {
            emitters[i] = matchingLogs[i].emitter;
        }
    }

    /// @notice Check if a selector is a reserved account function
    /// @dev Used in fuzz tests to avoid collisions with existing account methods
    /// @param selector Function selector to check
    /// @return true if selector is reserved
    function isReservedSelector(bytes4 selector) internal pure returns (bool) {
        // Exclude zero selector
        if (selector == bytes4(0)) return true;

        // ERC-4337 & Account Core
        if (selector == 0x19822f7c) return true; // validateUserOp
        if (selector == bytes4(keccak256("getDeposit()"))) return true;
        if (selector == bytes4(keccak256("addDeposit()"))) return true;
        if (selector == bytes4(keccak256("withdrawDepositTo(address,uint256)"))) return true;
        if (selector == bytes4(keccak256("entryPoint()"))) return true;

        // ERC-7579 Execution
        if (selector == bytes4(keccak256("execute(bytes32,bytes)"))) return true;
        if (selector == bytes4(keccak256("executeFromExecutor(bytes32,bytes)"))) return true;

        // ERC-7579 Module Management
        if (selector == bytes4(keccak256("installModule(uint256,address,bytes)"))) return true;
        if (selector == bytes4(keccak256("uninstallModule(uint256,address,bytes)"))) return true;
        if (selector == bytes4(keccak256("isModuleInstalled(uint256,address,bytes)"))) return true;

        // ERC-7579 Configuration
        if (selector == bytes4(keccak256("accountId()"))) return true;
        if (selector == bytes4(keccak256("supportsExecutionMode(bytes32)"))) return true;
        if (selector == bytes4(keccak256("supportsModule(uint256)"))) return true;

        // Module Enumeration
        if (selector == bytes4(keccak256("getInstalledModules(uint256)"))) return true;
        if (selector == bytes4(keccak256("getModuleCount(uint256)"))) return true;
        if (selector == bytes4(keccak256("getFallbackHandler(bytes4)"))) return true;
        if (selector == bytes4(keccak256("getActiveHookCount()"))) return true;
        if (selector == bytes4(keccak256("isValidator(address)"))) return true;
        if (selector == bytes4(keccak256("isExecutor(address)"))) return true;

        // ERC-7484 Registry
        if (selector == bytes4(keccak256("configureModuleRegistry(address)"))) return true;
        if (selector == bytes4(keccak256("configureAttesters(address[],uint8)"))) return true;
        if (selector == bytes4(keccak256("getModuleRegistry()"))) return true;
        if (selector == bytes4(keccak256("getAttesters()"))) return true;

        // ERC-1271 & ERC-165
        if (selector == bytes4(keccak256("isValidSignature(bytes32,bytes)"))) return true;
        if (selector == bytes4(keccak256("supportsInterface(bytes4)"))) return true;

        // ERC-1967 Upgrade
        if (selector == bytes4(keccak256("upgradeToAndCall(address,bytes)"))) return true;
        if (selector == bytes4(keccak256("proxiableUUID()"))) return true;

        // Token Receiver Interfaces
        if (selector == bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))) return true;
        if (selector == bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))) return true;
        if (selector == bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))) {
            return true;
        }

        return false;
    }

    // =============================================================================
    // ACCOUNT SETUP HELPERS
    // =============================================================================

    /// @notice Set up a new ModularSmartAccount with owner
    /// @dev Creates implementation, proxy, and initializes with owner
    /// @dev This is the standard pattern used across all tests
    /// @return account The initialized ModularSmartAccount
    /// @return ownerKey The private key of the owner
    /// @return owner The owner address
    function setupAccount() internal returns (ModularSmartAccount account, uint256 ownerKey, address owner) {
        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(IEntryPoint(ENTRYPOINT_V08));
        bytes memory initData = abi.encodeWithSignature("initialize(address)", owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        account = ModularSmartAccount(payable(address(proxy)));
    }

    /// @notice Set up a new ModularSmartAccount with custom EntryPoint
    /// @dev Useful for tests that need a specific EntryPoint instance
    /// @param customEntryPoint The EntryPoint to use
    /// @return account The initialized ModularSmartAccount
    /// @return ownerKey The private key of the owner
    /// @return owner The owner address
    function setupAccount(IEntryPoint customEntryPoint)
        internal
        returns (ModularSmartAccount account, uint256 ownerKey, address owner)
    {
        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(customEntryPoint);
        bytes memory initData = abi.encodeWithSignature("initialize(address)", owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        account = ModularSmartAccount(payable(address(proxy)));
    }

    /// @notice Helper constant for TEN_ETH (commonly used in tests)
    uint256 internal constant TEN_ETH = 10 ether;
}
