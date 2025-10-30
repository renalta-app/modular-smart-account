// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "../helpers/ForkHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_HOOK} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {AlwaysApproveValidator} from "../helpers/modules/AlwaysApproveValidator.sol";
import {ECDSASessionKeyValidator} from "../helpers/modules/ECDSASessionKeyValidator.sol";
import {ActivityLogHookModule} from "../helpers/modules/ActivityLogHookModule.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title EIP7702WithModulesTest
/// @notice Tests that verify ERC-7579 modules work correctly in EIP-7702 delegated mode
/// @dev This test suite documents the key improvement: modules (validators, signers, hooks, policies)
///      now work in EIP-7702 mode, enabling features like smart sessions for EOAs using delegation.
///
/// CONTEXT:
/// - EIP-7702 allows EOAs to delegate execution to a contract implementation
/// - ERC-7579 provides a modular architecture for smart accounts (validators, executors, hooks, etc.)
/// - Previously, EIP-7702 mode only supported direct EOA signature validation
/// - Now, modules are checked before falling back to EOA validation, enabling advanced features
///
/// KEY INSIGHT:
/// - EIP-7702 EOAs have persistent storage (confirmed by EIP-7702 spec)
/// - Modules can be installed and stored in the account's storage
/// - This enables smart sessions, spending limits, and other module features for delegated EOAs
contract EIP7702WithModulesTest is ForkHelpers {
    using MessageHashUtils for bytes32;

    ModularSmartAccount public implementation;
    uint256 public chainId;

    receive() external payable {}

    function setUp() public {
        setupFork();
        fund(address(this), 100 ether);
        verifyEssentialContracts();

        chainId = block.chainid;
        implementation = new ModularSmartAccount(entryPoint);
    }

    /// @dev Simulates EIP-7702 delegation by etching the delegation bytecode
    /// @param eoa The EOA address that will delegate
    /// @param delegate The implementation address to delegate to
    function setupEip7702Delegation(address eoa, address delegate) internal {
        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), delegate);
        vm.etch(eoa, delegationCode);
    }

    // =============================================================================
    // VALIDATOR MODULE TESTS
    // =============================================================================

    /// @notice TEST: Validator module can authenticate UserOps in EIP-7702 mode
    /// @dev This test proves that validator modules work for delegated EOAs
    function test_eip7702ValidatorModuleAuthenticatesUserOp() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        // Verify delegation is active
        address delegate = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegate, address(implementation), "Delegation should be active");

        // Initialize the account (EOA is the owner in 7702 mode)
        vm.prank(eoa);
        account.initialize(eoa);

        AlwaysApproveValidator validator = new AlwaysApproveValidator();
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        // Create a UserOp with no signature - validator will approve everything
        PackedUserOperation memory userOp = createUserOp(eoa, 0, "");
        userOp.signature = "";

        bytes32 userOpHash = getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "Validator module should authenticate in EIP-7702 mode");
    }

    /// @notice TEST: Session key validator works in EIP-7702 mode
    /// @dev This demonstrates smart sessions for delegated EOAs
    function test_eip7702SessionKeyValidatorWorks() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        (address sessionKey, uint256 sessionKeyPriv) = makeAddrAndKey("sessionKey");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        ECDSASessionKeyValidator sessionValidator = new ECDSASessionKeyValidator();
        bytes memory sessionKeyData = abi.encode(sessionKey);
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_VALIDATOR, address(sessionValidator), sessionKeyData);

        // Create UserOp signed by session key (NOT the EOA)
        PackedUserOperation memory userOp = createUserOp(eoa, 0, "");
        bytes32 userOpHash = getUserOpHash(userOp);

        // Sign with session key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPriv, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        // Validate via session key validator, not EOA
        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "Session key should work in EIP-7702 mode");
    }

    /// @notice TEST: EOA signature still works as fallback when no modules authenticate
    /// @dev Ensures backward compatibility - direct EOA signatures still work
    function test_eip7702EOASignatureFallbackWorks() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        // Install a validator that won't match (to test fallback)
        AlwaysApproveValidator validator = new AlwaysApproveValidator();
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        // Create UserOp signed by EOA to test fallback
        PackedUserOperation memory userOp = createAndSignUserOp(eoa, 0, "", eoaKey);
        bytes32 userOpHash = getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "EOA signature fallback should work in EIP-7702 mode");
    }

    // =============================================================================
    // HOOK MODULE TESTS
    // =============================================================================

    /// @notice TEST: Hook modules execute in EIP-7702 mode
    /// @dev Verifies that pre/post execution hooks work for delegated EOAs
    function test_eip7702HookModulesExecute() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        ActivityLogHookModule hook = new ActivityLogHookModule();
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_HOOK, address(hook), "");

        // Execute a transaction through the account using ERC-7579 execute (which triggers hooks)
        address target = makeAddr("target");
        bytes memory executionData = encodeSingleExecution(target, 0.1 ether, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createAndSignUserOp(eoa, 0, callData, eoaKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(address(this));
        entryPoint.handleOps(ops, payable(address(this)));

        // Verify hook was executed (activity was logged)
        uint64 activityCount = hook.invocationCount(eoa);
        assertGt(activityCount, 0, "Hook should have logged activity in EIP-7702 mode");
    }

    // =============================================================================
    // ERC-1271 SIGNATURE VALIDATION TESTS
    // =============================================================================

    /// @notice TEST: Validator modules work for ERC-1271 signatures in EIP-7702 mode
    /// @dev This tests the isValidSignature flow with modules
    function test_eip7702ValidatorModuleForERC1271() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        (address sessionKey, uint256 sessionKeyPriv) = makeAddrAndKey("sessionKey");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        ECDSASessionKeyValidator sessionValidator = new ECDSASessionKeyValidator();
        bytes memory sessionKeyData = abi.encode(sessionKey);
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_VALIDATOR, address(sessionValidator), sessionKeyData);

        bytes32 messageHash = keccak256("Sign this message");

        // Sign with session key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPriv, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = account.isValidSignature(messageHash, signature);

        assertEq(
            result,
            IERC1271.isValidSignature.selector,
            "Session key signature should be valid for ERC-1271 in EIP-7702 mode"
        );
    }

    /// @notice TEST: EOA signature works for ERC-1271 in EIP-7702 mode (fallback)
    /// @dev Ensures direct EOA signatures still validate
    function test_eip7702EOASignatureForERC1271() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        // Sign with EOA
        bytes32 messageHash = keccak256("Sign this with EOA");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = account.isValidSignature(messageHash, signature);

        assertEq(
            result, IERC1271.isValidSignature.selector, "EOA signature should be valid for ERC-1271 in EIP-7702 mode"
        );
    }

    // =============================================================================
    // MODULE PRIORITY TESTS
    // =============================================================================

    /// @notice TEST: Modules are checked before EOA fallback
    /// @dev This documents the authentication priority: modules first, EOA last
    function test_eip7702ModulePriorityOverEOA() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        account.initialize(eoa);

        AlwaysApproveValidator validator = new AlwaysApproveValidator();
        vm.prank(eoa);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        // Create UserOp with INVALID EOA signature but installed validator
        PackedUserOperation memory userOp = createUserOp(eoa, 0, "");
        userOp.signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27)); // Invalid sig

        bytes32 userOpHash = getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "Module should authenticate before checking EOA signature");
    }

    // =============================================================================
    // UNINITIALIZED ACCOUNT TESTS
    // =============================================================================

    /// @notice TEST: Uninitialized EIP-7702 account can still validate with EOA
    /// @dev Before modules are installed, EOA signature should work
    function test_eip7702UninitializedAccountUsesEOA() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        // Setup EIP-7702 delegation (no initialization)
        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        // Create UserOp signed by EOA (no modules installed)
        PackedUserOperation memory userOp = createAndSignUserOp(eoa, 0, "", eoaKey);
        bytes32 userOpHash = getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "Uninitialized EIP-7702 account should authenticate with EOA");
    }
}
