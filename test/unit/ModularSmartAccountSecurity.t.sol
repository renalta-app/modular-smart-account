// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestCounter} from "../mocks/TestCounter.sol";

/// @title ModularSmartAccountSecurityTest
/// @notice Security-focused tests covering:
/// - Signature validation edge cases
/// - Module authorization boundaries
/// - Access control enforcement
/// - Signature replay protection
/// - Invalid signature handling
contract ModularSmartAccountSecurityTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    // Test modules (reused across tests)
    TestValidatorModule public validator;

    error Unauthorized();

    function setUp() public {
        chainId = block.chainid;
        validator = new TestValidatorModule();
    }

    // ============================================
    // SIGNATURE VALIDATION SECURITY TESTS
    // ============================================

    function test_rejectsInvalidSignatureLength() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp.signature = hex"1234";

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.validateUserOp(packed, userOpHash, 0);
    }

    function test_rejectsSignatureFromWrongSigner() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        (, uint256 wrongSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, wrongSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_FAILED);
    }

    function test_rejectsUserOpWithWrongChainId() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        uint256 wrongChainId = chainId + 1;
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), wrongChainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_FAILED);
    }

    function test_rejectsReplayedSignatureWithDifferentNonce() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        UserOpHelpers.UserOperation memory replayedUserOp = userOp;
        replayedUserOp.nonce = 1;

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(replayedUserOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(replayedUserOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_FAILED);
    }

    function test_rejectsEmptySignature() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp.signature = "";

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.validateUserOp(packed, userOpHash, 0);
    }

    // ============================================
    // MODULE AUTHORIZATION SECURITY TESTS
    // ============================================

    function test_preventsDuplicateModuleInstallation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        vm.prank(owner);
        vm.expectRevert();
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);
    }

    function test_preventsExecuteFromExecutorWhenNotInstalled() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestCounter counter = new TestCounter();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        vm.expectRevert();
        account.executeFromExecutor(MODE_DEFAULT, execData);
    }

    function test_onlyEntryPointCanCallValidateUserOp() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        address randomCaller = createAddress();

        vm.prank(randomCaller);
        vm.expectRevert();
        account.validateUserOp(packed, userOpHash, 0);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_SUCCESS);
    }

    // ============================================
    // ACCESS CONTROL EDGE CASES
    // ============================================

    function test_preventModuleInstallationByNonOwner() public {
        (ModularSmartAccount account,,) = setupAccount();
        address attacker = createAddress();

        bytes memory initData = abi.encode(attacker);

        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);
    }

    function test_preventModuleUninstallationByNonOwner() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        address attacker = createAddress();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");
    }

    function test_preventRegistryConfigurationByNonOwner() public {
        (ModularSmartAccount account,,) = setupAccount();
        address attacker = createAddress();
        address fakeRegistry = createAddress();

        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        account.configureModuleRegistry(fakeRegistry);
    }

    function test_preventAttesterConfigurationByNonOwner() public {
        (ModularSmartAccount account,,) = setupAccount();
        address attacker = createAddress();
        address[] memory attesters = new address[](1);
        attesters[0] = createAddress();

        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        account.configureAttesters(attesters, 1);
    }

    // ============================================
    // ERC-1271 SIGNATURE VALIDATION SECURITY
    // ============================================

    function test_isValidSignatureRejectsInvalidSignature() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        bytes32 hash = keccak256("some message");
        bytes memory invalidSig = hex"1234567890";

        bytes4 result = account.isValidSignature(hash, invalidSig);
        assertEq(result, bytes4(0xffffffff), "Should return invalid signature indicator");
    }

    function test_isValidSignatureRequiresInstalledValidator() public {
        (ModularSmartAccount account,,) = setupAccount();

        bytes32 hash = keccak256("some message");
        bytes memory sig =
            hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12";

        bytes4 result = account.isValidSignature(hash, sig);
        assertEq(result, bytes4(0xffffffff), "Should return invalid signature indicator without validator");
    }

    // ============================================
    // FUZZ TESTS
    // ============================================

    function testFuzz_rejectsArbitraryInvalidSignatures(bytes memory randomSignature) public {
        vm.assume(randomSignature.length > 0 && randomSignature.length < 200);
        vm.assume(randomSignature.length != 65);

        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp.signature = randomSignature;

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.validateUserOp(packed, userOpHash, 0);
    }
}
