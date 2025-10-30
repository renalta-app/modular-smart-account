// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";

import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {TestCounter} from "../mocks/TestCounter.sol";
import {MockERC7484Registry} from "../mocks/MockERC7484Registry.sol";

import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestHookModule} from "../helpers/modules/TestERC7579Modules.sol";

import {OwnerValidatorModule} from "../helpers/modules/OwnerValidatorModule.sol";
import {DirectCallExecutorModule} from "../helpers/modules/DirectCallExecutorModule.sol";
import {ActivityLogHookModule} from "../helpers/modules/ActivityLogHookModule.sol";
import {AlwaysApproveValidator} from "../helpers/modules/AlwaysApproveValidator.sol";
import {AlwaysRejectValidator} from "../helpers/modules/AlwaysRejectValidator.sol";

/// @title ModuleCompositionTest
/// @notice Integration tests for how different module types compose together
/// Multi-validator setup and OR logic, multiple hooks executing in sequence,
/// executor modules for automation, ERC-7484 registry integration,
/// and full account lifecycle scenarios
contract ModuleCompositionTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    // Test modules (reused across tests)
    OwnerValidatorModule public ownerValidator;
    ActivityLogHookModule public activityLogHook;
    TestHookModule public testHook;
    TestCounter public counter;
    AlwaysApproveValidator public alwaysApproveValidator;
    AlwaysRejectValidator public alwaysRejectValidator;

    function setUp() public {
        chainId = block.chainid;
        ownerValidator = new OwnerValidatorModule();
        activityLogHook = new ActivityLogHookModule();
        testHook = new TestHookModule();
        counter = new TestCounter();
        alwaysApproveValidator = new AlwaysApproveValidator();
        alwaysRejectValidator = new AlwaysRejectValidator();
    }

    // ============================================
    // SCENARIO: MULTI-VALIDATOR WITH ACTIVITY MONITORING
    // ============================================

    function test_installPrimaryValidatorAndActivityHook() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        (address primarySigner,) = createAccountOwner();

        bytes memory primaryInit = abi.encode(primarySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), primaryInit);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(activityLogHook), "");

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(ownerValidator), ""),
            "Primary validator should be installed"
        );
        assertEq(activityLogHook.invocationCount(address(account)), 0, "Hook should have 0 invocations initially");
    }

    function test_executeTransactionWithValidatorAndHooksTrackingActivity() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        (address primarySigner,) = createAccountOwner();

        bytes memory primaryInit = abi.encode(primarySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), primaryInit);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(activityLogHook), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execPayload);

        assertEq(activityLogHook.invocationCount(address(account)), 1, "Hook should track 1 invocation");
        assertEq(counter.counters(address(account)), 1, "Counter should be incremented");
    }

    function test_supportMultipleValidatorsOrLogic() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        TestValidatorModule recoveryValidator = new TestValidatorModule();

        (address primarySigner,) = createAccountOwner();
        (address recoverySigner,) = createAccountOwner();

        bytes memory primaryInit = abi.encode(primarySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), primaryInit);

        bytes memory recoveryInit = abi.encode(recoverySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(recoveryValidator), recoveryInit);

        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 2, "Should have 2 validators installed");

        address[] memory installedValidators = account.getInstalledModules(MODULE_TYPE_VALIDATOR);

        assertTrue(arrayContains(installedValidators, address(ownerValidator)), "Primary validator not found");
        assertTrue(arrayContains(installedValidators, address(recoveryValidator)), "Recovery validator not found");

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(ownerValidator), ""),
            "Primary validator should be recognized"
        );
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(recoveryValidator), ""),
            "Recovery validator should be recognized"
        );
    }

    function test_supportMultipleHooksExecutingInSequence() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        (address primarySigner,) = createAccountOwner();

        bytes memory primaryInit = abi.encode(primarySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), primaryInit);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(activityLogHook), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(testHook), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execPayload);

        assertEq(activityLogHook.invocationCount(address(account)), 1, "Activity hook should track invocation");
        assertEq(testHook.hookCount(address(account)), 1, "Test hook should track invocation");
        assertEq(counter.counters(address(account)), 1, "Counter should be incremented");
    }

    // ============================================
    // SCENARIO: EXECUTOR MODULE AUTOMATION
    // ============================================

    /// @notice Test that executor modules can be installed
    /// @dev Note: This test verifies executor installation only. The owner performs the execution.
    /// For actual executor-initiated execution tests, see executor-specific test files.
    function test_installExecutorModule() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        DirectCallExecutorModule executor = new DirectCallExecutorModule();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""), "Executor should be installed"
        );

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execPayload);

        assertEq(counter.counters(address(account)), 1, "Counter should be incremented");
    }

    // ============================================
    // SCENARIO: ERC-7484 REGISTRY INTEGRATION
    // ============================================

    function test_configureRegistryAndRequireAttestationForModuleInstallation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        MockERC7484Registry registry = new MockERC7484Registry();
        (address attester,) = createAccountOwner();

        vm.prank(owner);
        account.configureModuleRegistry(address(registry));
        assertEq(account.getModuleRegistry(), address(registry), "Registry should be configured");

        address[] memory attesters = new address[](1);
        attesters[0] = attester;

        vm.prank(owner);
        account.configureAttesters(attesters, 1);

        (address[] memory returnedAttesters, uint256 threshold) = account.getAttesters();
        assertEq(returnedAttesters.length, 1, "Should have 1 attester");
        assertEq(returnedAttesters[0], attester, "Attester address should match");
        assertEq(threshold, 1, "Threshold should be 1");

        registry.setModuleAttestation(address(ownerValidator), true);
        registry.setModuleTypeValidation(address(ownerValidator), MODULE_TYPE_VALIDATOR, true);

        bytes memory initData = abi.encode(owner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), initData);

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(ownerValidator), ""),
            "Validator should be installed with attestation"
        );
    }

    function test_rejectModuleWithoutAttestation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        MockERC7484Registry registry = new MockERC7484Registry();
        (address attester,) = createAccountOwner();

        vm.prank(owner);
        account.configureModuleRegistry(address(registry));

        address[] memory attesters = new address[](1);
        attesters[0] = attester;

        vm.prank(owner);
        account.configureAttesters(attesters, 1);

        bytes memory initData = abi.encode(owner);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("ModuleNotAttested()"));
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), initData);
    }

    // ============================================
    // SCENARIO: COMPLETE USER JOURNEY
    // ============================================

    function test_demonstrateFullLifecycleSetupUseUpgrade() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        DirectCallExecutorModule executor = new DirectCallExecutorModule();

        (address signer,) = createAccountOwner();
        bytes memory validatorInit = abi.encode(signer);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), validatorInit);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(activityLogHook), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1, "Should have 1 validator");
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""), "Executor should be installed"
        );

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execPayload);

        assertEq(activityLogHook.invocationCount(address(account)), 1, "Hook should track activity");
        assertEq(counter.counters(address(account)), 1, "Counter should be incremented");

        TestValidatorModule recoveryValidator = new TestValidatorModule();
        (address recoverySigner,) = createAccountOwner();
        bytes memory recoveryInit = abi.encode(recoverySigner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(recoveryValidator), recoveryInit);
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 2, "Should have 2 validators after recovery added");

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(recoveryValidator), ""),
            "Recovery validator should be available"
        );

        address[] memory modules = account.getInstalledModules(MODULE_TYPE_VALIDATOR);
        assertEq(modules.length, 2, "Should have 2 validators in list");

        assertTrue(arrayContains(modules, address(ownerValidator)), "Validator not found");
        assertTrue(arrayContains(modules, address(recoveryValidator)), "Recovery validator not found");
    }

    // ============================================
    // SCENARIO: VALIDATOR OR LOGIC
    // ============================================

    /// @dev AlwaysApproveValidator allows any operation
    function test_validatorORLogic_alwaysApproveValidator() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(alwaysApproveValidator), "");

        address recipient = createAddress();
        fund(address(account), ONE_ETH);

        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");

        vm.prank(owner);
        account.execute(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, 0.1 ether, "Transfer should have succeeded with AlwaysApproveValidator");
    }

    /// @dev Owner validation works even when reject validator is installed (OR logic)
    function test_validatorORLogic_ownerOverridesRejectValidator() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(alwaysRejectValidator), "");

        address recipient = createAddress();
        fund(address(account), ONE_ETH);

        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");

        // Owner can still execute despite reject validator (OR logic)
        vm.prank(owner);
        account.execute(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, 0.1 ether, "Transfer should succeed via owner despite reject validator");
    }

    /// @dev Any single approving validator succeeds with multiple validators installed
    function test_validatorORLogic_singleApproverSucceedsWithMultipleValidators() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(alwaysRejectValidator), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(alwaysApproveValidator), "");

        address recipient = createAddress();
        fund(address(account), ONE_ETH);

        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");

        // Should succeed because AlwaysApproveValidator approves (OR logic)
        vm.prank(owner);
        account.execute(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, 0.1 ether, "Transfer should succeed via approve validator");
    }

    /// @dev Multiple validators provide flexible authorization
    function test_validatorORLogic_multipleValidatorsProvideFlexibility() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        (address primarySigner,) = createAccountOwner();

        bytes memory primaryInit = abi.encode(primarySigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), primaryInit);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(alwaysApproveValidator), "");

        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 2, "Should have 2 validators");
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(ownerValidator), ""),
            "Primary validator should be installed"
        );
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(alwaysApproveValidator), ""),
            "Backup validator should be installed"
        );

        // Either validator can authorize
        address recipient = createAddress();
        fund(address(account), ONE_ETH);

        bytes memory executionData = encodeSingleExecution(recipient, 0.5 ether, "");

        vm.prank(owner);
        account.execute(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, 0.5 ether, "Transfer should succeed via OR logic");
    }
}
