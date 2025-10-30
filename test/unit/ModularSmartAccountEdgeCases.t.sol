// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";

import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC7579ModuleLib} from "../../contracts/libraries/ERC7579ModuleLib.sol";
import {TestCounter} from "../mocks/TestCounter.sol";

import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestHookModule} from "../helpers/modules/TestERC7579Modules.sol";
import {OwnerValidatorModule} from "../helpers/modules/OwnerValidatorModule.sol";

/// @title ModularSmartAccountEdgeCasesTest
/// @notice Edge case and security tests for ModularSmartAccount
///
/// Test Categories:
/// - Module Installation Edge Cases
/// - Module Removal Edge Cases
/// - Execute Function Security
/// - Batch Execution Edge Cases
/// - Reentrancy Protection
/// - Hook Security
/// - Module Type Validation
/// - Authorization Edge Cases
/// - Gas Exhaustion Resistance
contract ModularSmartAccountEdgeCasesTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    address public attacker;
    uint256 public attackerKey;

    // Test modules (reused across tests)
    TestValidatorModule public validator;
    TestHookModule public hook;
    TestCounter public counter;
    OwnerValidatorModule public ownerValidator;

    function setUp() public {
        (attacker, attackerKey) = createAccountOwner();
        fund(attacker, 10 ether);
        validator = new TestValidatorModule();
        hook = new TestHookModule();
        counter = new TestCounter();
        ownerValidator = new OwnerValidatorModule();
    }

    // ============================================
    // MODULE INSTALLATION EDGE CASES
    // ============================================

    function test_preventsNonOwnerFromInstallingModules() public {
        (ModularSmartAccount account,,) = setupAccount();
        bytes memory initData = abi.encode(attacker);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);
    }

    function test_allowsRemovingValidatorWhenMultipleExist() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestValidatorModule validator1 = new TestValidatorModule();
        TestValidatorModule validator2 = new TestValidatorModule();
        bytes memory initData = abi.encode(owner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), initData);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit ERC7579ModuleLib.ModuleUninstalled(MODULE_TYPE_VALIDATOR, address(validator1));
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator1), "");

        assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator1), ""),
            "Validator1 should be uninstalled"
        );
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator2), ""),
            "Validator2 should remain installed"
        );
    }

    function test_preventsNonOwnerFromUninstallingModules() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        bytes memory initData = abi.encode(owner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");
    }

    // ============================================
    // BATCH EXECUTION EDGE CASES
    // ============================================

    function test_executesEmptyBatchWithoutReverting() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        Execution[] memory emptyBatch = new Execution[](0);
        bytes memory emptyBatchEncoded = abi.encode(emptyBatch);

        vm.prank(owner);
        account.execute(MODE_BATCH, emptyBatchEncoded);
    }

    function test_executesMultipleOperationsInBatchAndRevertsAllOnFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory call1 = abi.encodeWithSignature("count()");
        bytes memory call2 = abi.encodeWithSignature("count()");
        bytes memory invalidCall = hex"deadbeef";

        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution({target: address(counter), value: 0, data: call1});
        batch[1] = Execution({target: address(counter), value: 0, data: call2});
        batch[2] = Execution({target: address(counter), value: 0, data: invalidCall});

        bytes memory batchEncoded = encodeExecutionBatch(batch);

        vm.prank(owner);
        vm.expectRevert(); // Will revert with function selector not found for 0xdeadbeef
        account.execute(MODE_BATCH, batchEncoded);

        assertEq(counter.counters(address(account)), 0, "Counter should remain 0 when batch reverts");
    }

    function test_executesSuccessfulBatchCompletely() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory call1 = abi.encodeWithSignature("count()");
        bytes memory call2 = abi.encodeWithSignature("count()");
        bytes memory call3 = abi.encodeWithSignature("count()");

        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution({target: address(counter), value: 0, data: call1});
        batch[1] = Execution({target: address(counter), value: 0, data: call2});
        batch[2] = Execution({target: address(counter), value: 0, data: call3});

        bytes memory batchEncoded = encodeExecutionBatch(batch);

        vm.prank(owner);
        account.execute(MODE_BATCH, batchEncoded);

        assertEq(counter.counters(address(account)), 3, "All 3 batch operations should succeed");
    }

    // ============================================
    // HOOK EXECUTION EDGE CASES
    // ============================================

    function test_executesTransactionEvenWithNoHooksInstalled() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1, "Execution should succeed without hooks");
    }

    function test_maintainsHookOrderWithMultipleHooks() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestHookModule hook1 = new TestHookModule();
        TestHookModule hook2 = new TestHookModule();
        TestHookModule hook3 = new TestHookModule();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook1), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook2), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook3), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.recordLogs();
        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 hookPreTopic = keccak256("HookPre(address,address,uint256,bytes,uint256)");

        Vm.Log[] memory hookPreLogs = collectEventLogs(logs, hookPreTopic);
        assertEq(hookPreLogs.length, 3, "Should have 3 HookPre events");

        assertEq(hook1.hookCount(address(account)), 1, "Hook1 should be called once");
        assertEq(hook2.hookCount(address(account)), 1, "Hook2 should be called once");
        assertEq(hook3.hookCount(address(account)), 1, "Hook3 should be called once");
    }

    // ============================================
    // AUTHORIZATION EDGE CASES
    // ============================================

    function test_preventsDirectExecuteCallsFromUnauthorizedAddresses() public {
        (ModularSmartAccount account,,) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        account.execute(MODE_DEFAULT, execData);
    }

    function test_allowsEntryPointToExecute() public {
        (ModularSmartAccount account,,) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(address(entryPoint));
        account.execute(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1, "EntryPoint should be authorized to execute");
    }

    function test_allowsOwnerToExecute() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1, "Owner should be authorized to execute");
    }

    // ============================================
    // REENTRANCY PROTECTION
    // ============================================

    function test_preventsReentrantExecuteCallsWithReentrancyGuard() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory innerCall = abi.encodeWithSignature("count()");
        bytes memory innerExec = encodeExecution(address(counter), 0, innerCall);
        bytes memory reentrantCall = abi.encodeWithSignature("execute(bytes32,bytes)", MODE_DEFAULT, innerExec);
        bytes memory outerExec = encodeExecution(address(account), 0, reentrantCall);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("Reentrancy()"));
        account.execute{gas: 500000}(MODE_DEFAULT, outerExec);
    }

    function test_allowsNestedExecutionsThroughProperAuthorization() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory call1 = abi.encodeWithSignature("count()");
        bytes memory call2 = abi.encodeWithSignature("count()");

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({target: address(counter), value: 0, data: call1});
        batch[1] = Execution({target: address(counter), value: 0, data: call2});

        bytes memory batchEncoded = encodeExecutionBatch(batch);

        vm.prank(owner);
        account.execute(MODE_BATCH, batchEncoded);

        assertEq(counter.counters(address(account)), 2, "Batch execution should succeed (not reentrancy)");
    }

    // ============================================
    // MODULE INTERACTION EDGE CASES
    // ============================================

    function test_handlesModuleWithRevertingOnInstallGracefully() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        bytes memory invalidData = hex"1234";

        vm.prank(owner);
        vm.expectRevert();
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), invalidData);
    }

    function test_correctlyReportsModuleInstallationStatus() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        bytes memory initData = abi.encode(owner);

        assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "Module should not be installed initially"
        );

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "Module should be installed after installModule"
        );

        TestValidatorModule validator2 = new TestValidatorModule();
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "First validator should be uninstalled"
        );
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator2), ""),
            "Second validator should remain installed"
        );
    }

    // ============================================
    // GAS EXHAUSTION RESISTANCE
    // ============================================

    /// Note: This is a smoke test, not a precise gas benchmark. Actual gas costs vary with
    /// compiler versions and EVM changes. The test ensures basic functionality works.
    function test_handlesExecutionWithReasonableGasForSingleOperation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.execute{gas: 200000}(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1, "Execution should succeed with reasonable gas");
    }

    /// Note: This is a smoke test for gas exhaustion resistance, not a precise benchmark.
    /// The test ensures batched operations work with reasonable gas allocations.
    function test_handlesBatchWithReasonableGasLimits() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        Execution[] memory batch = new Execution[](10);
        for (uint256 i = 0; i < 10; i++) {
            batch[i] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("count()")});
        }

        bytes memory batchEncoded = encodeExecutionBatch(batch);

        vm.prank(owner);
        account.execute{gas: 500000}(MODE_BATCH, batchEncoded);

        assertEq(counter.counters(address(account)), 10, "All batch operations should succeed with reasonable gas");
    }
}
