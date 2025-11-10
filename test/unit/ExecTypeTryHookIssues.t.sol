// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {TestCounter} from "../mocks/TestCounter.sol";
import {StateTrackingHookModule} from "../helpers/modules/StateTrackingHookModule.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @title ExecTypeTryHookIssuesTest
/// @notice Documents that postCheck runs even when EXECTYPE_TRY causes silent failures
/// @dev This breaks hooks that assume postCheck only runs after successful execution
contract ExecTypeTryHookIssuesTest is ModularAccountTestBase {
    TestCounter public counter;
    StateTrackingHookModule public stateTracker;

    function setUp() public {
        counter = new TestCounter();
        stateTracker = new StateTrackingHookModule();
    }

    /// @notice postCheck runs even when execution fails with EXECTYPE_TRY
    function test_tryExec_hookPostCheckRunsOnFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(stateTracker), "");

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        bytes memory executionCalldata = encodeExecution(address(counter), 0, abi.encodeWithSignature("countFail()"));

        vm.prank(owner);
        account.execute(mode, executionCalldata);

        (uint256 attempts, uint256 successes) = stateTracker.getStats(address(account));
        assertEq(attempts, 1, "preCheck should run");
        assertEq(successes, 0, "postCheck should NOT run for failed execution");
        assertEq(counter.counters(address(account)), 0, "Execution should have failed");
    }

    /// @notice EXECTYPE_TRY is not allowed with CALLTYPE_BATCH
    function test_tryExec_batchNotAllowed() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});
        batch[1] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("TryExecNotAllowedForBatch()"));
        account.execute(mode, encodeExecutionBatch(batch));
    }

    /// @notice DEFAULT mode reverts entire tx; TRY mode runs postCheck despite failure
    function test_tryExec_inconsistentWithDefaultMode() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(stateTracker), "");

        bytes memory failingExecution = encodeExecution(address(counter), 0, abi.encodeWithSignature("countFail()"));

        bytes32 defaultMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.prank(owner);
        vm.expectRevert("count failed");
        account.execute(defaultMode, failingExecution);

        (uint256 attempts1, uint256 successes1) = stateTracker.getStats(address(account));
        assertEq(attempts1, 0, "DEFAULT mode: entire tx reverted");
        assertEq(successes1, 0, "DEFAULT mode: entire tx reverted");

        bytes32 tryMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        vm.prank(owner);
        account.execute(tryMode, failingExecution);

        (uint256 attempts2, uint256 successes2) = stateTracker.getStats(address(account));
        assertEq(attempts2, 1, "TRY mode: preCheck ran");
        assertEq(successes2, 0, "TRY mode: postCheck should NOT run on failed execution");
    }
}
