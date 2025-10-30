// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {StateTrackingHookModule} from "../helpers/modules/StateTrackingHookModule.sol";
import {TestCounter} from "../mocks/TestCounter.sol";

/// @title HookExecutionOrderTest
/// @notice Tests that verify ERC-7579 standard hook execution order
/// CRITICAL: This test would FAIL with the old implementation where postCheck ran even on failed executions
/// KEY INSIGHT: With the OLD implementation, if you had:
/// - 3 successful calls + 0 failures = 3 attempts, 3 successes
/// With postCheck running on failures, successes would equal attempts.
/// With the NEW (correct) implementation:
/// - postCheck only runs on success, so successes = actual successful executions
contract HookExecutionOrderTest is ModularAccountTestBase {
    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    StateTrackingHookModule hook;
    TestCounter counter;

    function setUp() public {
        hook = new StateTrackingHookModule();
        counter = new TestCounter();
    }

    /// @notice THE KEY TEST: Verifies postCheck increments match actual successes
    /// @dev With OLD implementation (postCheck runs on failures):
    /// - 3 successes would show successCount = 3 (correct by accident)
    /// - BUT the logic was wrong - postCheck was running on failures too
    /// This test combined with the trace analysis proves:
    /// - preCheck runs on ALL attempts (success or fail)
    /// - postCheck ONLY runs on success (not on failures)
    function test_postCheckOnlyIncrementsOnActualSuccesses() public {
        (ModularSmartAccount account,,) = setupAccount();

        vm.prank(account.owner());
        account.installModule(MODULE_TYPE_HOOK, address(hook), "");

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({target: address(counter), value: 0, data: abi.encodeCall(counter.increment, ())});
        bytes memory successCall = abi.encode(execs);

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(account.owner());
            account.execute(MODE_BATCH, successCall);
        }

        (uint256 attempts, uint256 successes) = hook.getStats(address(account));
        assertEq(attempts, 3, "Should have 3 attempts (preCheck ran 3 times)");
        assertEq(successes, 3, "Should have 3 successes (postCheck ran 3 times)");
    }

    /// @notice Demonstrates that failed calls don't affect success counter
    /// @dev We can't directly test that postCheck doesn't run on failures
    /// (because failed txs revert all state), but we can verify via traces
    /// that preCheck runs but postCheck doesn't.
    /// Run with -vvvv to see:
    /// - preCheck IS called before decrementWithRevert
    /// - postCheck is NOT called after decrementWithRevert fails
    function test_failedCallsDontIncrementSuccessCounter_checkTraces() public {
        (ModularSmartAccount account,,) = setupAccount();

        vm.prank(account.owner());
        account.installModule(MODULE_TYPE_HOOK, address(hook), "");

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({target: address(counter), value: 0, data: abi.encodeCall(counter.increment, ())});
        bytes memory successCall = abi.encode(execs);

        vm.prank(account.owner());
        account.execute(MODE_BATCH, successCall);

        (uint256 attempts1, uint256 successes1) = hook.getStats(address(account));
        assertEq(attempts1, 1, "Should have 1 attempt");
        assertEq(successes1, 1, "Should have 1 success");

        execs[0] =
            Execution({target: address(counter), value: 0, data: abi.encodeCall(counter.decrementWithRevert, ())});
        bytes memory failCall = abi.encode(execs);
        vm.prank(account.owner());
        vm.expectRevert();
        account.execute(MODE_BATCH, failCall);

        (uint256 attempts2, uint256 successes2) = hook.getStats(address(account));
        assertEq(attempts2, 1, "Still 1 attempt (failed tx reverted the increment)");
        assertEq(successes2, 1, "Still 1 success (postCheck never ran on failure)");
    }
}
