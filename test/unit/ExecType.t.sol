// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {TestCounter} from "../mocks/TestCounter.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

contract ExecTypeTest is ModularAccountTestBase {
    TestCounter public counter;

    function setUp() public {
        counter = new TestCounter();
    }

    function test_supportsExecutionMode_validatesExecType() public {
        (ModularSmartAccount account,,) = setupAccount();

        bytes32 modeDefaultRevert =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes32 modeDefaultTry =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));
        bytes32 modeInvalid = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, bytes1(0x02), bytes4(0), bytes22(0));

        assertTrue(account.supportsExecutionMode(modeDefaultRevert), "Should support EXECTYPE_DEFAULT");
        assertTrue(account.supportsExecutionMode(modeDefaultTry), "Should support EXECTYPE_TRY");
        assertFalse(account.supportsExecutionMode(modeInvalid), "Should reject invalid execType");
    }

    function test_execTypeDefault_revertsOnFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        bytes memory executionCalldata = encodeExecution(address(counter), 0, abi.encodeWithSignature("countFail()"));

        vm.prank(owner);
        vm.expectRevert("count failed");
        account.execute(mode, executionCalldata);
    }

    function test_execTypeTry_doesNotRevertOnFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        bytes memory executionCalldata = encodeExecution(address(counter), 0, abi.encodeWithSignature("countFail()"));

        vm.prank(owner);
        account.execute(mode, executionCalldata);
    }

    function test_execTypeTry_batchContinuesAfterFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});
        batch[1] =
            Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("decrementWithRevert()")});
        batch[2] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});

        vm.prank(owner);
        account.execute(mode, encodeExecutionBatch(batch));

        assertEq(counter.counters(address(account)), 2, "Should have executed first and third calls");
    }

    function test_execTypeDefault_batchRevertsOnFirstFailure() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        Execution[] memory batch = new Execution[](3);
        batch[0] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});
        batch[1] =
            Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("decrementWithRevert()")});
        batch[2] = Execution({target: address(counter), value: 0, data: abi.encodeWithSignature("increment()")});

        vm.prank(owner);
        vm.expectRevert("decrement always fails");
        account.execute(mode, encodeExecutionBatch(batch));

        assertEq(counter.counters(address(account)), 0, "Entire batch should revert atomically");
    }
}
