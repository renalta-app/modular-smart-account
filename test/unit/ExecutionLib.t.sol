// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ExecutionLib} from "../../contracts/libraries/ExecutionLib.sol";

/// @title ExecutionLibTest
/// @notice Test suite for ExecutionLib low-level call primitives
/// @dev Tests assembly implementations for call, staticcall, delegatecall, and return data retrieval
contract ExecutionLibTest is ModularAccountTestBase {
    TestTarget public target;
    TestDelegateTarget public delegateTarget;

    function setUp() public {
        target = new TestTarget();
        delegateTarget = new TestDelegateTarget();
    }

    // ============================================
    // CALL TESTS
    // ============================================

    function test_call_successWithValue() public {
        fund(address(this), ONE_ETH);

        bytes memory data = abi.encodeWithSignature("receiveValue()");
        bool success = ExecutionLib.call(address(target), ONE_ETH, data, gasleft());

        assertTrue(success);
        assertEq(address(target).balance, ONE_ETH);
        assertTrue(target.receiveValueCalled());
    }

    function test_call_successWithCalldata() public {
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());

        assertTrue(success);
        assertEq(target.value(), 42);
    }

    function test_call_failureReturnsFalse() public {
        bytes memory data = abi.encodeWithSignature("alwaysRevert()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());

        assertFalse(success);
    }

    function test_call_respectsGasLimit() public {
        bytes memory data = abi.encodeWithSignature("consumeGas(uint256)", 50);

        // Should fail with insufficient gas (50 SSTOREs needs ~1M gas for cold storage)
        bool success = ExecutionLib.call(address(target), 0, data, 50000);
        assertFalse(success, "Should fail due to insufficient gas");

        // Should succeed with sufficient gas
        success = ExecutionLib.call(address(target), 0, data, 2000000);
        assertTrue(success, "Should succeed with sufficient gas");
    }

    // ============================================
    // STATICCALL TESTS
    // ============================================

    function test_staticcall_successReadingState() public {
        target.setValue(123);

        bytes memory data = abi.encodeWithSignature("value()");
        bool success = ExecutionLib.staticcall(address(target), data, gasleft());

        assertTrue(success);
        bytes memory returnData = ExecutionLib.getReturnData(0);
        uint256 value = abi.decode(returnData, (uint256));
        assertEq(value, 123);
    }

    // solhint-disable-next-line func-visibility
    function test_staticcall_failureReturnsFalse() public view {
        bytes memory data = abi.encodeWithSignature("alwaysRevert()");
        bool success = ExecutionLib.staticcall(address(target), data, gasleft());

        assertFalse(success);
    }

    function test_staticcall_cannotModifyState() public {
        target.setValue(100);

        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);
        bool success = ExecutionLib.staticcall(address(target), data, gasleft());

        assertFalse(success, "Static call with state modification should fail");
        assertEq(target.value(), 100, "State should remain unchanged");
    }

    // ============================================
    // DELEGATECALL TESTS
    // ============================================

    function test_delegateCall_successModifyingCallerState() public {
        bytes memory data = abi.encodeWithSignature("setValueViaDelegateCall(uint256)", 999);
        bool success = ExecutionLib.delegateCall(address(delegateTarget), data, gasleft());

        assertTrue(success);
    }

    function test_delegateCall_failureReturnsFalse() public {
        bytes memory data = abi.encodeWithSignature("alwaysRevert()");
        bool success = ExecutionLib.delegateCall(address(delegateTarget), data, gasleft());

        assertFalse(success);
    }

    function test_delegateCall_preservesContext() public {
        bytes memory data = abi.encodeWithSignature("getAddress()");

        bool success = ExecutionLib.delegateCall(address(delegateTarget), data, gasleft());

        assertTrue(success);
        bytes memory returnData = ExecutionLib.getReturnData(0);
        address returnedAddress = abi.decode(returnData, (address));
        assertEq(returnedAddress, address(this), "delegatecall should execute in caller's context");
    }

    // ============================================
    // GETRETURNDATA TESTS
    // ============================================

    function test_getReturnData_retrievesFullData() public {
        bytes memory data = abi.encodeWithSignature("getBytes32()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());
        assertTrue(success);

        bytes memory returnData = ExecutionLib.getReturnData(0);
        bytes32 value = abi.decode(returnData, (bytes32));
        assertEq(value, bytes32(uint256(0xdeadbeef)));
    }

    function test_getReturnData_truncatesWithMaxLen() public {
        bytes memory data = abi.encodeWithSignature("getLargeData()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());
        assertTrue(success);

        bytes memory returnData = ExecutionLib.getReturnData(32);
        assertEq(returnData.length, 32);
    }

    function test_getReturnData_emptyReturnData() public {
        bytes memory data = abi.encodeWithSignature("noReturn()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());
        assertTrue(success);

        bytes memory returnData = ExecutionLib.getReturnData(0);
        assertEq(returnData.length, 0);
    }

    function test_getReturnData_withMaxLenZero() public {
        bytes memory data = abi.encodeWithSignature("getBytes32()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());
        assertTrue(success);

        bytes memory returnData = ExecutionLib.getReturnData(0);
        assertEq(returnData.length, 32);
    }

    function test_getReturnData_capturesRevertReason() public {
        bytes memory data = abi.encodeWithSignature("alwaysRevert()");
        bool success = ExecutionLib.call(address(target), 0, data, gasleft());

        assertFalse(success);
        bytes memory returnData = ExecutionLib.getReturnData(0);

        // Verify we captured the revert reason
        assertTrue(returnData.length > 0, "Should capture revert data");

        // Decode Error(string) - standard revert format
        if (returnData.length >= 68) {
            bytes4 errorSelector;
            assembly {
                errorSelector := mload(add(returnData, 0x20))
            }
            assertEq(errorSelector, bytes4(keccak256("Error(string)")), "Should be Error(string) selector");
        }
    }

    receive() external payable {}
}

contract TestTarget {
    uint256 public value;
    bool public receiveValueCalled;
    mapping(uint256 => uint256) public storage_;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function receiveValue() external payable {
        receiveValueCalled = true;
    }

    function alwaysRevert() external pure {
        revert("intentional revert");
    }

    function getBytes32() external pure returns (bytes32) {
        return bytes32(uint256(0xdeadbeef));
    }

    function getLargeData() external pure returns (bytes memory) {
        return new bytes(128);
    }

    function noReturn() external pure {}

    function consumeGas(uint256 iterations) external {
        for (uint256 i = 0; i < iterations; i++) {
            storage_[i] = i;
        }
    }

    receive() external payable {}
}

contract TestDelegateTarget {
    uint256 public value;

    function setValueViaDelegateCall(uint256 _value) external {
        value = _value;
    }

    function getAddress() external view returns (address) {
        return address(this);
    }

    function alwaysRevert() external pure {
        revert("intentional revert");
    }
}
