// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibCall} from "solady/utils/LibCall.sol";
import {ExecutionLib} from "./ExecutionLib.sol";

/// @title ERC7579ExecutionLib
/// @notice Library for ERC-7579 execution mode dispatch and invocation
/// @dev Handles single, batch, delegatecall, and staticcall execution paths with optional return data collection
library ERC7579ExecutionLib {
    /// @notice Thrown when value is provided for a call type that doesn't support it
    /// @param callType The call type that was attempted
    error ValueNotAllowedForCallType(uint8 callType);

    /// @notice Thrown when EXECTYPE_TRY is used with CALLTYPE_BATCH
    /// @dev Batch operations with try-exec create ambiguous success states that hooks cannot properly track
    error TryExecNotAllowedForBatch();

    /// @dev Validates that value is allowed for the call type
    function _validateValueForCallType(bytes1 callType, uint256 value) private pure {
        if (callType == LibERC7579.CALLTYPE_STATICCALL && value != 0) {
            revert ValueNotAllowedForCallType(uint8(callType));
        }
    }

    /// @notice Dispatches execution with return data collection
    /// @dev Used by executeFromExecutor() where modules need return values.
    /// @param mode The encoded execution mode (callType in upper byte)
    /// @param executionCalldata The encoded execution data
    /// @return success True if all executions succeeded, false if any failed (only relevant with EXECTYPE_TRY)
    /// @return returnData Array of return data from each executed call
    function dispatchExecute(bytes32 mode, bytes calldata executionCalldata)
        internal
        returns (bool success, bytes[] memory returnData)
    {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        bool tryExec = execType == LibERC7579.EXECTYPE_TRY;

        if (tryExec && callType == LibERC7579.CALLTYPE_BATCH) {
            revert TryExecNotAllowedForBatch();
        }

        success = true;

        if (callType == LibERC7579.CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionCalldata);
            uint256 len = pointers.length;
            returnData = new bytes[](len);
            for (uint256 i = 0; i < len;) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                (bool callSuccess, bytes memory retData) =
                    _invokeSingleWithMode(target, value, data, LibERC7579.CALLTYPE_SINGLE, tryExec);
                returnData[i] = retData;
                if (!callSuccess) {
                    success = false;
                }
                unchecked {
                    ++i;
                }
            }
        } else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            (address target, bytes calldata data) = LibERC7579.decodeDelegate(executionCalldata);
            returnData = new bytes[](1);
            (success, returnData[0]) = _invokeDelegateWithMode(target, data, tryExec);
        } else {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionCalldata);
            returnData = new bytes[](1);
            (success, returnData[0]) = _invokeSingleWithMode(target, value, data, callType, tryExec);
        }
    }

    /// @notice Dispatches execution without return data collection
    /// @dev Used by execute() for gas optimization when return data is not needed.
    /// @param mode The encoded execution mode (callType in upper byte)
    /// @param executionCalldata The encoded execution data
    /// @return success True if all executions succeeded, false if any failed (only relevant with EXECTYPE_TRY)
    function dispatchExecuteNoReturn(bytes32 mode, bytes calldata executionCalldata) internal returns (bool success) {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        bool tryExec = execType == LibERC7579.EXECTYPE_TRY;

        if (tryExec && callType == LibERC7579.CALLTYPE_BATCH) {
            revert TryExecNotAllowedForBatch();
        }

        success = true;

        if (callType == LibERC7579.CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionCalldata);
            uint256 len = pointers.length;
            for (uint256 i = 0; i < len;) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                if (!_invokeSingleWithModeNoReturn(target, value, data, LibERC7579.CALLTYPE_SINGLE, tryExec)) {
                    success = false;
                }
                unchecked {
                    ++i;
                }
            }
        } else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            (address target, bytes calldata data) = LibERC7579.decodeDelegate(executionCalldata);
            success = _invokeDelegateWithModeNoReturn(target, data, tryExec);
        } else {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionCalldata);
            success = _invokeSingleWithModeNoReturn(target, value, data, callType, tryExec);
        }
    }

    function _invokeSingleWithMode(address target, uint256 value, bytes calldata data, bytes1 callType, bool tryExec)
        private
        returns (bool success, bytes memory ret)
    {
        _validateValueForCallType(callType, value);

        if (callType == LibERC7579.CALLTYPE_STATICCALL) {
            success = ExecutionLib.staticcall(target, data, gasleft());
        } else {
            success = ExecutionLib.call(target, value, data, gasleft());
        }

        ret = ExecutionLib.getReturnData(0);

        if (!success && !tryExec) {
            LibCall.bubbleUpRevert(ret);
        }
    }

    function _invokeSingleWithModeNoReturn(
        address target,
        uint256 value,
        bytes calldata data,
        bytes1 callType,
        bool tryExec
    ) private returns (bool) {
        _validateValueForCallType(callType, value);

        bool success;
        if (callType == LibERC7579.CALLTYPE_STATICCALL) {
            success = ExecutionLib.staticcall(target, data, gasleft());
        } else {
            success = ExecutionLib.call(target, value, data, gasleft());
        }

        if (!success && !tryExec) {
            LibCall.bubbleUpRevert(ExecutionLib.getReturnData(0));
        }

        return success;
    }

    function _invokeDelegateWithMode(address target, bytes calldata data, bool tryExec)
        private
        returns (bool success, bytes memory ret)
    {
        success = ExecutionLib.delegateCall(target, data, gasleft());
        ret = ExecutionLib.getReturnData(0);

        if (!success && !tryExec) {
            LibCall.bubbleUpRevert(ret);
        }
    }

    function _invokeDelegateWithModeNoReturn(address target, bytes calldata data, bool tryExec) private returns (bool) {
        bool success = ExecutionLib.delegateCall(target, data, gasleft());

        if (!success && !tryExec) {
            LibCall.bubbleUpRevert(ExecutionLib.getReturnData(0));
        }

        return success;
    }
}
