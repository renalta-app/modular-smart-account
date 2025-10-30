// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// solhint-disable no-inline-assembly

/// @title ExecutionLib
/// @notice Low-level execution primitives for making contract calls
/// @dev Provides gas-efficient assembly implementations for call types and revert handling
library ExecutionLib {
    /// @notice Executes a call to a target address
    function call(address to, uint256 value, bytes memory data, uint256 txGas) internal returns (bool success) {
        assembly ("memory-safe") {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /// @notice Executes a static call to a target address
    function staticcall(address to, bytes memory data, uint256 txGas) internal view returns (bool success) {
        assembly ("memory-safe") {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /// @notice Executes a delegate call to a target address
    function delegateCall(address to, bytes memory data, uint256 txGas) internal returns (bool success) {
        assembly ("memory-safe") {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /// @notice Retrieves return data from the last call or delegatecall
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            let len := returndatasize()
            if gt(maxLen, 0) {
                if gt(len, maxLen) {
                    len := maxLen
                }
            }
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }
}
