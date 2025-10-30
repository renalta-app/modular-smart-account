// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "forge-std/interfaces/IERC20.sol";

contract TransferLimitHook {
    /*//////////////////////////////////////////////////////////////////////////
                                    CONSTANTS
    //////////////////////////////////////////////////////////////////////////*/

    uint256 internal constant MODULE_TYPE_HOOK = 4;

    /*//////////////////////////////////////////////////////////////////////////
                                     STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    struct TokenConfig {
        address token;
        uint256 limit;
    }

    mapping(address account => mapping(address token => uint256)) public transferLimits;

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    function onInstall(bytes calldata data) external {
        TokenConfig memory config = abi.decode(data, (TokenConfig));
        transferLimits[msg.sender][config.token] = config.limit;
    }

    function onUninstall(bytes calldata data) external {
        TokenConfig memory config = abi.decode(data, (TokenConfig));
        delete transferLimits[msg.sender][config.token];
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    HOOK FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Called by account before execution
    /// @dev msgData contains the full calldata to execute(bytes32 mode, bytes calldata executionCalldata)
    function preCheck(address, uint256, bytes calldata msgData) external view returns (bytes memory) {
        if (msgData.length < 4) return "";

        bytes4 selector = bytes4(msgData[0:4]);

        // execute(bytes32,bytes) selector = 0xb61d27f6 or executeFromExecutor
        // We need to handle both execute() and executeFromExecutor()
        if (
            selector != bytes4(keccak256("execute(bytes32,bytes)"))
                && selector != bytes4(keccak256("executeFromExecutor(bytes32,bytes)"))
        ) {
            return "";
        }

        // Parse: selector(4) + mode(32) + offset(32) + length(32) + executionCalldata
        if (msgData.length < 100) return "";

        bytes32 mode = bytes32(msgData[4:36]);
        // casting to 'bytes1' is safe because we only need the first byte (call type)
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes1 callType = bytes1(mode); // First byte is call type

        // Get offset to executionCalldata
        uint256 offset = 4 + uint256(bytes32(msgData[36:68]));
        if (msgData.length < offset + 32) return "";

        uint256 length = uint256(bytes32(msgData[offset:offset + 32]));
        if (msgData.length < offset + 32 + length) return "";

        bytes calldata executionData = msgData[offset + 32:offset + 32 + length];

        if (callType == 0x00) {
            // CALLTYPE_SINGLE
            _checkSingleExecution(executionData);
        } else if (callType == 0x01) {
            // CALLTYPE_BATCH
            _checkBatchExecution(executionData);
        }

        return "";
    }

    function postCheck(bytes calldata) external pure {}

    /*//////////////////////////////////////////////////////////////////////////
                                EXECUTION PARSING
    //////////////////////////////////////////////////////////////////////////*/

    function _checkSingleExecution(bytes calldata executionData) internal view {
        if (executionData.length < 52) return;

        address target = address(bytes20(executionData[0:20]));
        bytes memory targetCallData = executionData[52:];

        _checkTransferLimit(msg.sender, target, targetCallData);
    }

    function _checkBatchExecution(bytes calldata executionData) internal view {
        Execution[] memory executions = abi.decode(executionData, (Execution[]));
        for (uint256 i = 0; i < executions.length; i++) {
            _checkTransferLimit(msg.sender, executions[i].target, executions[i].data);
        }
    }

    /// @notice Execution struct for batch operations
    struct Execution {
        address target;
        uint256 value;
        bytes data;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    function _checkTransferLimit(address account, address token, bytes memory callData) internal view {
        if (callData.length < 4) return;

        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }

        if (selector == IERC20.transfer.selector) {
            uint256 limit = transferLimits[account][token];
            if (limit != 0) {
                bytes memory params = new bytes(callData.length - 4);
                for (uint256 i = 0; i < params.length; i++) {
                    params[i] = callData[i + 4];
                }
                (, uint256 value) = abi.decode(params, (address, uint256));
                if (value > limit) {
                    revert("TransferLimitHook: transfer amount exceeds limit");
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    function name() external pure returns (string memory) {
        return "TransferLimitHook";
    }

    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_HOOK;
    }
}
