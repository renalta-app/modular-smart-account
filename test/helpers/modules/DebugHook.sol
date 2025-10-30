// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title DebugHook
/// @notice A hook that reverts with the msgData selector for debugging
contract DebugHook {
    uint256 internal constant MODULE_TYPE_HOOK = 4;

    error HookCalled(bytes4 selector, uint256 dataLength);

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address, uint256, bytes calldata msgData) external pure returns (bytes memory) {
        bytes4 selector = msgData.length >= 4 ? bytes4(msgData[0:4]) : bytes4(0);
        revert HookCalled(selector, msgData.length);
    }

    function postCheck(bytes calldata) external pure {}
}
