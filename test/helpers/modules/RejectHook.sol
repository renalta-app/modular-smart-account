// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title RejectHook
/// @notice A minimal hook that always reverts in preCheck - FOR TESTING ONLY
/// @dev This hook blocks all operations
contract RejectHook {
    uint256 internal constant MODULE_TYPE_HOOK = 4;

    error HookRejected();

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address, uint256, bytes calldata) external pure returns (bytes memory) {
        revert HookRejected();
    }

    function postCheck(bytes calldata) external pure {
        revert HookRejected();
    }
}
