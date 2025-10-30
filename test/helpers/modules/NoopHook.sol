// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title NoopHook
/// @notice A minimal hook that does nothing - FOR TESTING ONLY
/// @dev This hook allows all operations without any checks
contract NoopHook {
    uint256 internal constant MODULE_TYPE_HOOK = 4;

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address, uint256, bytes calldata) external pure returns (bytes memory) {
        return "";
    }

    function postCheck(bytes calldata) external pure {}
}
