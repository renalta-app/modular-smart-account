// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7579Hook, MODULE_TYPE_HOOK} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title ActivityLogHookModule
/// @notice Baseline hook module that emits structured events before and after account executions
/// @dev Provides simple observability and demonstrates per-account hook storage
contract ActivityLogHookModule is IERC7579Hook {
    struct HookState {
        uint64 invocationCount;
        bool installed;
    }

    mapping(address account => HookState state) private _state;

    error ActivityLogHookAlreadyInstalled(address account);
    error ActivityLogHookNotInstalled(address account);

    event HookPreCheck(
        address indexed account, address indexed caller, uint256 value, bytes callData, uint64 invocation
    );
    event HookPostCheck(address indexed account, bytes hookData, uint64 invocation);

    function onInstall(bytes calldata) external override {
        HookState storage state = _state[msg.sender];
        if (state.installed) revert ActivityLogHookAlreadyInstalled(msg.sender);
        state.installed = true;
        state.invocationCount = 0;
    }

    function onUninstall(bytes calldata) external override {
        HookState storage state = _state[msg.sender];
        if (!state.installed) revert ActivityLogHookNotInstalled(msg.sender);
        delete _state[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata msgData)
        external
        override
        returns (bytes memory hookData)
    {
        HookState storage state = _state[msg.sender];
        if (!state.installed) revert ActivityLogHookNotInstalled(msg.sender);

        uint64 nextInvocation = ++state.invocationCount;
        emit HookPreCheck(msg.sender, msgSender, value, msgData, nextInvocation);
        return abi.encode(nextInvocation, msgSender, value, msgData);
    }

    function postCheck(bytes calldata hookData) external override {
        HookState storage state = _state[msg.sender];
        if (!state.installed) revert ActivityLogHookNotInstalled(msg.sender);

        emit HookPostCheck(msg.sender, hookData, state.invocationCount);
    }

    function invocationCount(address account) external view returns (uint64) {
        return _state[account].invocationCount;
    }
}
