// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {
    IERC7579Module,
    IERC7579Execution,
    MODULE_TYPE_EXECUTOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title DirectCallExecutorModule
/// @notice Minimal executor that forwards encoded execution payloads to the owning smart account
/// @dev When invoked by the account it belongs to, calls `executeFromExecutor` allowing batched or delegate executions
contract DirectCallExecutorModule is IERC7579Module {
    mapping(address account => bool installed) private _installed;

    error DirectCallExecutorAlreadyInstalled(address account);
    error DirectCallExecutorNotInstalled(address account);

    event ExecutorInvoked(address indexed account, bytes32 mode, bytes executionCalldata, uint256 value);

    function onInstall(bytes calldata) external override {
        if (_installed[msg.sender]) revert DirectCallExecutorAlreadyInstalled(msg.sender);
        _installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external override {
        if (!_installed[msg.sender]) revert DirectCallExecutorNotInstalled(msg.sender);
        _installed[msg.sender] = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function execute(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        if (!_installed[msg.sender]) revert DirectCallExecutorNotInstalled(msg.sender);

        emit ExecutorInvoked(msg.sender, mode, executionCalldata, msg.value);
        return IERC7579Execution(msg.sender).executeFromExecutor{value: msg.value}(mode, executionCalldata);
    }

    function isInstalled(address account) external view returns (bool) {
        return _installed[account];
    }
}
