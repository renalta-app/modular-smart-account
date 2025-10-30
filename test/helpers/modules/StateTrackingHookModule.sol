// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7579Hook, MODULE_TYPE_HOOK} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title StateTrackingHookModule
/// @notice Hook module that tracks successful executions in postCheck
/// @dev This hook demonstrates why postCheck should NOT run on failed executions:
///      - preCheck: Records intent to execute
///      - postCheck: Increments "successful execution" counter
///      If postCheck runs on failures, the counter would incorrectly increment even when the underlying execution reverted
contract StateTrackingHookModule is IERC7579Hook {
    /// @notice Emitted when preCheck runs (before execution)
    event PreCheckCalled(address indexed account, address indexed caller, uint256 value);

    /// @notice Emitted when postCheck runs (after successful execution)
    event PostCheckCalled(address indexed account, uint256 newSuccessCount);

    /// @notice Tracks number of SUCCESSFUL executions per account
    /// @dev This counter should ONLY increment when execution succeeds
    mapping(address => uint256) public successfulExecutionCount;

    /// @notice Tracks number of preCheck calls per account (all attempts)
    /// @dev This counter increments on every execution attempt (success or fail)
    mapping(address => uint256) public totalAttemptCount;

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    /// @notice PreCheck runs before every execution (success or fail)
    function preCheck(address msgSender, uint256 value, bytes calldata) external override returns (bytes memory) {
        totalAttemptCount[msg.sender]++;
        emit PreCheckCalled(msg.sender, msgSender, value);
        return "";
    }

    /// @notice PostCheck should ONLY run after successful execution
    function postCheck(bytes calldata) external override {
        successfulExecutionCount[msg.sender]++;
        emit PostCheckCalled(msg.sender, successfulExecutionCount[msg.sender]);
    }

    /// @notice Helper to check if counts match expectations
    function getStats(address account) external view returns (uint256 attempts, uint256 successes) {
        return (totalAttemptCount[account], successfulExecutionCount[account]);
    }
}
