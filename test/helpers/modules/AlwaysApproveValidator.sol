// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title AlwaysApproveValidator
/// @notice A minimal validator that always approves - FOR TESTING ONLY
/// @dev This validator provides no security and should NEVER be used in production
contract AlwaysApproveValidator {
    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external pure returns (uint256) {
        return 0;
    }
}
