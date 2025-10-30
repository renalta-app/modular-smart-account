// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant ERC7579_MODULE_TYPE_STATELESS_VALIDATOR = 7;

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 typeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

/// @title ISessionValidator
/// @notice Stateless session key validator interface for SmartSessions
interface ISessionValidator is IModule {
    /// @notice Validates a signature for a given session
    /// @param hash The userOp hash to validate
    /// @param sig The signature of userOp
    /// @param data The config data used to validate the signature
    /// @return validSig True if signature is valid, false otherwise
    function validateSignatureWithData(bytes32 hash, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool validSig);
}

/// @title AlwaysApproveSessionValidator
/// @notice Session validator that always approves - FOR TESTING ONLY
/// @dev This validator provides NO SECURITY and should NEVER be used in production
contract AlwaysApproveSessionValidator is ISessionValidator {
    /// @notice Always returns true regardless of signature
    function validateSignatureWithData(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }

    function onInstall(bytes calldata) external pure {}

    function onUninstall(bytes calldata) external pure {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR || typeId == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x940d3840 || interfaceId == 0x01ffc9a7 || interfaceId == type(ISessionValidator).interfaceId;
    }
}
