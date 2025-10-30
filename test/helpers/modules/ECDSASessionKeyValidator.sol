// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant ERC7579_MODULE_TYPE_STATELESS_VALIDATOR = 7;
uint256 constant SIG_VALIDATION_SUCCESS = 0;
uint256 constant SIG_VALIDATION_FAILED = 1;

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 typeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

/// @title ISessionValidator
/// @notice Stateless session key validator interface for SmartSessions
/// @dev Based on erc7579/smartsessions ISessionValidator interface
interface ISessionValidator is IModule {
    /// @notice Validates a signature for a given session
    /// @param hash The userOp hash to validate
    /// @param sig The signature of userOp
    /// @param data The config data used to validate the signature (session key address)
    /// @return validSig True if signature is valid, false otherwise
    function validateSignatureWithData(bytes32 hash, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool validSig);
}

/// @title ECDSASessionKeyValidator
/// @notice ECDSA validator for session keys - supports both standalone and SmartSession modes
/// @dev Validates signatures using ECDSA recovery. Can be used as:
///      1. Standalone ERC-7579 validator (session key stored during onInstall)
///      2. SmartSession stateless validator (session key passed in data parameter)
contract ECDSASessionKeyValidator is ISessionValidator {
    using MessageHashUtils for bytes32;

    /// @notice Stores the session key for each account when used as standalone validator
    mapping(address account => address sessionKey) private _sessionKeys;

    // =============================================================================
    // ERC-7579 VALIDATOR INTERFACE (Standalone mode)
    // =============================================================================

    /// @notice Validates a UserOperation using the stored session key
    /// @dev Used when module is installed as a standard validator (not via SmartSessions)
    ///      msg.sender is the account that installed this module
    /// @param userOp The user operation to validate
    /// @param userOpHash The hash of the user operation
    /// @return validationData 0 if valid, 1 if invalid (per ERC-4337 spec)
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        returns (uint256 validationData)
    {
        address sessionKey = _sessionKeys[msg.sender];
        if (sessionKey == address(0)) {
            return SIG_VALIDATION_FAILED;
        }

        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        return recovered == sessionKey ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /// @notice Validates an ERC-1271 signature using the stored session key
    /// @param sender The address calling isValidSignature (unused)
    /// @param hash The hash to validate
    /// @param signature The signature bytes
    /// @return magicValue ERC-1271 magic value if valid, 0xffffffff otherwise
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4 magicValue)
    {
        address sessionKey = _sessionKeys[msg.sender];
        if (sessionKey == address(0)) {
            return 0xffffffff;
        }

        address recovered = ECDSA.recover(hash, signature);
        return recovered == sessionKey ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    // =============================================================================
    // SMARTSESSION STATELESS VALIDATOR INTERFACE
    // =============================================================================

    /// @notice Validates an ECDSA signature against a session key (SmartSession mode)
    /// @param hash The hash that was signed
    /// @param sig The ECDSA signature
    /// @param data The session key address (abi.encodePacked(address))
    /// @return validSig True if the signature was created by the session key
    function validateSignatureWithData(bytes32 hash, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool validSig)
    {
        address sessionKey = address(bytes20(data[0:20]));

        // Try raw ECDSA recovery first
        address recovered = ECDSA.recover(hash, sig);
        if (recovered == sessionKey) {
            return true;
        }

        // Try with eth_sign prefix for better wallet compatibility
        bytes32 ethSignHash = hash.toEthSignedMessageHash();
        recovered = ECDSA.recover(ethSignHash, sig);
        return recovered == sessionKey;
    }

    // =============================================================================
    // MODULE LIFECYCLE
    // =============================================================================

    function onInstall(bytes calldata data) external {
        // If data is provided, store the session key for standalone mode
        if (data.length >= 32) {
            // Data is abi.encode(address), which is 32 bytes with address right-aligned
            // Extract the address from bytes 12-32 (last 20 bytes)
            _sessionKeys[msg.sender] = address(bytes20(data[12:32]));
        } else if (data.length >= 20) {
            // For abi.encodePacked(address), address is in first 20 bytes
            _sessionKeys[msg.sender] = address(bytes20(data[0:20]));
        }
    }

    function onUninstall(bytes calldata) external {
        delete _sessionKeys[msg.sender];
    }

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
