// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IModule} from "modulekit/accounts/common/interfaces/IERC7579Module.sol";

/// @dev Policy modules check if UserOperations or actions should be permitted
uint256 constant MODULE_TYPE_POLICY = 5;
/// @dev Signer modules validate signatures on provided hashes
uint256 constant MODULE_TYPE_SIGNER = 6;
/// @dev Stateless validators compare against calldata-provided data without relying on stored state
uint256 constant MODULE_TYPE_STATELESS_VALIDATOR = 7;

/// @title IPolicy
/// @notice Policy modules check if UserOperations or actions should be permitted
/// @dev Implements module type id: 5
interface IPolicy is IModule {
    /// @notice Checks a userOp to determine if it should be executed
    /// @dev SHOULD validate the executions in the userOp against stored configurations
    /// @param id The id of the policy
    /// @param userOp The user operation to check
    /// @return The validation data to return to the EntryPoint as specified by ERC-4337
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external payable returns (uint256);

    /// @notice Checks a signature to determine if it should be executed
    /// @dev SHOULD validate the hash in order to determine what the signature is used for and if it should be permitted
    /// MAY check the sender to determine whether the signature should be permitted
    /// @param id The id of the policy
    /// @param sender The sender of the transaction
    /// @param hash The hash of the transaction
    /// @param sig The signature of the transaction
    /// @return The validation data to return to the EntryPoint as specified by ERC-4337
    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (uint256);
}

/// @title ISigner
/// @notice Signer modules validate signatures on provided hashes
/// @dev Implements module type id: 6
interface ISigner is IModule {
    /// @notice Check the signature of a user operation
    /// @param id The id of the signer config
    /// @param userOp The user operation
    /// @param userOpHash The hash of the user operation
    /// @return The status of the signature check to return to the EntryPoint
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256);

    /// @notice Check an ERC-1271 signature
    /// @param id The id of the signer config
    /// @param sender The sender of the signature
    /// @param hash The hash to check against
    /// @param sig The signature to validate
    /// @return The ERC-1271 magic value if the signature is valid
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

/// @title IStatelessValidator
/// @notice Validators that don't rely on stored state but compare against calldata-provided data
/// @dev Implements module type id: 7
/// @dev It is RECOMMENDED that all Validators (module type id 1) also implement this interface for additional composability
interface IStatelessValidator is IModule {
    /// @notice Validates a signature given some data
    /// @dev MUST validate that the signature is a valid signature of the hash
    /// MUST compare the validated signature against the data provided
    /// MUST return true if the signature is valid and false otherwise
    /// @param hash The data that was signed over
    /// @param signature The signature to verify
    /// @param data The data to validate the verified signature against
    /// @return True if the signature is valid, false otherwise
    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        returns (bool);

    /// @notice Returns boolean value if module is a certain type
    /// @param moduleTypeId the module type ID according the ERC-7579 spec
    /// @return True if the module is of the given type, false otherwise
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}
