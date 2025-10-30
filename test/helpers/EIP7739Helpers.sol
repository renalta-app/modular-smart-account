// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title EIP7739Helpers
/// @notice Helper library for creating EIP-7739 wrapped signatures in tests
/// @dev EIP-7739 requires the client/wallet to wrap signatures with the account's domain
///      This helper simulates what a wallet would do when signing for a smart account
library EIP7739Helpers {
    using MessageHashUtils for bytes32;

    // EIP-712 type hash for PersonalSign
    bytes32 constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    /// @notice Creates an EIP-7739 wrapped signature for PersonalSign flow
    /// @dev This simulates what a wallet does when signing a message for a smart account
    ///      The signature includes the account's domain separator, binding it to that specific account
    /// @param vm The Foundry VM instance
    /// @param signerKey The private key to sign with
    /// @param messageHash The raw message hash to sign
    /// @param accountDomainSeparator The EIP-712 domain separator of the smart account
    /// @return The EIP-7739 wrapped signature (just the raw signature for PersonalSign flow)
    function signPersonalSign(Vm vm, uint256 signerKey, bytes32 messageHash, bytes32 accountDomainSeparator)
        internal
        pure
        returns (bytes memory)
    {
        // Step 1: Create the PersonalSign struct hash
        // personalSignStructHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, messageHash))
        bytes32 personalSignStructHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, messageHash));

        // Step 2: Combine with the account's domain separator
        // finalHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        bytes32 finalHash = accountDomainSeparator.toTypedDataHash(personalSignStructHash);

        // Step 3: Sign the final hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, finalHash);

        // Return the signature
        return abi.encodePacked(r, s, v);
    }

    /// @notice Computes the EIP-712 domain separator for a smart account
    /// @dev Matches the domain separator computed by OpenZeppelin's EIP712 contract
    /// @param accountAddress The address of the smart account
    /// @param chainId The chain ID
    /// @return The EIP-712 domain separator
    function computeDomainSeparator(address accountAddress, uint256 chainId) internal pure returns (bytes32) {
        bytes32 typeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

        bytes32 nameHash = keccak256(bytes("ModularSmartAccount"));
        bytes32 versionHash = keccak256(bytes("1"));

        return keccak256(abi.encode(typeHash, nameHash, versionHash, chainId, accountAddress));
    }
}
