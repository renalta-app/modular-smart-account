// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title UserOpHelpers
/// @notice Helper library for ERC-4337 UserOperation construction and signing
library UserOpHelpers {
    // ERC-4337 UserOperation constants
    string internal constant DOMAIN_NAME = "ERC4337";
    string internal constant DOMAIN_VERSION = "1";
    bytes32 internal constant PACKED_USEROP_TYPEHASH = keccak256(
        "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"
    );
    bytes2 internal constant INITCODE_EIP7702_MARKER = 0x7702;

    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint128 callGasLimit;
        uint128 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        address paymaster;
        uint128 paymasterVerificationGasLimit;
        uint128 paymasterPostOpGasLimit;
        bytes paymasterData;
        bytes signature;
    }

    /// @notice Get default UserOperation values
    function getDefaultUserOp() internal pure returns (UserOperation memory) {
        return UserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 150000,
            preVerificationGas: 21000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1e9,
            paymaster: address(0),
            paymasterData: "",
            paymasterVerificationGasLimit: 3e5,
            paymasterPostOpGasLimit: 0,
            signature: ""
        });
    }

    /// @notice Pack two uint128 gas limits into bytes32
    function packGasLimits(uint128 high, uint128 low) internal pure returns (bytes32) {
        return bytes32((uint256(high) << 128) | uint256(low));
    }

    /// @notice Pack paymaster data into bytes
    function packPaymasterData(
        address paymaster,
        uint128 verificationGasLimit,
        uint128 postOpGasLimit,
        bytes memory paymasterData
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit, paymasterData);
    }

    /// @notice Pack UserOperation into PackedUserOperation format
    function packUserOp(UserOperation memory userOp) internal pure returns (PackedUserOperation memory) {
        bytes32 accountGasLimits = packGasLimits(userOp.verificationGasLimit, userOp.callGasLimit);
        bytes32 gasFees = packGasLimits(uint128(userOp.maxPriorityFeePerGas), uint128(userOp.maxFeePerGas));

        bytes memory paymasterAndData = "";
        if (userOp.paymaster != address(0)) {
            paymasterAndData = packPaymasterData(
                userOp.paymaster,
                userOp.paymasterVerificationGasLimit,
                userOp.paymasterPostOpGasLimit,
                userOp.paymasterData
            );
        }

        return PackedUserOperation({
            sender: userOp.sender,
            nonce: userOp.nonce,
            initCode: userOp.initCode,
            callData: userOp.callData,
            accountGasLimits: accountGasLimits,
            preVerificationGas: userOp.preVerificationGas,
            gasFees: gasFees,
            paymasterAndData: paymasterAndData,
            signature: userOp.signature
        });
    }

    /// @notice Get EIP-712 domain separator for UserOperation signing
    function getDomainSeparator(address entryPoint, uint256 chainId) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                chainId,
                entryPoint
            )
        );
    }

    /// @notice Encode PackedUserOperation for EIP-712 signature
    function encodeUserOpForSignature(PackedUserOperation memory packedUserOp) internal pure returns (bytes memory) {
        return abi.encode(
            PACKED_USEROP_TYPEHASH,
            packedUserOp.sender,
            packedUserOp.nonce,
            keccak256(packedUserOp.initCode),
            keccak256(packedUserOp.callData),
            packedUserOp.accountGasLimits,
            packedUserOp.preVerificationGas,
            packedUserOp.gasFees,
            keccak256(packedUserOp.paymasterAndData)
        );
    }

    /// @notice Get UserOperation hash for signature verification
    function getUserOpHash(UserOperation memory userOp, address entryPoint, uint256 chainId)
        internal
        pure
        returns (bytes32)
    {
        PackedUserOperation memory packed = packUserOp(userOp);
        bytes memory encoded = encodeUserOpForSignature(packed);

        return keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(entryPoint, chainId), keccak256(encoded)));
    }

    /// @notice Check if UserOp initCode indicates EIP-7702 delegation
    function isEip7702UserOp(UserOperation memory userOp) internal pure returns (bool) {
        if (userOp.initCode.length < 2) return false;
        bytes memory initCode = userOp.initCode;
        bytes2 marker;
        assembly {
            marker := mload(add(initCode, 32))
        }
        return marker == INITCODE_EIP7702_MARKER;
    }

    /// @notice Sign UserOperation with a private key (using Foundry's vm.sign)
    function signUserOp(Vm vm, UserOperation memory userOp, uint256 privateKey, address entryPoint, uint256 chainId)
        internal
        pure
        returns (UserOperation memory)
    {
        bytes32 hash = getUserOpHash(userOp, entryPoint, chainId);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        userOp.signature = abi.encodePacked(r, s, v);
        return userOp;
    }

    /// @notice Fill UserOperation with default values for unset fields
    function fillUserOpDefaults(UserOperation memory userOp) internal pure returns (UserOperation memory) {
        UserOperation memory defaults = getDefaultUserOp();

        if (userOp.sender == address(0)) userOp.sender = defaults.sender;
        if (userOp.verificationGasLimit == 0) userOp.verificationGasLimit = defaults.verificationGasLimit;
        if (userOp.preVerificationGas == 0) userOp.preVerificationGas = defaults.preVerificationGas;
        if (userOp.maxPriorityFeePerGas == 0) userOp.maxPriorityFeePerGas = defaults.maxPriorityFeePerGas;

        return userOp;
    }

    /// @notice Create a UserOperation with common test values pre-filled
    /// @param sender Account address that will execute the operation
    /// @param nonce The nonce for this operation
    /// @return userOp UserOperation with sender, nonce, and standard gas limits set
    function createUserOp(address sender, uint256 nonce) internal pure returns (UserOperation memory userOp) {
        userOp = getDefaultUserOp();
        userOp.sender = sender;
        userOp.nonce = nonce;
        userOp.callGasLimit = 100000;
        userOp.verificationGasLimit = 100000;
    }

    /// @notice Create a UserOperation with custom gas limits
    /// @param sender Account address that will execute the operation
    /// @param nonce The nonce for this operation
    /// @param callGasLimit Gas limit for the execution phase
    /// @param verificationGasLimit Gas limit for the verification phase
    /// @return userOp UserOperation with specified values
    function createUserOp(address sender, uint256 nonce, uint128 callGasLimit, uint128 verificationGasLimit)
        internal
        pure
        returns (UserOperation memory userOp)
    {
        userOp = getDefaultUserOp();
        userOp.sender = sender;
        userOp.nonce = nonce;
        userOp.callGasLimit = callGasLimit;
        userOp.verificationGasLimit = verificationGasLimit;
    }
}
