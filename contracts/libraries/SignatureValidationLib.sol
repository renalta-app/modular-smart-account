// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";
import {ModuleStorage} from "../accounts/ModuleStorage.sol";
import {IERC7579Validator, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7780PolicyLib} from "./ERC7780PolicyLib.sol";
import {ERC7780SignerLib} from "./ERC7780SignerLib.sol";

/// @title SignatureValidationLib
/// @notice Library for ERC-4337 and ERC-1271 signature validation with ERC-7780 support
/// @dev Handles signature validation for both normal mode and EIP-7702 delegate mode
library SignatureValidationLib {
    using ModuleStorage for ModuleStorage.Layout;
    using EnumerableSet for EnumerableSet.AddressSet;
    using MessageHashUtils for bytes32;
    using ERC7780PolicyLib for ModuleStorage.Layout;
    using ERC7780SignerLib for ModuleStorage.Layout;

    /// @notice Validates a UserOperation signature and checks policies
    /// @param $ Storage layout reference
    /// @param owner The account owner address (EOA in 7702 mode, stored owner otherwise)
    /// @param userOp The packed user operation
    /// @param userOpHash The hash of the user operation
    /// @return validationData Packed validation result (0 for success, non-zero for failure)
    function _validateUserOp(
        ModuleStorage.Layout storage $,
        address owner,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        validationData = _validateUserOpSignature($, owner, userOp, userOpHash);

        // Always check policies even if signature validation failed
        // This ensures accurate gas estimation per ERC-4337 guidelines
        uint256 policyResult = $.checkUserOpPolicy(bytes32(0), userOp);
        if (policyResult != 0) {
            return _intersectValidationData(validationData, policyResult);
        }

        return validationData;
    }

    /// @notice Intersects two validationData values by taking the most restrictive time bounds
    /// @dev ValidationData format (ERC-4337):
    ///      - bits 0-159: authorizer (0=valid, 1=invalid, otherwise=aggregator address)
    ///      - bits 160-207: validUntil timestamp (48 bits)
    ///      - bits 208-255: validAfter timestamp (48 bits)
    /// @param validationData1 First validation data
    /// @param validationData2 Second validation data
    /// @return Intersected validation data with most restrictive time bounds
    function _intersectValidationData(uint256 validationData1, uint256 validationData2)
        private
        pure
        returns (uint256)
    {
        uint256 authorizer1 = validationData1 & ((1 << 160) - 1);
        uint256 authorizer2 = validationData2 & ((1 << 160) - 1);

        if ((authorizer1 & 1) != 0) return validationData1;
        if ((authorizer2 & 1) != 0) return validationData2;

        uint48 validUntil1 = uint48((validationData1 >> 160) & 0xFFFFFFFFFFFF);
        uint48 validAfter1 = uint48(validationData1 >> 208);
        uint48 validUntil2 = uint48((validationData2 >> 160) & 0xFFFFFFFFFFFF);
        uint48 validAfter2 = uint48(validationData2 >> 208);

        uint48 validAfter = validAfter1 > validAfter2 ? validAfter1 : validAfter2;
        uint48 validUntil;

        if (validUntil1 == 0) {
            validUntil = validUntil2;
        } else if (validUntil2 == 0) {
            validUntil = validUntil1;
        } else {
            validUntil = validUntil1 < validUntil2 ? validUntil1 : validUntil2;
        }

        return uint256(validAfter) << 208 | uint256(validUntil) << 160;
    }

    /// @notice Validates a UserOperation signature
    /// @dev Tries signers, validators, then owner. Stops on first valid signature.
    /// @param $ Storage layout reference
    /// @param owner The account owner address (EOA in 7702 mode, stored owner otherwise)
    /// @param userOp The packed user operation
    /// @param userOpHash The hash of the user operation
    /// @return validationData Packed validation result (0 for success, 1 for failure)
    function _validateUserOpSignature(
        ModuleStorage.Layout storage $,
        address owner,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        bool authenticated = false;
        bool isEip7702Mode = EIP7702Utils.fetchDelegate(address(this)) != address(0);

        // Try signer modules first (bytes32(0) is the default signer ID)
        validationData = $.checkUserOpSignature(bytes32(0), userOp, userOpHash);
        if ((validationData & 1) == 0) {
            authenticated = true;
        }

        // Try validator modules
        if (!authenticated) {
            EnumerableSet.AddressSet storage validators = $.moduleSets[MODULE_TYPE_VALIDATOR];
            uint256 count = validators.length();

            for (uint256 i = 0; i < count;) {
                address module = validators.at(i);
                uint256 result = IERC7579Validator(module).validateUserOp(userOp, userOpHash);
                // Check bit-0 of validationData: 0 = valid, 1 = invalid
                if ((result & 1) == 0) {
                    validationData = result;
                    authenticated = true;
                    break;
                }
                unchecked {
                    ++i;
                }
            }
        }

        if (!authenticated) {
            if (isEip7702Mode) {
                if (_isValidEip7702Signature(userOpHash, userOp.signature)) {
                    validationData = ERC4337Utils.SIG_VALIDATION_SUCCESS;
                    authenticated = true;
                }
            } else {
                if (_isValidOwnerSignature(owner, userOpHash, userOp.signature)) {
                    validationData = ERC4337Utils.SIG_VALIDATION_SUCCESS;
                    authenticated = true;
                }
            }
        }

        if (!authenticated) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        return validationData;
    }

    /// @notice Validates a signature for ERC-1271 compatibility and checks policies
    /// @dev Tries EIP-7739, signers, validators, then owner. Stops on first valid signature.
    /// @param $ Storage layout reference
    /// @param owner The account owner address (EOA in 7702 mode, stored owner otherwise)
    /// @param hash The hash to validate
    /// @param signature The signature bytes
    /// @param sender The address calling isValidSignature (for validator context)
    /// @param domainSeparator The EIP-712 domain separator of the account
    /// @return True if signature is valid, false otherwise
    function isValidSignature(
        ModuleStorage.Layout storage $,
        address owner,
        bytes32 hash,
        bytes calldata signature,
        address sender,
        bytes32 domainSeparator
    ) internal view returns (bool) {
        bool authenticated = false;
        bool isEip7702Mode = EIP7702Utils.fetchDelegate(address(this)) != address(0);

        // Try EIP-7739 (skipped in EIP-7702 mode where EOA signature is already bound to address(this))
        if (!isEip7702Mode && _isValidEip7739PersonalSign(owner, hash, signature, domainSeparator)) {
            authenticated = true;
        }

        // Try signer modules (bytes32(0) is the default signer ID)
        if (!authenticated) {
            bytes4 signerResult = $.checkSignature(bytes32(0), sender, hash, signature);
            // Check for ERC-1271 magic value (0x1626ba7e)
            if (signerResult == 0x1626ba7e) {
                authenticated = true;
            }
        }

        // Try validator modules
        if (!authenticated) {
            EnumerableSet.AddressSet storage validators = $.moduleSets[MODULE_TYPE_VALIDATOR];
            uint256 count = validators.length();

            for (uint256 i = 0; i < count;) {
                address module = validators.at(i);
                if (_validatorAcceptsSignature(module, sender, hash, signature)) {
                    authenticated = true;
                    break;
                }
                unchecked {
                    ++i;
                }
            }
        }

        if (!authenticated) {
            if (isEip7702Mode) {
                if (_isValidEip7702Signature(hash, signature)) {
                    authenticated = true;
                }
            } else {
                if (SignatureCheckerLib.isValidSignatureNow(owner, hash, signature)) {
                    authenticated = true;
                }
            }
        }

        if (!authenticated) {
            return false;
        }

        uint256 policyResult = $.checkSignaturePolicy(bytes32(0), sender, hash, signature);
        if (policyResult != 0) {
            return false;
        }

        return true;
    }

    /// @dev Validates EIP-7702 EOA signature, trying both standard ECDSA and eth_sign formats
    function _isValidEip7702Signature(bytes32 hash, bytes calldata signature) private view returns (bool) {
        address signer = _tryRecover(hash, signature);
        if (signer == address(this)) {
            return true;
        }
        signer = _tryRecover(hash.toEthSignedMessageHash(), signature);
        return signer == address(this);
    }

    /// @dev Validates signature for expected signer (EOA or contract)
    function _isValidOwnerSignature(address expectedSigner, bytes32 hash, bytes calldata signature)
        private
        view
        returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNow(expectedSigner, hash, signature);
    }

    /// @dev Recovers signer, returning address(0) on failure
    function _tryRecover(bytes32 hash, bytes calldata signature) private view returns (address) {
        return ECDSA.tryRecover(hash, signature);
    }

    /// @dev Validates an EIP-7739 PersonalSign signature
    function _isValidEip7739PersonalSign(
        address owner,
        bytes32 hash,
        bytes calldata signature,
        bytes32 domainSeparator
    ) private view returns (bool) {
        bytes32 personalSignStructHash = ERC7739Utils.personalSignStructHash(hash);
        bytes32 finalHash = domainSeparator.toTypedDataHash(personalSignStructHash);
        return SignatureCheckerLib.isValidSignatureNow(owner, finalHash, signature);
    }

    /// @dev Checks if a validator module accepts a signature
    function _validatorAcceptsSignature(address validator, address sender, bytes32 hash, bytes calldata signature)
        private
        view
        returns (bool)
    {
        bytes memory processedSignature = signature;

        if (signature.length > 20) {
            address declaredValidator;
            assembly {
                declaredValidator := shr(96, calldataload(signature.offset))
            }

            if (declaredValidator == validator) {
                uint256 withoutAddressLength = signature.length - 20;
                bytes memory stripped = new bytes(withoutAddressLength);
                for (uint256 i; i < withoutAddressLength;) {
                    stripped[i] = signature[i + 20];
                    unchecked {
                        ++i;
                    }
                }
                processedSignature = stripped;

                if (processedSignature.length > 1 && processedSignature[0] == bytes1(0x01)) {
                    uint256 trimmedLength = processedSignature.length - 1;
                    bytes memory trimmed = new bytes(trimmedLength);
                    for (uint256 j; j < trimmedLength;) {
                        trimmed[j] = processedSignature[j + 1];
                        unchecked {
                            ++j;
                        }
                    }
                    processedSignature = trimmed;
                }
            }
        }

        try IERC7579Validator(validator).isValidSignatureWithSender(sender, hash, processedSignature) returns (
            bytes4 magic
        ) {
            return magic == IERC1271.isValidSignature.selector;
        } catch {
            return false;
        }
    }
}
