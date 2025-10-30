// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ModuleStorage} from "../accounts/ModuleStorage.sol";
import {ISigner, MODULE_TYPE_SIGNER} from "../interfaces/IERC7780.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title ERC7780SignerLib
/// @notice Library for managing ERC-7780 signer module execution
library ERC7780SignerLib {
    using ModuleStorage for ModuleStorage.Layout;

    /// @notice Validates a UserOperation signature using installed signer modules
    /// @dev Only a single signer must return success (0) to approve the UserOp.
    ///      Returns 1 if no signers are installed or none validated successfully.
    /// @param $ Storage layout reference
    /// @param id The signer identifier
    /// @param userOp The UserOperation to validate
    /// @param userOpHash The hash of the UserOperation
    /// @return validation The validation result (0 = success, non-zero = failure)
    function checkUserOpSignature(
        ModuleStorage.Layout storage $,
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validation) {
        uint256 count = $.moduleCount(MODULE_TYPE_SIGNER);
        if (count == 0) {
            return 1;
        }

        for (uint256 i = 0; i < count;) {
            address signer = $.moduleAt(MODULE_TYPE_SIGNER, i);
            validation = ISigner(signer).checkUserOpSignature(id, userOp, userOpHash);

            // Return early on first successful validation
            if ((validation & 1) == 0) {
                return validation;
            }

            unchecked {
                ++i;
            }
        }

        return 1; // No signer validated successfully
    }

    /// @notice Validates an ERC-1271 signature using installed signer modules
    /// @dev Only a signer signer must return success (0) approves the UserOp.
    ///      Returns 0xffffffff if no signers are installed or none validated successfully.
    /// @param $ Storage layout reference
    /// @param id The signer identifier
    /// @param sender The address that sent the signature
    /// @param hash The hash being signed
    /// @param sig The signature data
    /// @return The ERC-1271 magic value (0x1626ba7e) if valid, 0xffffffff otherwise
    function checkSignature(
        ModuleStorage.Layout storage $,
        bytes32 id,
        address sender,
        bytes32 hash,
        bytes calldata sig
    ) internal view returns (bytes4) {
        uint256 count = $.moduleCount(MODULE_TYPE_SIGNER);
        if (count == 0) {
            return 0xffffffff;
        }

        for (uint256 i = 0; i < count;) {
            address signer = $.moduleAt(MODULE_TYPE_SIGNER, i);
            bytes4 result = ISigner(signer).checkSignature(id, sender, hash, sig);

            // ERC-1271 magic value: 0x1626ba7e
            if (result == 0x1626ba7e) {
                return result;
            }

            unchecked {
                ++i;
            }
        }

        return 0xffffffff;
    }
}
