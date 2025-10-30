// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ModuleStorage} from "../accounts/ModuleStorage.sol";
import {IPolicy, MODULE_TYPE_POLICY} from "../interfaces/IERC7780.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title ERC7780PolicyLib
/// @notice Library for managing ERC-7780 policy module execution
library ERC7780PolicyLib {
    using ModuleStorage for ModuleStorage.Layout;

    /// @notice Validates a UserOperation against all installed policy modules
    /// @dev All policies must return success (0) for the UserOp to be valid.
    ///      Returns the first non-zero validation result encountered.
    /// @param $ Storage layout reference
    /// @param id The policy identifier
    /// @param userOp The UserOperation to validate
    /// @return validation The validation result (0 = success, non-zero = failure)
    function checkUserOpPolicy(ModuleStorage.Layout storage $, bytes32 id, PackedUserOperation calldata userOp)
        internal
        returns (uint256 validation)
    {
        uint256 count = $.moduleCount(MODULE_TYPE_POLICY);
        if (count == 0) {
            return 0;
        }

        for (uint256 i = 0; i < count;) {
            address policy = $.moduleAt(MODULE_TYPE_POLICY, i);
            validation = IPolicy(policy).checkUserOpPolicy(id, userOp);

            // Return immediately on first failure
            if (validation != 0) {
                return validation;
            }

            unchecked {
                ++i;
            }
        }

        return 0;
    }

    /// @notice Validates a signature against all installed policy modules
    /// @dev All policies must return success (0) for the signature to be valid.
    ///      Returns the first non-zero validation result encountered.
    /// @param $ Storage layout reference
    /// @param id The policy identifier
    /// @param sender The address that sent the signature
    /// @param hash The hash being signed
    /// @param sig The signature data
    /// @return validation The validation result (0 = success, non-zero = failure)
    function checkSignaturePolicy(
        ModuleStorage.Layout storage $,
        bytes32 id,
        address sender,
        bytes32 hash,
        bytes calldata sig
    ) internal view returns (uint256 validation) {
        uint256 count = $.moduleCount(MODULE_TYPE_POLICY);
        if (count == 0) {
            return 0;
        }

        for (uint256 i = 0; i < count;) {
            address policy = $.moduleAt(MODULE_TYPE_POLICY, i);
            validation = IPolicy(policy).checkSignaturePolicy(id, sender, hash, sig);

            // Return immediately on first failure
            if (validation != 0) {
                return validation;
            }

            unchecked {
                ++i;
            }
        }

        return 0;
    }
}
