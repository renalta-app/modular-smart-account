// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title ModuleStorage
/// @notice Storage helpers for ERC-7579 module management
/// @dev The layout keccak slot is intentionally namespaced so upgrades can reserve
///      additional fields without clashing with the existing SimpleAccount storage
/// @custom:storage-location erc7201:smartaccount.module.storage.v1
library ModuleStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev ERC-7201 namespaced storage slot for "smartaccount.module.storage.v1"
    bytes32 internal constant STORAGE_SLOT = 0xc7dc1b39760e1f0d2996da727d34b86d38c45f80dda4cda848f9c8eddaa8e400;

    /// @notice Thrown when attempting to install a module that is already installed
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module
    error ModuleAlreadyInstalled(uint256 moduleTypeId, address module);

    /// @notice Thrown when attempting to remove a module that is not installed
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module
    error ModuleNotInstalled(uint256 moduleTypeId, address module);

    /// @notice Main storage layout for module management
    /// @dev Uses ERC-7201 namespaced storage pattern
    struct Layout {
        /// @dev Maps module type ID to the set of installed module addresses
        mapping(uint256 => EnumerableSet.AddressSet) moduleSets;
        /// @dev Selector-based fallback routing: function selector => fallback handler
        mapping(bytes4 => address) fallbackHandlers;
        /// @dev optional ERC-7484 Module Registry address
        address moduleRegistry;
        /// @dev Minimum number of registry attestations required
        uint8 attestationThreshold;
        /// @dev Array of trusted attester addresses for registry checks
        address[] attesters;
        /// @dev Reserved storage slots for future upgrades
        uint256[46] __gap;
    }

    /// @notice Returns the storage layout at the namespaced storage slot
    /// @return l The storage layout reference
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = STORAGE_SLOT;
        assembly ("memory-safe") {
            l.slot := slot
        }
    }

    /// @notice Adds a module to the installed module set
    /// @dev Reverts if module is already installed
    /// @param l The storage layout reference
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to add
    function addModule(Layout storage l, uint256 moduleTypeId, address module) internal {
        if (!l.moduleSets[moduleTypeId].add(module)) {
            revert ModuleAlreadyInstalled(moduleTypeId, module);
        }
    }

    /// @notice Removes a module from the installed module set
    /// @dev Reverts if module is not installed
    /// @param l The storage layout reference
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to remove
    function removeModule(Layout storage l, uint256 moduleTypeId, address module) internal {
        if (!l.moduleSets[moduleTypeId].remove(module)) {
            revert ModuleNotInstalled(moduleTypeId, module);
        }
    }

    /// @notice Returns the count of installed modules for a given type
    /// @param l The storage layout reference
    /// @param moduleTypeId The type ID of the module
    /// @return The number of installed modules of the given type
    function moduleCount(Layout storage l, uint256 moduleTypeId) internal view returns (uint256) {
        return l.moduleSets[moduleTypeId].length();
    }

    /// @notice Returns the module address at a specific index for a given type
    /// @param l The storage layout reference
    /// @param moduleTypeId The type ID of the module
    /// @param index The index in the module set
    /// @return The address of the module at the specified index
    function moduleAt(Layout storage l, uint256 moduleTypeId, uint256 index) internal view returns (address) {
        return l.moduleSets[moduleTypeId].at(index);
    }

    /// @notice Checks if a module is installed
    /// @param l The storage layout reference
    /// @param moduleTypeId The type ID of the module
    /// @param module The address of the module to check
    /// @return True if the module is installed, false otherwise
    function isModuleInstalled(Layout storage l, uint256 moduleTypeId, address module) internal view returns (bool) {
        return l.moduleSets[moduleTypeId].contains(module);
    }
}
