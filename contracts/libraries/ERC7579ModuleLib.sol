// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ModuleStorage} from "../accounts/ModuleStorage.sol";
import {IERC7579Module, MODULE_TYPE_FALLBACK} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC7484Registry} from "../interfaces/IERC7484.sol";

/// @title ERC7579ModuleLib
/// @notice Library for ERC-7579 module lifecycle management
/// @dev Handles installation, uninstallation, and validation of modules with ERC-7484 registry attestation support
library ERC7579ModuleLib {
    using ModuleStorage for ModuleStorage.Layout;

    /// @notice Thrown when trying to install a fallback handler for an already-registered selector
    /// @param selector The function selector that already has a handler
    error FallbackAlreadySet(bytes4 selector);

    /// @notice Thrown when trying to uninstall a fallback handler that doesn't match
    /// @param selector The function selector
    /// @param expected The expected handler address
    /// @param actual The actual handler address
    error FallbackMismatch(bytes4 selector, address expected, address actual);

    /// @notice Thrown when fallback init/deinit data doesn't contain a 4-byte selector
    error InvalidFallbackInitData();

    /// @notice Emitted when a module is successfully installed
    /// @param moduleTypeId The type of module installed
    /// @param module The address of the installed module
    event ModuleInstalled(uint256 moduleTypeId, address module);

    /// @notice Emitted when a module is successfully uninstalled
    /// @param moduleTypeId The type of module uninstalled
    /// @param module The address of the uninstalled module
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    /// @notice Installs a module with lifecycle management
    /// @dev Handles special module types and calls onInstall hook.
    ///      Special handling:
    ///      - Fallback: Selector extracted from initData, registered in mapping
    /// @param $ Storage layout reference
    /// @param moduleTypeId The type of module to install (1-4)
    /// @param module The module address
    /// @param initData Initialization data for the module
    function installModule(
        ModuleStorage.Layout storage $,
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    ) internal {
        // Handle module-type specific installation
        if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            _installFallbackModule($, module, initData);
        } else {
            $.addModule(moduleTypeId, module);
        }

        // Call module's onInstall hook
        // For fallback, strip selector from initData before passing
        bytes calldata moduleInitData = moduleTypeId == MODULE_TYPE_FALLBACK ? initData[4:] : initData;
        IERC7579Module(module).onInstall(moduleInitData);

        emit ModuleInstalled(moduleTypeId, module);
    }

    /// @notice Uninstalls a module with cleanup
    /// @dev Handles fallback handler cleanup.
    ///      Special handling: Fallback modules remove selector mapping.
    ///      Note: Allows removing all validators - account has owner fallback validation
    ///      (see SignatureValidationLib for owner fallback in both UserOp and ERC-1271 flows)
    /// @param $ Storage layout reference
    /// @param moduleTypeId The type of module to uninstall
    /// @param module The module address
    /// @param deInitData De-initialization data for the module
    function uninstallModule(
        ModuleStorage.Layout storage $,
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    ) internal {
        // fallback modules must be handled specially
        if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            _uninstallFallbackModule($, module, deInitData);
        } else {
            $.removeModule(moduleTypeId, module);
        }

        // Call module's onUninstall hook
        // For fallback, strip selector from deInitData before passing
        bytes calldata moduleDeInitData = moduleTypeId == MODULE_TYPE_FALLBACK ? deInitData[4:] : deInitData;
        IERC7579Module(module).onUninstall(moduleDeInitData);

        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @notice Checks if a module is installed (with fallback special handling)
    /// @dev For fallback modules, additionalContext must contain the 4-byte selector
    /// @param $ Storage layout reference
    /// @param moduleTypeId The module type
    /// @param module The module address
    /// @param additionalContext For fallbacks: selector (4 bytes)
    /// @return True if module is installed
    function isModuleInstalled(
        ModuleStorage.Layout storage $,
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) internal view returns (bool) {
        if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            // For fallback, additionalContext must contain the selector (4 bytes)
            if (additionalContext.length < 4) return false;
            bytes4 selector = bytes4(additionalContext[0:4]);
            return $.fallbackHandlers[selector] == module;
        }
        return $.isModuleInstalled(moduleTypeId, module);
    }

    /// @notice Checks module attestation via ERC-7484 registry
    /// @dev Only checks if registry is configured and threshold > 0.
    ///      Reverts if attestation check fails
    /// @param $ Storage layout reference
    /// @param module The module to check
    /// @param moduleTypeId The module type
    function checkModuleAttestation(ModuleStorage.Layout storage $, address module, uint256 moduleTypeId)
        internal
        view
    {
        address registry = $.moduleRegistry;
        if (registry == address(0)) return; // No registry configured

        uint8 threshold = $.attestationThreshold;

        if (threshold > 0) {
            IERC7484Registry(registry).check(module, moduleTypeId, $.attesters, threshold);
        } else {
            IERC7484Registry(registry).checkForAccount(address(this), module, moduleTypeId);
        }
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    /// @dev Installs a fallback handler module
    /// @param $ Storage layout reference
    /// @param module The fallback handler address
    /// @param initData Must contain selector (4 bytes) + additional init data
    function _installFallbackModule(ModuleStorage.Layout storage $, address module, bytes calldata initData) private {
        // extract selector from initData (first 4 bytes)
        if (initData.length < 4) revert InvalidFallbackInitData();
        bytes4 selector = bytes4(initData[0:4]);

        if ($.fallbackHandlers[selector] != address(0)) {
            revert FallbackAlreadySet(selector);
        }

        $.fallbackHandlers[selector] = module;
        $.addModule(MODULE_TYPE_FALLBACK, module);
    }

    /// @dev Uninstalls a fallback handler module
    /// @param $ Storage layout reference
    /// @param module The fallback handler address
    /// @param deInitData Must contain selector (4 bytes) + additional deinit data
    function _uninstallFallbackModule(ModuleStorage.Layout storage $, address module, bytes calldata deInitData)
        private
    {
        // extract selector from deInitData (first 4 bytes)
        if (deInitData.length < 4) revert InvalidFallbackInitData();
        bytes4 selector = bytes4(deInitData[0:4]);

        address current = $.fallbackHandlers[selector];
        if (current != module) {
            revert FallbackMismatch(selector, current, module);
        }

        $.fallbackHandlers[selector] = address(0);
        $.removeModule(MODULE_TYPE_FALLBACK, module);
    }
}
