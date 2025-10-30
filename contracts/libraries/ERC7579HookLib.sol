// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ModuleStorage} from "../accounts/ModuleStorage.sol";
import {IERC7579Hook, MODULE_TYPE_HOOK} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title ERC7579HookLib
/// @notice Library for managing ERC-7579 hook execution
/// @dev Handles pre-execution and post-execution hook invocations
///      with deterministic ordering based on install order.
library ERC7579HookLib {
    using ModuleStorage for ModuleStorage.Layout;

    /// @notice Runs pre-execution hooks on all installed hook modules
    /// @dev Hook reverts will propagate and halt execution per ERC-7579 spec.
    ///      This allows hooks to enforce security policies.
    /// @param $ Storage layout reference
    /// @param caller The address initiating the execution
    /// @param value The ETH value being transferred
    /// @param callData The calldata being executed
    /// @return hooks Array of hook addresses that were called
    /// @return contexts Array of context data returned by each hook's preCheck
    function runHooksPre(ModuleStorage.Layout storage $, address caller, uint256 value, bytes calldata callData)
        internal
        returns (address[] memory hooks, bytes[] memory contexts)
    {
        uint256 count = $.moduleCount(MODULE_TYPE_HOOK);
        if (count == 0) {
            return (new address[](0), new bytes[](0));
        }

        hooks = new address[](count);
        contexts = new bytes[](count);

        for (uint256 i = 0; i < count;) {
            address hook = $.moduleAt(MODULE_TYPE_HOOK, i);
            hooks[i] = hook;
            // Intentionally no try-catch: hook reverts will propagate and stop execution
            contexts[i] = IERC7579Hook(hook).preCheck(caller, value, callData);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Runs post-execution hooks on all previously invoked hooks
    /// @dev Hook reverts will propagate per ERC-7579 spec.
    ///      Hooks can validate execution results and revert if needed.
    ///      IMPORTANT: Must pass the same hooks/contexts from preCheck to maintain state
    /// @param hooks Array of hook addresses (from runHooksPre)
    /// @param contexts Array of context data (from runHooksPre)
    function runHooksPost(address[] memory hooks, bytes[] memory contexts) internal {
        uint256 count = hooks.length;
        if (count == 0) {
            return;
        }

        for (uint256 i = 0; i < count;) {
            // Intentionally no try-catch: hook reverts will propagate and stop execution
            IERC7579Hook(hooks[i]).postCheck(contexts[i]);
            unchecked {
                ++i;
            }
        }
    }
}
