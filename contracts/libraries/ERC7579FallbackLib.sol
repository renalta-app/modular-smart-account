// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ModuleStorage} from "../accounts/ModuleStorage.sol";

/// @title ERC7579FallbackLib
/// @notice Library for ERC-7579 fallback handler routing
/// @dev Handles fallback function routing to registered handlers
library ERC7579FallbackLib {
    using ModuleStorage for ModuleStorage.Layout;

    /// @notice Thrown when no fallback handler is registered for a function selector
    /// @param selector The function selector that was called
    error FallbackNotConfigured(bytes4 selector);

    /// @notice Routes fallback calls to registered handlers
    /// @dev Appends msg.sender to calldata (ERC-2771 pattern) and forwards the call.
    ///      Uses regular call (not delegatecall) per ERC-7579 spec
    /// @param $ Storage layout reference
    /// @param callData The original calldata including selector
    function handleFallback(ModuleStorage.Layout storage $, bytes calldata callData) internal {
        bytes4 selector = bytes4(callData[0:4]);
        address handler = $.fallbackHandlers[selector];
        if (handler == address(0)) revert FallbackNotConfigured(selector);

        // Append msg.sender to calldata (ERC-2771 pattern)
        bytes memory dataWithSender = abi.encodePacked(callData, msg.sender);

        // Call handler (not delegatecall per ERC-7579 spec)
        (bool success, bytes memory returnData) = handler.call{value: msg.value}(dataWithSender);

        if (!success) {
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }

        assembly {
            return(add(returnData, 0x20), mload(returnData))
        }
    }
}
