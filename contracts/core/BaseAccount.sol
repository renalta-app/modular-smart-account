// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccount, PackedUserOperation, IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {LibCall} from "solady/utils/LibCall.sol";
import {ExecutionLib} from "../libraries/ExecutionLib.sol";

/// @title BaseAccount
/// @notice Base contract for ERC-4337 account implementations
/// @dev Provides core account logic including UserOp validation and execution
///      Specific account implementations should inherit this and provide signature validation
abstract contract BaseAccount is IAccount {
    /// @notice Call structure for batch execution
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Thrown when a call in a batch execution fails
    /// @param index The index of the failed call in the batch
    /// @param error The revert data from the failed call
    error ExecuteError(uint256 index, bytes error);

    /// @notice Thrown when called by an address that is not the EntryPoint
    error NotFromEntryPoint();

    /// @notice Returns the account's next sequential nonce
    /// @dev For nonces with specific keys, use `entryPoint().getNonce(account, key)`
    /// @return The next sequential nonce (key 0)
    function getNonce() external view virtual returns (uint256) {
        return entryPoint().getNonce(address(this), 0);
    }

    /// @notice Returns the EntryPoint used by this account
    /// @dev Must be implemented by subclasses to return the canonical EntryPoint
    /// @return The EntryPoint contract address
    function entryPoint() public view virtual returns (IEntryPoint);

    /// @notice Executes a single call from the account
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata to send
    function execute(address target, uint256 value, bytes calldata data) external virtual {
        _requireForExecute();

        bool ok = ExecutionLib.call(target, value, data, gasleft());
        if (!ok) {
            LibCall.bubbleUpRevert(ExecutionLib.getReturnData(0));
        }
    }

    /// @notice Executes a batch of calls from the account
    /// @dev Reverts on the first failing call. For multi-call batches, wraps revert with ExecuteError
    /// @param calls Array of Call structs to execute
    function executeBatch(Call[] calldata calls) external virtual {
        _requireForExecute();

        uint256 callsLength = calls.length;
        for (uint256 i = 0; i < callsLength;) {
            Call calldata call = calls[i];
            bool ok = ExecutionLib.call(call.target, call.value, call.data, gasleft());
            if (!ok) {
                if (callsLength == 1) {
                    LibCall.bubbleUpRevert(ExecutionLib.getReturnData(0));
                } else {
                    revert ExecuteError(i, ExecutionLib.getReturnData(0));
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        override
        returns (uint256 validationData)
    {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    /// @dev Ensures the caller is the EntryPoint
    function _requireFromEntryPoint() internal view virtual {
        if (msg.sender != address(entryPoint())) {
            revert NotFromEntryPoint();
        }
    }

    /// @dev Ensures the caller is authorized to execute
    /// @dev Default implementation requires calls from EntryPoint only
    function _requireForExecute() internal view virtual {
        _requireFromEntryPoint();
    }

    /// @dev Validates the signature for a UserOperation
    /// @param userOp The UserOperation to validate
    /// @param userOpHash The hash of the UserOperation (includes EntryPoint and chain ID)
    /// @return validationData Packed validation data:
    ///         - [0:19]: aggregatorOrSigFail (0 = valid, 1 = invalid, otherwise aggregator address)
    ///         - [20:25]: validUntil timestamp (0 for no expiry)
    ///         - [26:31]: validAfter timestamp
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData);

    /// @dev Validates the nonce of a UserOperation
    /// @dev Override to enforce nonce ordering requirements. The EntryPoint handles nonce uniqueness.
    ///      Examples:
    ///      - Sequential only: `require(nonce < type(uint64).max)`
    ///      - Out-of-order only: `require(nonce & type(uint64).max == 0)`
    /// @param nonce The nonce to validate
    function _validateNonce(uint256 nonce) internal view virtual {}

    /// @dev Sends the missing funds to the EntryPoint to cover this transaction
    /// @dev Override to implement custom fund management (e.g., over-deposit to reduce future transfers)
    /// @param missingAccountFunds The minimum amount to send (may be 0 if deposit is sufficient or paymaster is used)
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success);
        }
    }
}
