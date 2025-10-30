// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IERC7484Registry
/// @notice Interface for ERC-7484 Module Registry
/// @dev Enables smart accounts to query attestations about module security from trusted attesters
interface IERC7484Registry {
    /// @notice Checks module with caller's stored attesters
    /// @param module The module address to check
    function check(address module) external view;

    /// @notice Checks module for a specific smart account
    /// @param smartAccount The smart account address
    /// @param module The module address to check
    function checkForAccount(address smartAccount, address module) external view;

    /// @notice Checks module with module type validation
    /// @param module The module address to check
    /// @param moduleType The expected module type
    function check(address module, uint256 moduleType) external view;

    /// @notice Checks module for account with type validation
    /// @param smartAccount The smart account address
    /// @param module The module address to check
    /// @param moduleType The expected module type
    function checkForAccount(address smartAccount, address module, uint256 moduleType) external view;

    /// @notice Configures trusted attesters for the caller
    /// @param threshold Minimum number of attestations required
    /// @param attesters Array of trusted attester addresses
    function trustAttesters(uint8 threshold, address[] calldata attesters) external;

    /// @notice Checks module with explicitly provided attesters
    /// @param module The module address to check
    /// @param attesters Array of attester addresses
    /// @param threshold Minimum attestations required
    function check(address module, address[] calldata attesters, uint256 threshold) external view;

    /// @notice Checks module with attesters and type validation
    /// @param module The module address to check
    /// @param moduleType The expected module type
    /// @param attesters Array of attester addresses
    /// @param threshold Minimum attestations required
    function check(address module, uint256 moduleType, address[] calldata attesters, uint256 threshold) external view;
}
