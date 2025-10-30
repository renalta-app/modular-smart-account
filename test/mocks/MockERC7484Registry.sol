// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7484Registry} from "../../contracts/interfaces/IERC7484.sol";

/// @dev Mock ERC-7484 Registry for testing
/// Allows configuring which modules pass/fail attestation checks
contract MockERC7484Registry is IERC7484Registry {
    // module => isAttested
    mapping(address => bool) public moduleAttestations;

    // module => moduleType => isValid
    mapping(address => mapping(uint256 => bool)) public moduleTypeValidations;

    error ModuleNotAttested();
    error InsufficientAttestations();

    /// @dev Set whether a module is attested
    function setModuleAttestation(address module, bool attested) external {
        moduleAttestations[module] = attested;
    }

    /// @dev Set whether a module's type is valid
    function setModuleTypeValidation(address module, uint256 moduleType, bool valid) external {
        moduleTypeValidations[module][moduleType] = valid;
    }

    function check(address module) external view override {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
    }

    function checkForAccount(
        address,
        /* smartAccount */
        address module
    )
        external
        view
        override
    {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
    }

    function check(address module, uint256 moduleType) external view override {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
        if (!moduleTypeValidations[module][moduleType]) {
            revert ModuleNotAttested();
        }
    }

    function checkForAccount(
        address,
        /* smartAccount */
        address module,
        uint256 moduleType
    )
        external
        view
        override
    {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
        if (!moduleTypeValidations[module][moduleType]) {
            revert ModuleNotAttested();
        }
    }

    function trustAttesters(
        uint8,
        /* threshold */
        address[] calldata /* attesters */
    )
        external
        override
    {
        // No-op in mock
    }

    function check(
        address module,
        address[] calldata,
        /* attesters */
        uint256 /* threshold */
    )
        external
        view
        override
    {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
    }

    function check(
        address module,
        uint256 moduleType,
        address[] calldata,
        /* attesters */
        uint256 /* threshold */
    )
        external
        view
        override
    {
        if (!moduleAttestations[module]) {
            revert ModuleNotAttested();
        }
        if (!moduleTypeValidations[module][moduleType]) {
            revert ModuleNotAttested();
        }
    }
}
