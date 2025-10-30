// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR,
    VALIDATION_FAILED,
    VALIDATION_SUCCESS
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title OwnerValidatorModule
/// @notice Simple validator module that auths a single EOA per smart account
/// @dev Designed as a production-friendly baseline for ERC-7579 validator modules.
///      Stores configuration per account and emits `OwnerUpdated` events on owner changes
contract OwnerValidatorModule is IERC7579Validator {
    using ECDSA for bytes32;

    struct Config {
        address owner;
        bool installed;
    }

    mapping(address account => Config config) private _configs;

    error OwnerValidatorModuleAlreadyInstalled(address account);
    error OwnerValidatorModuleNotInstalled(address account);
    error OwnerValidatorModuleInvalidOwner();

    event OwnerUpdated(address indexed account, address indexed previousOwner, address indexed newOwner);

    function onInstall(bytes calldata data) external override {
        Config storage cfg = _configs[msg.sender];
        if (cfg.installed) revert OwnerValidatorModuleAlreadyInstalled(msg.sender);

        address owner = abi.decode(data, (address));
        if (owner == address(0)) revert OwnerValidatorModuleInvalidOwner();

        cfg.owner = owner;
        cfg.installed = true;
        emit OwnerUpdated(msg.sender, address(0), owner);
    }

    function onUninstall(bytes calldata) external override {
        Config storage cfg = _configs[msg.sender];
        if (!cfg.installed) revert OwnerValidatorModuleNotInstalled(msg.sender);

        address previousOwner = cfg.owner;
        delete _configs[msg.sender];
        emit OwnerUpdated(msg.sender, previousOwner, address(0));
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        Config storage cfg = _configs[msg.sender];
        if (!cfg.installed) revert OwnerValidatorModuleNotInstalled(msg.sender);

        address signer = ECDSA.recover(userOpHash, userOp.signature);
        return signer == cfg.owner ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        Config storage cfg = _configs[msg.sender];
        if (!cfg.installed) {
            return 0xffffffff;
        }

        address signer = ECDSA.recover(hash, signature);
        return signer == cfg.owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    function ownerOf(address account) external view returns (address) {
        return _configs[account].owner;
    }

    function updateOwner(address newOwner) external {
        Config storage cfg = _configs[msg.sender];
        if (!cfg.installed) revert OwnerValidatorModuleNotInstalled(msg.sender);
        if (newOwner == address(0)) revert OwnerValidatorModuleInvalidOwner();

        address previousOwner = cfg.owner;
        cfg.owner = newOwner;
        emit OwnerUpdated(msg.sender, previousOwner, newOwner);
    }
}
