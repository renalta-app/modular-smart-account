// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IPolicy, ISigner, IStatelessValidator} from "../../../contracts/interfaces/IERC7780.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IModule} from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR
} from "../../../contracts/interfaces/IERC7780.sol";

/// @title TestPolicyModule
/// @notice Test implementation of ERC-7780 Policy module
/// @dev Simple policy that checks gas price limits
contract TestPolicyModule is IPolicy, IERC7579Module {
    /// @dev Mapping of policy ID to max gas price allowed
    mapping(bytes32 => uint256) public maxGasPrice;

    /// @notice Thrown when gas price exceeds limit
    error GasPriceTooHigh(uint256 actual, uint256 max);

    /// @notice Thrown when module is already initialized
    error AlreadyInitialized();

    /// @notice Initialize the policy with a max gas price
    /// @dev data should be abi.encoded(bytes32 id, uint256 maxGas)
    function onInstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            (bytes32 id, uint256 maxGas) = abi.decode(data, (bytes32, uint256));
            if (maxGasPrice[id] != 0) revert AlreadyInitialized();
            maxGasPrice[id] = maxGas;
        }
    }

    /// @notice Clean up the policy
    function onUninstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            bytes32 id = abi.decode(data, (bytes32));
            delete maxGasPrice[id];
        }
    }

    /// @notice Check if module is of given type
    function isModuleType(uint256 moduleTypeId) external pure override(IModule, IERC7579Module) returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    /// @notice Check if module is initialized for a smart account
    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    /// @notice Check UserOp against gas price policy
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        uint256 max = maxGasPrice[id];
        if (max == 0) return 0;

        uint256 maxFeePerGas = uint256(bytes32(userOp.gasFees) >> 128);
        if (maxFeePerGas > max) {
            return 1;
        }
        return 0;
    }

    /// @notice Check signature against policy (allow all for this test)
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}

/// @title TestSignerModule
/// @notice Test implementation of ERC-7780 Signer module
/// @dev Simple ECDSA signer module
contract TestSignerModule is ISigner, IERC7579Module {
    /// @dev Mapping of signer ID to authorized signer address
    mapping(bytes32 => address) public authorizedSigner;

    /// @notice Thrown when module is already initialized
    error AlreadyInitialized();

    /// @notice Initialize the signer with an authorized address
    /// @dev data should be abi.encoded(bytes32 id, address signer)
    function onInstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            (bytes32 id, address signer) = abi.decode(data, (bytes32, address));
            if (authorizedSigner[id] != address(0)) revert AlreadyInitialized();
            authorizedSigner[id] = signer;
        }
    }

    /// @notice Clean up the signer
    function onUninstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            bytes32 id = abi.decode(data, (bytes32));
            delete authorizedSigner[id];
        }
    }

    /// @notice Check if module is of given type
    function isModuleType(uint256 moduleTypeId) external pure override(IModule, IERC7579Module) returns (bool) {
        return moduleTypeId == MODULE_TYPE_SIGNER;
    }

    /// @notice Check if module is initialized for a smart account
    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    /// @notice Check UserOp signature
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address signer = authorizedSigner[id];
        if (signer == address(0)) return 1;

        address recovered = ECDSA.tryRecover(userOpHash, userOp.signature);
        if (recovered == signer) {
            return 0;
        }
        return 1;
    }

    /// @notice Check ERC-1271 signature
    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address signer = authorizedSigner[id];
        if (signer == address(0)) return 0xffffffff;

        address recovered = ECDSA.tryRecover(hash, sig);
        if (recovered == signer) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/// @title TestStatelessValidator
/// @notice Test implementation of ERC-7780 Stateless Validator
/// @dev Validates ECDSA signatures against calldata-provided addresses
contract TestStatelessValidator is IStatelessValidator {
    /// @notice Initialize the validator (no-op for stateless validator)
    function onInstall(bytes calldata) external override {}

    /// @notice Clean up the validator (no-op for stateless validator)
    function onUninstall(bytes calldata) external override {}

    /// @notice Check if module is of given type
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    /// @notice Check if module is initialized for a smart account
    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    /// @notice Validate signature with data
    /// @dev data should be abi.encoded(address expectedSigner)
    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override
        returns (bool)
    {
        if (data.length < 32) return false;

        address expectedSigner = abi.decode(data, (address));
        address recovered = ECDSA.tryRecover(hash, signature);
        return recovered == expectedSigner;
    }
}

/// @title MultiTypeModule
/// @notice Test module that implements multiple ERC-7780 types
/// @dev Demonstrates a module can be multiple types simultaneously
contract MultiTypeModule is IPolicy, ISigner, IERC7579Module {
    /// @dev Mapping of account to allowed status
    mapping(address => bool) public allowed;

    function onInstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            address account = abi.decode(data, (address));
            allowed[account] = true;
        }
    }

    function onUninstall(bytes calldata data) external override(IModule, IERC7579Module) {
        if (data.length > 0) {
            address account = abi.decode(data, (address));
            delete allowed[account];
        }
    }

    function isModuleType(uint256 moduleTypeId) external pure override(IModule, IERC7579Module) returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY || moduleTypeId == MODULE_TYPE_SIGNER;
    }

    /// @notice Check if module is initialized for a smart account
    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        return allowed[userOp.sender] ? 0 : 1;
    }

    function checkSignaturePolicy(bytes32, address sender, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        return allowed[sender] ? 0 : 1;
    }

    function checkUserOpSignature(bytes32, PackedUserOperation calldata userOp, bytes32)
        external
        payable
        override
        returns (uint256)
    {
        return allowed[userOp.sender] ? 0 : 1;
    }

    function checkSignature(bytes32, address sender, bytes32, bytes calldata) external view override returns (bytes4) {
        return allowed[sender] ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
