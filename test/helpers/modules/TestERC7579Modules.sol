// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";

import {
    IERC7579Module,
    IERC7579Validator,
    IERC7579Hook,
    IERC7579Execution,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @dev Simple validator module for testing. It trusts a single EOA per account
contract TestValidatorModule is IERC7579Validator {
    using ECDSA for bytes32;

    error AlreadyInstalled(address account);
    error NotInstalled(address account);
    error InvalidOwner();

    struct Config {
        address owner;
        bool installed;
    }

    mapping(address => Config) private configs;

    function onInstall(bytes calldata data) external override {
        Config storage cfg = configs[msg.sender];
        if (cfg.installed) revert AlreadyInstalled(msg.sender);
        address owner = abi.decode(data, (address));
        if (owner == address(0)) revert InvalidOwner();
        cfg.owner = owner;
        cfg.installed = true;
    }

    function onUninstall(bytes calldata) external override {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        delete configs[msg.sender];
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
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        address signer = ECDSA.recover(userOpHash, userOp.signature);
        return signer == cfg.owner ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) {
            return 0xffffffff;
        }
        address signer = ECDSA.recover(hash, signature);
        return signer == cfg.owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}

contract TestExecutorModule is IERC7579Module {
    error AlreadyInstalled(address account);
    error NotInstalled(address account);

    mapping(address => bool) private installed;

    event ExecutorCalled(address indexed account, bytes32 mode, bytes executionCalldata);

    function onInstall(bytes calldata) external override {
        if (installed[msg.sender]) revert AlreadyInstalled(msg.sender);
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external override {
        if (!installed[msg.sender]) revert NotInstalled(msg.sender);
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function proxyExecute(IERC7579Execution account, bytes32 mode, bytes calldata executionCalldata)
        external
        returns (bytes[] memory results)
    {
        emit ExecutorCalled(address(account), mode, executionCalldata);
        results = account.executeFromExecutor(mode, executionCalldata);
    }
}

contract TestHookModule is IERC7579Hook {
    event HookPre(address indexed account, address indexed caller, uint256 value, bytes data, uint256 counter);
    event HookPost(address indexed account, bytes hookData, uint256 counter);

    mapping(address => uint256) public hookCount;

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata msgData)
        external
        override
        returns (bytes memory)
    {
        uint256 count = ++hookCount[msg.sender];
        emit HookPre(msg.sender, msgSender, value, msgData, count);
        return abi.encode(count);
    }

    function postCheck(bytes calldata hookData) external override {
        uint256 count = hookCount[msg.sender];
        emit HookPost(msg.sender, hookData, count);
    }
}

/// @dev Buggy hook that always reverts - for testing hook failure resilience
contract RevertingHookModule is IERC7579Hook {
    error HookPreCheckAlwaysFails();
    error HookPostCheckAlwaysFails();

    bool public revertOnPreCheck;
    bool public revertOnPostCheck;

    constructor(bool _revertOnPre, bool _revertOnPost) {
        revertOnPreCheck = _revertOnPre;
        revertOnPostCheck = _revertOnPost;
    }

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address, uint256, bytes calldata) external view override returns (bytes memory) {
        if (revertOnPreCheck) {
            revert HookPreCheckAlwaysFails();
        }
        return "";
    }

    function postCheck(bytes calldata) external view override {
        if (revertOnPostCheck) {
            revert HookPostCheckAlwaysFails();
        }
    }
}

contract TestFallbackModule is IERC7579Module {
    event FallbackHandled(address indexed account, address indexed caller, bytes data, uint256 value);

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    receive() external payable {
        emit FallbackHandled(address(this), msg.sender, "", msg.value);
    }

    fallback() external payable {
        // ERC-2771: Extract original sender from end of calldata
        address originalSender = msg.sender;
        if (msg.data.length >= 20) {
            assembly {
                originalSender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        }
        emit FallbackHandled(address(this), originalSender, msg.data, msg.value);
    }
}

/// @dev Test fallback module that handles a specific custom function for testing multi-fallback routing.
///      This module returns a fixed string when called with customFunction()
contract TestCustomFunctionModule is IERC7579Module {
    event CustomFunctionCalled(address indexed caller);

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    function customFunction() external returns (string memory) {
        address originalSender = msg.sender;
        if (msg.data.length >= 24) {
            assembly {
                originalSender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        }
        emit CustomFunctionCalled(originalSender);
        return "custom function executed";
    }
}

/// @dev Test fallback module that handles another custom function for testing multi-fallback routing
contract TestAnotherFunctionModule is IERC7579Module {
    event AnotherFunctionCalled(address indexed caller, uint256 value);

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    function anotherFunction(uint256 value) external returns (uint256) {
        address originalSender = msg.sender;
        if (msg.data.length >= 20) {
            assembly {
                originalSender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        }
        emit AnotherFunctionCalled(originalSender, value);
        return value * 2;
    }
}

/// @dev Time-bounded validator module for testing time-ranged signatures.
///      Returns validation data with validAfter and validUntil timestamps
contract TimeBoundedValidatorModule is IERC7579Validator {
    using ECDSA for bytes32;

    error AlreadyInstalled(address account);
    error NotInstalled(address account);
    error InvalidOwner();

    struct Config {
        address owner;
        bool installed;
        uint48 validAfter;
        uint48 validUntil;
    }

    mapping(address => Config) private configs;

    function onInstall(bytes calldata data) external override {
        Config storage cfg = configs[msg.sender];
        if (cfg.installed) revert AlreadyInstalled(msg.sender);
        (address owner, uint48 validAfter, uint48 validUntil) = abi.decode(data, (address, uint48, uint48));
        if (owner == address(0)) revert InvalidOwner();
        cfg.owner = owner;
        cfg.validAfter = validAfter;
        cfg.validUntil = validUntil;
        cfg.installed = true;
    }

    function onUninstall(bytes calldata) external override {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        delete configs[msg.sender];
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
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        address signer = ECDSA.recover(userOpHash, userOp.signature);
        bool sigValid = signer == cfg.owner;

        // Return packed validation data with time bounds
        return ERC4337Utils.packValidationData(sigValid, cfg.validAfter, cfg.validUntil);
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) {
            return 0xffffffff;
        }
        address signer = ECDSA.recover(hash, signature);
        return signer == cfg.owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}

/// @dev Validator module that returns an aggregator address in validation data
///      Used to test proper handling of ERC-4337 aggregator addresses (odd and even)
contract AggregatorValidatorModule is IERC7579Validator {
    using ECDSA for bytes32;

    error AlreadyInstalled(address account);
    error NotInstalled(address account);
    error InvalidOwner();

    struct Config {
        address owner;
        bool installed;
        address aggregator;
    }

    mapping(address => Config) private configs;

    function onInstall(bytes calldata data) external override {
        Config storage cfg = configs[msg.sender];
        if (cfg.installed) revert AlreadyInstalled(msg.sender);
        (address owner, address aggregator) = abi.decode(data, (address, address));
        if (owner == address(0)) revert InvalidOwner();
        cfg.owner = owner;
        cfg.aggregator = aggregator;
        cfg.installed = true;
    }

    function onUninstall(bytes calldata) external override {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        delete configs[msg.sender];
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
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        address signer = ECDSA.recover(userOpHash, userOp.signature);
        bool sigValid = signer == cfg.owner;

        // Return validation data with aggregator address
        // If signature is valid, return aggregator; otherwise return SIG_VALIDATION_FAILED
        return ERC4337Utils.packValidationData(
            sigValid ? cfg.aggregator : address(uint160(ERC4337Utils.SIG_VALIDATION_FAILED)),
            0,
            0
        );
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) {
            return 0xffffffff;
        }
        address signer = ECDSA.recover(hash, signature);
        return signer == cfg.owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
