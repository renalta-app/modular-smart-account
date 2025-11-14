// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AggregatorValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IPolicy, MODULE_TYPE_POLICY} from "../../contracts/interfaces/IERC7780.sol";

/// @title AggregatorWithPolicyTest
/// @notice Tests that aggregator addresses are preserved when policies add time bounds
/// @dev Validates bug: _intersectValidationData loses aggregator address when combining with policy
contract AggregatorWithPolicyTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    function setUp() public {
        chainId = block.chainid;
    }

    /// @notice Test that aggregator is preserved when policy adds time bounds
    /// @dev BUG: _intersectValidationData only returns time bounds, loses aggregator address
    function test_preservesAggregatorWhenPolicyAddsTimeBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();
        AggregatorValidatorModule validator = new AggregatorValidatorModule();

        // Install validator with aggregator address
        address aggregator = address(0x1234567890123456789012345678901234567890);
        bytes memory initData = abi.encode(moduleSigner, aggregator);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        // Install time-bounded policy
        TimeBoundedPolicy policy = new TimeBoundedPolicy();
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes memory policyData = abi.encode(validAfter, validUntil);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policy), policyData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        // Should preserve BOTH aggregator AND time bounds
        (address returnedAggregator, uint48 returnedAfter, uint48 returnedUntil) =
            ERC4337Utils.parseValidationData(validation);

        assertEq(returnedAggregator, aggregator, "Aggregator should be preserved from validator");
        assertEq(returnedAfter, validAfter, "validAfter should come from policy");
        assertEq(returnedUntil, validUntil, "validUntil should come from policy");
    }

    /// @notice Test that odd aggregator is preserved when policy adds time bounds
    function test_preservesOddAggregatorWhenPolicyAddsTimeBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();
        AggregatorValidatorModule validator = new AggregatorValidatorModule();

        // Odd aggregator address
        address aggregator = address(0x1234567890123456789012345678901234567891);
        bytes memory initData = abi.encode(moduleSigner, aggregator);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        TimeBoundedPolicy policy = new TimeBoundedPolicy();
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes memory policyData = abi.encode(validAfter, validUntil);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policy), policyData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        (address returnedAggregator, uint48 returnedAfter, uint48 returnedUntil) =
            ERC4337Utils.parseValidationData(validation);

        assertEq(returnedAggregator, aggregator, "Odd aggregator should be preserved");
        assertEq(returnedAfter, validAfter, "validAfter should come from policy");
        assertEq(returnedUntil, validUntil, "validUntil should come from policy");
    }
}

/// @dev Time-bounded policy module for testing
contract TimeBoundedPolicy is IPolicy {
    error AlreadyInstalled(address account);
    error NotInstalled(address account);

    struct Config {
        bool installed;
        uint48 validAfter;
        uint48 validUntil;
    }

    mapping(address => Config) private configs;

    function onInstall(bytes calldata data) external {
        Config storage cfg = configs[msg.sender];
        if (cfg.installed) revert AlreadyInstalled(msg.sender);
        (uint48 validAfter, uint48 validUntil) = abi.decode(data, (uint48, uint48));
        cfg.validAfter = validAfter;
        cfg.validUntil = validUntil;
        cfg.installed = true;
    }

    function onUninstall(bytes calldata) external {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        delete configs[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable returns (uint256) {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        // Return time bounds as validation data (aggregator = 0, meaning success)
        return ERC4337Utils.packValidationData(address(0), cfg.validAfter, cfg.validUntil);
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external view returns (uint256) {
        Config storage cfg = configs[msg.sender];
        if (!cfg.installed) revert NotInstalled(msg.sender);
        return ERC4337Utils.packValidationData(address(0), cfg.validAfter, cfg.validUntil);
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }
}
