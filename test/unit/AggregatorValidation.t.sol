// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AggregatorValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";

/// @title AggregatorValidationTest
/// @notice Tests for ERC-4337 aggregator address handling
/// @dev Validates bug: (validationData & 1) != 0 incorrectly treats odd aggregators as SIG_VALIDATION_FAILED
contract AggregatorValidationTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    function setUp() public {
        chainId = block.chainid;
    }

    function _testAggregatorAddress(address aggregator) internal {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();
        AggregatorValidatorModule validator = new AggregatorValidatorModule();

        bytes memory initData = abi.encode(moduleSigner, aggregator);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        (address returnedAggregator,,) = ERC4337Utils.parseValidationData(validation);
        assertEq(returnedAggregator, aggregator, "Aggregator address should be preserved");
    }

    /// @notice Test that odd aggregator addresses are preserved
    /// @dev BUG: (validationData & 1) check treats odd addresses as SIG_VALIDATION_FAILED
    function test_preservesOddAggregator() public {
        _testAggregatorAddress(address(0x1234567890123456789012345678901234567891));
    }

    /// @notice Test that even aggregator addresses are preserved
    function test_preservesEvenAggregator() public {
        _testAggregatorAddress(address(0x1234567890123456789012345678901234567890));
    }

    /// @notice Test that address(1) means signature failure
    function test_rejectsAddress1AsFailed() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        (, uint256 wrongKey) = createAccountOwner();
        AggregatorValidatorModule validator = new AggregatorValidatorModule();

        bytes memory initData = abi.encode(moduleSigner, address(0x1234));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, wrongKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        (address returnedAggregator,,) = ERC4337Utils.parseValidationData(validation);
        assertEq(returnedAggregator, address(1), "Invalid signature returns address(1)");
    }
}
