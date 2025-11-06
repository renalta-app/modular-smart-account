// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title ModularSmartAccountExecuteUserOpTest
contract ModularSmartAccountExecuteUserOpTest is ModularAccountTestBase {
    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);

    function setUp() public {}

    /// @notice Test that executeUserOp reverts with explicit error when callData is empty
    /// @dev Should revert with InvalidUserOpCallData as opposed to lower level hard revert
    function test_revertsWithExplicitErrorWhenCallDataEmpty() public {
        (ModularSmartAccount account,,) = setupAccount();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: hex"", // 0 bytes
            accountGasLimits: bytes32(uint256(100000) | (uint256(100000) << 128)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) | (uint256(1 gwei) << 128)),
            paymasterAndData: "",
            signature: ""
        });

        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSignature("InvalidUserOpCallData()"));
        account.executeUserOp(userOp, bytes32(0));
    }

    /// @notice Test with callData of exactly 3 bytes
    function test_revertsWithExplicitErrorWhenCallDataIs3Bytes() public {
        (ModularSmartAccount account,,) = setupAccount();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: hex"010203", // 3 bytes
            accountGasLimits: bytes32(uint256(100000) | (uint256(100000) << 128)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) | (uint256(1 gwei) << 128)),
            paymasterAndData: "",
            signature: ""
        });

        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSignature("InvalidUserOpCallData()"));
        account.executeUserOp(userOp, bytes32(0));
    }
}
