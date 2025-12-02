// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

interface IModularExecute {
    function execute(
        bytes32 mode,
        bytes calldata executionCalldata
    ) external payable;
}

contract DummySignatureTest is Test {
    ModularSmartAccountFactory factory;
    ModularSmartAccount account;
    IEntryPoint entryPoint;
    address owner;
    uint256 ownerKey;

    // The dummy signature from permissionless.js tests
    bytes constant DUMMY_SIG =
        hex"fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";

    function setUp() public {
        entryPoint = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);

        ModularSmartAccount impl = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(impl));

        (owner, ownerKey) = makeAddrAndKey("owner");
        account = ModularSmartAccount(payable(factory.createAccount(owner, 0)));
        vm.deal(address(account), 10 ether);
    }

    function test_validateUserOpWithDummySignature_gas_estimation_scenario()
        public
    {
        // This test simulates what happens during bundler gas estimation
        // The key difference: gas limits are all 0, and it should NOT revert

        bytes memory executionCalldata = abi.encodePacked(
            address(0), // to
            uint256(0), // value
            bytes("") // data
        );

        bytes32 mode = bytes32(LibERC7579.CALLTYPE_SINGLE);
        bytes memory callData = abi.encodeCall(
            IModularExecute.execute,
            (mode, executionCalldata)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "", // No init code - account already deployed
            callData: callData,
            accountGasLimits: bytes32(0), // 0 gas limits - estimation scenario
            preVerificationGas: 0,
            gasFees: bytes32(
                abi.encodePacked(uint128(1 gwei), uint128(1 gwei))
            ),
            paymasterAndData: "",
            signature: DUMMY_SIG
        });

        bytes32 userOpHash = keccak256("test_hash");

        // Simulate EntryPoint calling validateUserOp
        vm.prank(address(entryPoint));

        // This should NOT revert - it should return validation data
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1, "Should return SIG_VALIDATION_FAILED (1)");
    }

    function test_validateUserOpWithDummySignature_initCode_scenario() public {
        // This test simulates what happens when account needs to be deployed
        // (initCode provided, account doesn't exist yet)

        address newOwner = makeAddr("newOwner");

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeCall(factory.createAccount, (newOwner, 1))
        );

        // Calculate counterfactual address
        address counterfactualAccount = factory.getAddress(newOwner, 1);

        bytes memory executionCalldata = abi.encodePacked(
            address(0), // to
            uint256(0), // value
            bytes("") // data
        );

        bytes32 mode = bytes32(LibERC7579.CALLTYPE_SINGLE);
        bytes memory callData = abi.encodeCall(
            IModularExecute.execute,
            (mode, executionCalldata)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: counterfactualAccount,
            nonce: 0,
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(
                abi.encodePacked(uint128(1 gwei), uint128(1 gwei))
            ),
            paymasterAndData: "",
            signature: DUMMY_SIG
        });

        bytes32 userOpHash = keccak256("test_hash");

        // First deploy the account (simulate EntryPoint behavior)
        factory.createAccount(newOwner, 1);

        // Then validate
        vm.prank(address(entryPoint));
        uint256 validationData = ModularSmartAccount(
            payable(counterfactualAccount)
        ).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1, "Should return SIG_VALIDATION_FAILED (1)");
    }
}
