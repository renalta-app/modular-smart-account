// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    TestPolicyModule,
    TestSignerModule,
    TestStatelessValidator,
    MultiTypeModule
} from "../helpers/modules/TestERC7780Modules.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR
} from "../../contracts/interfaces/IERC7780.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract ERC7780ModulesTest is ModularAccountTestBase {
    ModularSmartAccount public account;
    ModularSmartAccountFactory public factory;
    IEntryPoint public entryPoint;

    TestPolicyModule public policyModule;
    TestSignerModule public signerModule;
    TestStatelessValidator public statelessValidator;
    MultiTypeModule public multiTypeModule;

    address public owner;
    uint256 public ownerKey;
    address public authorizedSigner;
    uint256 public authorizedSignerKey;

    bytes32 public constant DEFAULT_ID = bytes32(0);

    function setUp() public {
        (owner, ownerKey) = createAccountOwner();
        (authorizedSigner, authorizedSignerKey) = createAccountOwner();

        entryPoint = IEntryPoint(ENTRYPOINT_V08);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(implementation));
        account = factory.createAccount(owner, 0);

        policyModule = new TestPolicyModule();
        signerModule = new TestSignerModule();
        statelessValidator = new TestStatelessValidator();
        multiTypeModule = new MultiTypeModule();

        vm.label(address(account), "Account");
        vm.label(owner, "Owner");
        vm.label(authorizedSigner, "AuthorizedSigner");
    }

    // -------------------------------------------------------------------------
    // Policy Module Tests
    // -------------------------------------------------------------------------

    function test_PolicyModule_Install() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID, uint256(100 gwei)));

        assertTrue(account.isModuleInstalled(MODULE_TYPE_POLICY, address(policyModule), ""));
        assertEq(policyModule.maxGasPrice(DEFAULT_ID), 100 gwei);
    }

    function test_PolicyModule_Uninstall() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID, uint256(100 gwei)));

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID));

        assertFalse(account.isModuleInstalled(MODULE_TYPE_POLICY, address(policyModule), ""));
        assertEq(policyModule.maxGasPrice(DEFAULT_ID), 0);
    }

    function test_PolicyModule_CheckUserOpPolicy_Pass() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID, uint256(100 gwei)));

        PackedUserOperation memory userOp = _createUserOpWithGasFees(50 gwei, 1 gwei);

        uint256 result = policyModule.checkUserOpPolicy(DEFAULT_ID, userOp);
        assertEq(result, 0, "Policy should pass");
    }

    function test_PolicyModule_CheckUserOpPolicy_Fail() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID, uint256(100 gwei)));

        // Create UserOp with 150 gwei gas price (exceeds limit)
        PackedUserOperation memory userOp = _createUserOpWithGasFees(150 gwei, 1 gwei);

        uint256 result = policyModule.checkUserOpPolicy(DEFAULT_ID, userOp);
        assertEq(result, 1, "Policy should fail");
    }

    // -------------------------------------------------------------------------
    // Signer Module Tests
    // -------------------------------------------------------------------------

    function test_SignerModule_Install() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));

        assertTrue(account.isModuleInstalled(MODULE_TYPE_SIGNER, address(signerModule), ""));
        assertEq(signerModule.authorizedSigner(DEFAULT_ID), authorizedSigner);
    }

    function test_SignerModule_Uninstall() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID));

        assertFalse(account.isModuleInstalled(MODULE_TYPE_SIGNER, address(signerModule), ""));
        assertEq(signerModule.authorizedSigner(DEFAULT_ID), address(0));
    }

    function test_SignerModule_CheckUserOpSignature_Valid() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));

        PackedUserOperation memory userOp = _createUserOpWithGasFees(50 gwei, 1 gwei);
        bytes32 userOpHash = keccak256(abi.encode(userOp));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        uint256 result = signerModule.checkUserOpSignature(DEFAULT_ID, userOp, userOpHash);
        assertEq(result, 0, "Signature should be valid");
    }

    function test_SignerModule_CheckUserOpSignature_Invalid() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));

        PackedUserOperation memory userOp = _createUserOpWithGasFees(50 gwei, 1 gwei);
        bytes32 userOpHash = keccak256(abi.encode(userOp));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash); // Wrong key
        userOp.signature = abi.encodePacked(r, s, v);

        uint256 result = signerModule.checkUserOpSignature(DEFAULT_ID, userOp, userOpHash);
        assertEq(result, 1, "Signature should be invalid");
    }

    function test_SignerModule_CheckSignature_Valid() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));

        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = signerModule.checkSignature(DEFAULT_ID, address(this), hash, signature);
        assertEq(result, IERC1271.isValidSignature.selector, "Signature should be valid");
    }

    // -------------------------------------------------------------------------
    // Stateless Validator Tests
    // -------------------------------------------------------------------------

    function test_StatelessValidator_ValidateSignatureWithData_Valid() public view {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encode(authorizedSigner);

        bool result = statelessValidator.validateSignatureWithData(hash, signature, data);
        assertTrue(result, "Signature should be valid");
    }

    function test_StatelessValidator_ValidateSignatureWithData_Invalid() public view {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encode(authorizedSigner); // Expects different signer

        bool result = statelessValidator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Signature should be invalid");
    }

    function test_StatelessValidator_IsModuleType() public view {
        assertTrue(statelessValidator.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
        assertFalse(statelessValidator.isModuleType(MODULE_TYPE_POLICY));
        assertFalse(statelessValidator.isModuleType(MODULE_TYPE_SIGNER));
    }

    // -------------------------------------------------------------------------
    // Multi-Type Module Tests
    // -------------------------------------------------------------------------

    function test_MultiTypeModule_IsMultipleTypes() public view {
        assertTrue(multiTypeModule.isModuleType(MODULE_TYPE_POLICY));
        assertTrue(multiTypeModule.isModuleType(MODULE_TYPE_SIGNER));
        assertFalse(multiTypeModule.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
    }

    function test_MultiTypeModule_AsPolicy() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(multiTypeModule), abi.encode(address(account)));

        assertTrue(account.isModuleInstalled(MODULE_TYPE_POLICY, address(multiTypeModule), ""));
        assertTrue(multiTypeModule.allowed(address(account)));
    }

    function test_MultiTypeModule_AsSigner() public {
        vm.prank(owner);
        account.installModule(MODULE_TYPE_SIGNER, address(multiTypeModule), abi.encode(address(account)));

        assertTrue(account.isModuleInstalled(MODULE_TYPE_SIGNER, address(multiTypeModule), ""));
        assertTrue(multiTypeModule.allowed(address(account)));
    }

    // -------------------------------------------------------------------------
    // Account Integration Tests
    // -------------------------------------------------------------------------

    function test_Account_SupportsERC7780ModuleTypes() public view {
        assertTrue(account.supportsModule(MODULE_TYPE_POLICY));
        assertTrue(account.supportsModule(MODULE_TYPE_SIGNER));
        assertTrue(account.supportsModule(MODULE_TYPE_STATELESS_VALIDATOR));
    }

    function test_Account_InstallMultipleERC7780Modules() public {
        vm.startPrank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policyModule), abi.encode(DEFAULT_ID, uint256(100 gwei)));
        account.installModule(MODULE_TYPE_SIGNER, address(signerModule), abi.encode(DEFAULT_ID, authorizedSigner));
        vm.stopPrank();

        assertTrue(account.isModuleInstalled(MODULE_TYPE_POLICY, address(policyModule), ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_SIGNER, address(signerModule), ""));
    }

    // -------------------------------------------------------------------------
    // Helper Functions
    // -------------------------------------------------------------------------

    function _createUserOpWithGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(uint256(150000) << 128 | uint256(150000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(maxFeePerGas) << 128 | uint256(maxPriorityFeePerGas)),
            paymasterAndData: "",
            signature: ""
        });
    }
}
