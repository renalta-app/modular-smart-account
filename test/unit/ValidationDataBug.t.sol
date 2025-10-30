// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {TimeBoundedValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MockERC1271Wallet} from "../mocks/MockERC1271Wallet.sol";

/// @title ValidationDataBugTest
/// @notice Tests to demonstrate and fix validation data handling bugs
/// @dev These tests validate proper handling of:
///      - Time-bounded validation data (validAfter/validUntil)
///      - Signature validation with non-zero validation data
///      - Contract owner ERC-1271 support
contract ValidationDataBugTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    function setUp() public {
        chainId = block.chainid;
    }

    // ============================================
    // TIME-BOUNDED VALIDATION DATA TESTS
    // ============================================
    // These tests verify proper handling of validation data with time bounds (validAfter/validUntil).
    // The account must correctly preserve and return time-bounded validation data while
    // checking bit-0 for signature validity.

    /// @notice Test that time-bounded validators return proper validation data
    /// A time-bounded validator returns non-zero validation data with bit-0=0 (valid)
    /// The account must correctly preserve the time bounds in the returned validation data
    /// while ensuring the signature is cryptographically valid (bit-0=0).
    /// This test validates that time-bounded signatures ARE accepted when valid.
    function test_acceptsTimeBoundedValidSignature() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();
        TimeBoundedValidatorModule validator = new TimeBoundedValidatorModule();

        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        bytes memory initData = abi.encode(moduleSigner, validAfter, validUntil);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        // Validation should succeed (bit-0 = 0)
        assertEq(validation & 1, 0, "Signature should be valid (bit-0 = 0)");

        // Validation should be non-zero (contains time bounds)
        assertTrue(validation != 0, "Validation data should contain time bounds");

        // Decode and verify time bounds are preserved
        (address aggregator, uint48 returnedAfter, uint48 returnedUntil) = ERC4337Utils.parseValidationData(validation);
        assertEq(aggregator, address(0), "Aggregator should be address(0) for success");
        assertEq(returnedAfter, validAfter, "validAfter should be preserved");
        assertEq(returnedUntil, validUntil, "validUntil should be preserved");
    }

    /// @notice Test that account returns valid crypto signature with time bounds for expired signatures
    /// The account returns time-bounded validation data with bit-0=0 (cryptographically valid).
    /// The EntryPoint is responsible for checking if the time bounds are satisfied.
    /// This test verifies the account correctly returns validation data even when timestamp is expired.
    function test_returnsValidCryptoSignatureWithExpiredTimeBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();
        TimeBoundedValidatorModule validator = new TimeBoundedValidatorModule();

        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        bytes memory initData = abi.encode(moduleSigner, validAfter, validUntil);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        vm.warp(block.timestamp + 2 hours);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        // The EntryPoint checks time bounds, not the account.
        // The account returns validation data with bit-0=0 (signature is cryptographically valid)
        // and includes the time bounds for the EntryPoint to verify.
        assertEq(validation & 1, 0, "Signature is cryptographically valid (bit-0 = 0)");

        // Verify time bounds are expired (EntryPoint would reject this)
        (,, uint48 returnedUntil) = ERC4337Utils.parseValidationData(validation);
        assertTrue(block.timestamp > returnedUntil, "Current time should be after validUntil");
    }

    /// @notice Test that invalid signatures are correctly identified with bit-0=1 in validation data
    /// Verifies that when a time-bounded validator receives an invalid signature,
    /// it returns validation data with bit-0=1 (invalid), even if time bounds are present.
    function test_correctlyIdentifiesInvalidSignatureWithTimeBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        (, uint256 wrongKey) = createAccountOwner(); // Wrong signer
        TimeBoundedValidatorModule validator = new TimeBoundedValidatorModule();

        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        bytes memory initData = abi.encode(moduleSigner, validAfter, validUntil);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.getDefaultUserOp();
        userOp.sender = address(account);
        userOp.nonce = 0;
        userOp.callGasLimit = 100000;
        userOp.verificationGasLimit = 100000;
        userOp = UserOpHelpers.signUserOp(vm, userOp, wrongKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        // Should have bit-0 = 1 (invalid signature)
        assertEq(validation & 1, 1, "Invalid signature should have bit-0 = 1");
    }

    // ============================================
    // CONTRACT OWNER ERC-1271 SUPPORT TESTS
    // ============================================
    // These tests verify that the account supports contract owners (smart contract wallets)
    // that implement ERC-1271 signature validation, not just EOA owners.

    /// @notice Test that contract owners can validate signatures via ERC-1271
    /// Verifies the account supports contract owners that implement IERC1271,
    /// not just EOA owners with ECDSA signatures.
    function test_supportsContractOwnerERC1271Validation() public {
        (address walletSigner, uint256 walletSignerKey) = createAccountOwner();
        MockERC1271Wallet contractWallet = new MockERC1271Wallet(walletSigner);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        bytes memory initData = abi.encodeWithSignature("initialize(address)", address(contractWallet));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        ModularSmartAccount account = ModularSmartAccount(payable(address(proxy)));

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.getDefaultUserOp();
        userOp.sender = address(account);
        userOp.nonce = 0;
        userOp.callGasLimit = 100000;
        userOp.verificationGasLimit = 200000;
        userOp = UserOpHelpers.signUserOp(vm, userOp, walletSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_SUCCESS, "Contract owner signature should be valid");

        bytes4 result = account.isValidSignature(userOpHash, userOp.signature);
        assertEq(result, IERC1271.isValidSignature.selector, "Contract owner should pass ERC-1271");
    }
}
