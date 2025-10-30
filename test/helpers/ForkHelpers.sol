// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkTestBase} from "./ForkTestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ForkHelpers
/// @notice Helper functions for fork testing with real modules and EntryPoint
/// @dev Extends ForkTestBase with utilities for UserOp creation, signing, and module interaction
abstract contract ForkHelpers is ForkTestBase {
    using MessageHashUtils for bytes32;

    // =============================================================================
    // STANDARD FORK TEST SETUP
    // =============================================================================

    /// @notice Standard setup for fork tests
    /// @dev Call this in your test's setUp() function for common fork test initialization
    /// @return factory The ModularSmartAccountFactory instance
    /// @return account The created ModularSmartAccount
    /// @return owner The owner address
    /// @return ownerKey The private key of the owner
    function setUpForkTest()
        internal
        returns (ModularSmartAccountFactory factory, ModularSmartAccount account, address owner, uint256 ownerKey)
    {
        setupFork();
        fund(address(this), 100 ether);
        verifyEssentialContracts();
        return setupForkAccount();
    }

    // =============================================================================
    // USEROPERATIONS
    // =============================================================================

    /// @notice Create a basic UserOperation
    function createUserOp(address sender, uint256 nonce, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2000000), uint128(2000000))),
            preVerificationGas: 100000,
            gasFees: bytes32(abi.encodePacked(uint128(1000000000), uint128(1000000000))),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @notice Create a UserOperation with factory deployment
    function createUserOpWithFactory(
        address sender,
        uint256 nonce,
        address factory,
        bytes memory factoryData,
        bytes memory callData
    ) internal pure returns (PackedUserOperation memory) {
        PackedUserOperation memory userOp = createUserOp(sender, nonce, callData);
        userOp.initCode = abi.encodePacked(factory, factoryData);
        return userOp;
    }

    /// @notice Get the hash that needs to be signed for a UserOperation
    /// @dev Uses EntryPoint v0.7/v0.8's getUserOpHash function for accurate hash
    function getUserOpHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        // EntryPoint v0.7+ has getUserOpHash but it's not in IEntryPoint
        // We need to encode to calldata format for the call
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Call EntryPoint's getUserOpHash via IEntryPointExtra interface
        return IEntryPointExtra(address(entryPoint)).getUserOpHash(ops[0]);
    }

    /// @notice Sign a UserOperation with a private key
    /// @dev Signs the raw userOp hash directly (ERC-4337 standard)
    /// @param useEthSign If true, wraps hash with toEthSignedMessageHash (for modules like OwnableValidator)
    function signUserOp(PackedUserOperation memory userOp, uint256 privateKey, bool useEthSign)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 hash = getUserOpHash(userOp);

        // Some modules (like Rhinestone's OwnableValidator) expect eth_sign format
        if (useEthSign) {
            hash = hash.toEthSignedMessageHash();
        }

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
    }

    /// @notice Sign a UserOperation with a private key (raw hash)
    /// @dev Convenience wrapper for standard ERC-4337 signing
    function signUserOp(PackedUserOperation memory userOp, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        return signUserOp(userOp, privateKey, false);
    }

    /// @notice Create and sign a UserOperation in one step
    /// @param useEthSign If true, uses eth_sign format (for modules like OwnableValidator)
    function createAndSignUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData,
        uint256 signerKey,
        bool useEthSign
    ) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory userOp = createUserOp(sender, nonce, callData);
        userOp.signature = signUserOp(userOp, signerKey, useEthSign);
        return userOp;
    }

    /// @notice Create and sign a UserOperation in one step (raw hash)
    /// @dev Convenience wrapper for standard ERC-4337 signing
    function createAndSignUserOp(address sender, uint256 nonce, bytes memory callData, uint256 signerKey)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return createAndSignUserOp(sender, nonce, callData, signerKey, false);
    }

    // =============================================================================
    // ENTRYPOINT INTERACTIONS
    // =============================================================================

    /// @notice Submit a single UserOperation to EntryPoint
    function submitUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(address(this)));
    }

    /// @notice Submit multiple UserOperations to EntryPoint
    function submitUserOps(PackedUserOperation[] memory ops) internal {
        entryPoint.handleOps(ops, payable(address(this)));
    }

    /// @notice Simulate a UserOperation without executing it
    /// @dev Useful for checking validation and estimating gas
    function simulateUserOp(PackedUserOperation memory userOp)
        internal
        returns (bool success, bytes memory returnData)
    {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        (success, returnData) = address(entryPoint)
            .call(abi.encodeWithSelector(entryPoint.handleOps.selector, ops, payable(address(this))));
    }

    /// @notice Get the deposit info for an account
    function getDeposit(address account) internal view returns (uint256) {
        return entryPoint.balanceOf(account);
    }

    /// @notice Deposit ETH for an account's gas
    function depositFor(address account, uint256 amount) internal {
        entryPoint.depositTo{value: amount}(account);
    }

    // =============================================================================
    // MODULE INSTALLATION HELPERS
    // =============================================================================

    /// @notice Encode installation data for OwnableValidator
    /// @dev OwnableValidator expects (uint256 threshold, address[] owners)
    function encodeOwnableValidatorInstall(address owner) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return abi.encode(1, owners); // threshold = 1, single owner
    }

    /// @notice Encode installation data for WebAuthnValidator
    /// @dev Simplified - actual implementation may require more parameters
    function encodeWebAuthnValidatorInstall(bytes memory publicKey) internal pure returns (bytes memory) {
        return abi.encode(publicKey);
    }

    /// @notice Encode installation data for SmartSessions
    function encodeSmartSessionsInstall(bytes memory sessionData) internal pure returns (bytes memory) {
        return sessionData;
    }

    // =============================================================================
    // REGISTRY INTERACTIONS
    // =============================================================================

    /// @notice Check if a module passes registry validation
    /// @dev Uses the registry's check function with provided attesters
    function checkModuleWithAttesters(address module, address[] memory attesters, uint256 threshold)
        internal
        view
        returns (bool)
    {
        try registry.check(module, attesters, threshold) {
            return true;
        } catch {
            return false;
        }
    }

    /// @notice Check if a module is valid using the basic check
    function checkModule(address module) internal view returns (bool) {
        try registry.check(module) {
            return true;
        } catch {
            return false;
        }
    }

    // =============================================================================
    // GAS MEASUREMENT
    // =============================================================================

    /// @notice Measure gas used by a UserOperation
    function measureUserOpGas(PackedUserOperation memory userOp) internal returns (uint256 gasUsed) {
        uint256 gasBefore = gasleft();
        submitUserOp(userOp);
        gasUsed = gasBefore - gasleft();
    }

    // =============================================================================
    // SNAPSHOT HELPERS
    // =============================================================================

    uint256 private snapshotId;

    /// @notice Take a snapshot of current state
    function takeSnapshot() internal returns (uint256) {
        snapshotId = vm.snapshot();
        return snapshotId;
    }

    /// @notice Revert to snapshot
    function revertToSnapshot(uint256 id) internal {
        vm.revertTo(id);
    }

    /// @notice Revert to last snapshot
    function revertToSnapshot() internal {
        require(snapshotId != 0, "No snapshot taken");
        vm.revertTo(snapshotId);
    }

    // =============================================================================
    // IMPERSONATION HELPERS
    // =============================================================================

    /// @notice Impersonate an address and execute a function
    function asAddress(address who, function() internal fn) internal {
        vm.startPrank(who);
        fn();
        vm.stopPrank();
    }
}
