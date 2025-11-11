// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IPolicy} from "../../contracts/interfaces/IERC7780.sol";
import {IERC7579Validator} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MODULE_TYPE_POLICY} from "../../contracts/interfaces/IERC7780.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title ValidationDataIntersectionTest
/// @notice Tests for H-02: Validation Data Not Properly Intersected
/// @dev Tests the intersection of time bounds from validators and policies
contract ValidationDataIntersectionTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    TimeBoundedValidator public validator;
    TimeBoundedPolicy public policy;

    function setUp() public {
        chainId = block.chainid;
        validator = new TimeBoundedValidator();
        policy = new TimeBoundedPolicy();
    }

    /// @notice Test where validator has narrower window than policy
    /// @dev Validator: 1200-1800, Policy: 1000-2000, Expected: 1200-1800 (intersection)
    function test_validationDataIntersection_ValidatorHasNarrowerWindow() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address signer, uint256 signerKey) = createAccountOwner();

        bytes memory validatorInitData = abi.encode(signer, uint48(1200), uint48(1800));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);

        bytes memory policyInitData = abi.encode(bytes32(0), uint48(1000), uint48(2000));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policy), policyInitData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, signerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(packed, userOpHash, 0);

        // casting to 'uint48' is safe because we're extracting a 48-bit field from validationData
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 actualValidAfter = uint48(validationData >> 208);
        uint48 actualValidUntil = uint48((validationData >> 160) & 0xFFFFFFFFFFFF);

        assertEq(actualValidAfter, 1200, "validAfter should be max(1200, 1000)");
        assertEq(actualValidUntil, 1800, "validUntil should be min(1800, 2000)");
    }

    /// @notice Test where policy has narrower window than validator
    /// @dev Validator: 1000-2000, Policy: 1200-1800, Expected: 1200-1800 (intersection)
    function test_validationDataIntersection_BothHaveTimeBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address signer, uint256 signerKey) = createAccountOwner();

        bytes memory validatorInitData = abi.encode(signer, uint48(1000), uint48(2000));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);

        bytes memory policyInitData = abi.encode(bytes32(0), uint48(1200), uint48(1800));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(policy), policyInitData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, signerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(packed, userOpHash, 0);

        // casting to 'uint48' is safe because we're extracting a 48-bit field from validationData
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 actualValidAfter = uint48(validationData >> 208);
        uint48 actualValidUntil = uint48((validationData >> 160) & 0xFFFFFFFFFFFF);

        assertEq(actualValidAfter, 1200, "validAfter should be max(1000, 1200)");
        assertEq(actualValidUntil, 1800, "validUntil should be min(2000, 1800)");
    }

    /// @notice Test edge case: validator has time bounds, policy returns 0 (success, no bounds)
    function test_validationDataIntersection_OnlyValidatorHasBounds() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address signer, uint256 signerKey) = createAccountOwner();

        // Validator: valid from 1000 to 2000
        bytes memory validatorInitData = abi.encode(signer, uint48(1000), uint48(2000));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);

        // Policy: returns 0 (no time bounds, just success)
        SimplePolicyModule simplePolicy = new SimplePolicyModule();
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(simplePolicy), "");

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, signerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(packed, userOpHash, 0);

        // Expected: Validator's time bounds should be preserved
        // casting to 'uint48' is safe because we're extracting a 48-bit field from validationData
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 actualValidAfter = uint48(validationData >> 208);
        uint48 actualValidUntil = uint48((validationData >> 160) & 0xFFFFFFFFFFFF);

        assertEq(actualValidAfter, 1000, "validAfter should be preserved from validator");
        assertEq(actualValidUntil, 2000, "validUntil should be preserved from validator");
    }

    /// @notice Test edge case: policy fails (returns 1), should return failure immediately
    function test_validationDataIntersection_PolicyFails() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address signer, uint256 signerKey) = createAccountOwner();

        // Validator: valid from 1000 to 2000
        bytes memory validatorInitData = abi.encode(signer, uint48(1000), uint48(2000));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);

        // Policy: always fails (returns 1)
        RejectingPolicyModule rejectingPolicy = new RejectingPolicyModule();
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(rejectingPolicy), "");

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, signerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(packed, userOpHash, 0);

        // Should fail with authorizer = 1 (failure)
        assertEq(validationData & 1, 1, "Should fail when policy rejects");
    }

    /// @notice Test ERC-4337 compliance: policy checks must execute even with invalid signature
    /// @dev Ensures accurate gas estimation per ERC-4337 spec (no early return on SIG_VALIDATION_FAILED)
    function test_erc4337Compliance_PolicyExecutesWithInvalidSignature() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address signer, uint256 signerKey) = createAccountOwner();

        bytes memory validatorInitData = abi.encode(signer, uint48(0), uint48(0));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);

        CallCountingPolicy countingPolicy = new CallCountingPolicy();
        vm.prank(owner);
        account.installModule(MODULE_TYPE_POLICY, address(countingPolicy), "");

        // Invalid signature (wrong signer)
        (, uint256 wrongKey) = createAccountOwner();
        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, wrongKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(packed, userOpHash, 0);

        assertEq(validationData & 1, 1, "Signature validation should fail");
        assertEq(countingPolicy.callCount(address(account)), 1, "Policy must execute despite invalid signature");
    }
}

// ============================================
// MOCK MODULES FOR TESTING
// ============================================

/// @notice Tracks policy execution count for gas estimation testing
contract CallCountingPolicy is IPolicy {
    mapping(address => uint256) public callCount;

    function onInstall(bytes calldata) external override {}
    function onUninstall(bytes calldata) external override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        callCount[userOp.sender]++;
        return 0;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}

/// @notice Validator that returns time-bounded validation data
contract TimeBoundedValidator is IERC7579Validator {
    mapping(address => address) public authorizedSigner;
    mapping(address => uint48) public validAfter;
    mapping(address => uint48) public validUntil;

    function onInstall(bytes calldata data) external override {
        (address signer, uint48 _validAfter, uint48 _validUntil) = abi.decode(data, (address, uint48, uint48));
        authorizedSigner[msg.sender] = signer;
        validAfter[msg.sender] = _validAfter;
        validUntil[msg.sender] = _validUntil;
    }

    function onUninstall(bytes calldata) external override {
        delete authorizedSigner[msg.sender];
        delete validAfter[msg.sender];
        delete validUntil[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        address account = userOp.sender;
        address signer = authorizedSigner[account];

        if (signer == address(0)) return 1; // Not configured

        address recovered = ECDSA.tryRecover(userOpHash, userOp.signature);
        if (recovered != signer) return 1; // Signature invalid

        // Pack time bounds into validationData
        // Format: authorizer (0=valid) | validUntil | validAfter
        uint256 validationData = 0; // authorizer = 0 (valid)
        validationData |= uint256(validUntil[account]) << 160;
        validationData |= uint256(validAfter[account]) << 208;

        return validationData;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0x1626ba7e; // ERC-1271 magic value
    }
}

/// @notice Policy that returns time-bounded validation data
contract TimeBoundedPolicy is IPolicy {
    mapping(bytes32 => mapping(address => uint48)) public validAfter;
    mapping(bytes32 => mapping(address => uint48)) public validUntil;

    function onInstall(bytes calldata data) external override {
        (bytes32 id, uint48 _validAfter, uint48 _validUntil) = abi.decode(data, (bytes32, uint48, uint48));
        validAfter[id][msg.sender] = _validAfter;
        validUntil[id][msg.sender] = _validUntil;
    }

    function onUninstall(bytes calldata data) external override {
        bytes32 id = abi.decode(data, (bytes32));
        delete validAfter[id][msg.sender];
        delete validUntil[id][msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        address account = userOp.sender;

        // Pack time bounds into validationData
        uint256 validationData = 0; // authorizer = 0 (valid)
        validationData |= uint256(validUntil[id][account]) << 160;
        validationData |= uint256(validAfter[id][account]) << 208;

        return validationData;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}

/// @notice Simple policy that always returns 0 (success, no time bounds)
contract SimplePolicyModule is IPolicy {
    function onInstall(bytes calldata) external override {}
    function onUninstall(bytes calldata) external override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable override returns (uint256) {
        return 0; // Always succeed, no time bounds
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}

/// @notice Policy that always fails (returns 1)
contract RejectingPolicyModule is IPolicy {
    function onInstall(bytes calldata) external override {}
    function onUninstall(bytes calldata) external override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable override returns (uint256) {
        return 1; // Always fail
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 1;
    }
}
