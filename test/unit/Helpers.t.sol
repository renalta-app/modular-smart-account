// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";
import {TestHelpers} from "../helpers/TestHelpers.sol";

/// @title HelpersTest
/// @notice Test suite for test utility helper functions
/// @dev Includes tests for UserOp helpers and ERC-4337 ValidationData packing/parsing
contract HelpersTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    // ValidationHelpers test state
    TestHelpers public validationHelpers;
    address constant ADDR_ZERO = address(0);
    address constant ADDR_1 = address(0x0000000000000000000000000000000000000001);
    address constant ADDR_9 = address(0x9999999999999999999999999999999999999999);
    uint48 constant MAX_UINT48 = type(uint48).max;

    function setUp() public {
        validationHelpers = new TestHelpers();
    }

    // ============================================
    // USEROP HELPERS TESTS
    // ============================================

    function test_packGasLimits() public pure {
        uint128 high = 100000;
        uint128 low = 200000;

        bytes32 packed = UserOpHelpers.packGasLimits(high, low);

        uint256 unpackedHigh = uint256(packed) >> 128;
        uint256 unpackedLow = uint256(uint128(uint256(packed)));

        assertEq(unpackedHigh, high, "High gas limit should match");
        assertEq(unpackedLow, low, "Low gas limit should match");
    }

    function test_getUserOpHash() public pure {
        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(0x1234), 1);

        address entryPoint = address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        uint256 chainId = 1;

        bytes32 hash = UserOpHelpers.getUserOpHash(userOp, entryPoint, chainId);

        assertTrue(hash != bytes32(0), "Hash should not be zero");
    }

    function test_signUserOp() public {
        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(0x1234), 1);

        (address signer, uint256 privateKey) = createAccountOwner();
        address entryPoint = address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        uint256 chainId = 1;

        userOp = UserOpHelpers.signUserOp(vm, userOp, privateKey, entryPoint, chainId);

        assertTrue(userOp.signature.length == 65, "Signature should be 65 bytes");

        bytes32 hash = UserOpHelpers.getUserOpHash(userOp, entryPoint, chainId);
        address recovered = recoverSigner(hash, userOp.signature);
        assertEq(recovered, signer, "Recovered signer should match");
    }

    function test_fillUserOpDefaults() public pure {
        UserOpHelpers.UserOperation memory userOp;
        userOp.sender = address(0x1234);
        userOp.nonce = 5;

        UserOpHelpers.UserOperation memory filled = UserOpHelpers.fillUserOpDefaults(userOp);

        assertEq(filled.sender, address(0x1234), "Sender should be preserved");
        assertEq(filled.nonce, 5, "Nonce should be preserved");
        assertEq(filled.verificationGasLimit, 150000, "Verification gas limit should be default");
        assertEq(filled.preVerificationGas, 21000, "Pre-verification gas should be default");
        assertEq(filled.maxPriorityFeePerGas, 1e9, "Max priority fee should be default");
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(hash, v, r, s);
    }

    // ============================================
    // VALIDATION DATA PACKING/PARSING TESTS
    // ============================================

    /// @notice Pack ValidationData struct into uint256
    /// @param aggregator The aggregator address
    /// @param validUntil The time until which the signature is valid
    /// @param validAfter The time after which the signature is valid
    /// @return The packed ValidationData as uint256
    function packValidationData(address aggregator, uint48 validUntil, uint48 validAfter)
        internal
        pure
        returns (uint256)
    {
        return uint256(uint160(aggregator)) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }

    function test_parseValidationData() public view {
        TestHelpers.ValidationData memory result0 = validationHelpers.parseValidationData(0);
        assertEq(result0.aggregator, ADDR_ZERO, "Aggregator should be zero");
        assertEq(result0.validAfter, 0, "ValidAfter should be 0");
        assertEq(result0.validUntil, MAX_UINT48, "ValidUntil should be max when 0");

        TestHelpers.ValidationData memory result1 = validationHelpers.parseValidationData(1);
        assertEq(result1.aggregator, ADDR_1, "Aggregator should be 0x1");
        assertEq(result1.validAfter, 0, "ValidAfter should be 0");
        assertEq(result1.validUntil, MAX_UINT48, "ValidUntil should be max");

        uint256 packed3 = packValidationData(ADDR_ZERO, 0, 10);
        TestHelpers.ValidationData memory result3 = validationHelpers.parseValidationData(packed3);
        assertEq(result3.aggregator, ADDR_ZERO, "Aggregator should be zero");
        assertEq(result3.validAfter, 10, "ValidAfter should be 10");
        assertEq(result3.validUntil, MAX_UINT48, "ValidUntil 0 should parse as max");

        uint256 packed4 = packValidationData(ADDR_ZERO, 10, 0);
        TestHelpers.ValidationData memory result4 = validationHelpers.parseValidationData(packed4);
        assertEq(result4.aggregator, ADDR_ZERO, "Aggregator should be zero");
        assertEq(result4.validAfter, 0, "ValidAfter should be 0");
        assertEq(result4.validUntil, 10, "ValidUntil should be 10");
    }

    function test_packValidationData() public view {
        uint256 result0 = validationHelpers.packValidationData(false, 0, 0);
        assertEq(result0, 0, "No failure with no time bounds should be 0");

        uint256 result1 = validationHelpers.packValidationData(true, 0, 0);
        assertEq(result1, 1, "Signature failed should set aggregator to 1");

        uint256 result2 = validationHelpers.packValidationData(true, 123, 456);
        uint256 expected = packValidationData(ADDR_1, 123, 456);
        assertEq(result2, expected, "Should pack with time bounds and signature failure");
    }

    function test_packValidationDataStruct() public view {
        TestHelpers.ValidationData memory data =
            TestHelpers.ValidationData({aggregator: ADDR_9, validUntil: 234, validAfter: 567});

        uint256 packed = validationHelpers.packValidationDataStruct(data);
        uint256 expected = packValidationData(ADDR_9, 234, 567);

        assertEq(packed, expected, "Packed data should match expected");
    }

    function test_packAndParse_roundTrip() public view {
        TestHelpers.ValidationData memory original =
            TestHelpers.ValidationData({aggregator: ADDR_9, validUntil: 1000, validAfter: 500});

        uint256 packed = validationHelpers.packValidationDataStruct(original);
        TestHelpers.ValidationData memory parsed = validationHelpers.parseValidationData(packed);

        assertEq(parsed.aggregator, original.aggregator, "Aggregator should survive round trip");
        assertEq(parsed.validUntil, original.validUntil, "ValidUntil should survive round trip");
        assertEq(parsed.validAfter, original.validAfter, "ValidAfter should survive round trip");
    }

    function testFuzz_packAndParseInverse(address aggregator, uint48 validUntil, uint48 validAfter) public view {
        uint48 expectedValidUntil = validUntil == 0 ? MAX_UINT48 : validUntil;

        TestHelpers.ValidationData memory original =
            TestHelpers.ValidationData({aggregator: aggregator, validUntil: validUntil, validAfter: validAfter});

        uint256 packed = validationHelpers.packValidationDataStruct(original);
        TestHelpers.ValidationData memory parsed = validationHelpers.parseValidationData(packed);

        assertEq(parsed.aggregator, original.aggregator, "Fuzz: aggregator mismatch");
        assertEq(parsed.validUntil, expectedValidUntil, "Fuzz: validUntil mismatch");
        assertEq(parsed.validAfter, original.validAfter, "Fuzz: validAfter mismatch");
    }

    function testFuzz_packValidationDataWithFlag(bool sigFailed, uint48 validUntil, uint48 validAfter) public view {
        uint256 packed = validationHelpers.packValidationData(sigFailed, validUntil, validAfter);
        TestHelpers.ValidationData memory parsed = validationHelpers.parseValidationData(packed);

        address expectedAggregator = sigFailed ? ADDR_1 : ADDR_ZERO;
        uint48 expectedValidUntil = validUntil == 0 ? MAX_UINT48 : validUntil;

        assertEq(parsed.aggregator, expectedAggregator, "Fuzz: aggregator should match sigFailed flag");
        assertEq(parsed.validUntil, expectedValidUntil, "Fuzz: validUntil should handle 0 as max");
        assertEq(parsed.validAfter, validAfter, "Fuzz: validAfter should match");
    }

    function test_maxValues() public view {
        TestHelpers.ValidationData memory data = TestHelpers.ValidationData({
            aggregator: address(type(uint160).max), validUntil: MAX_UINT48, validAfter: MAX_UINT48
        });

        uint256 packed = validationHelpers.packValidationDataStruct(data);
        TestHelpers.ValidationData memory parsed = validationHelpers.parseValidationData(packed);

        assertEq(parsed.aggregator, data.aggregator, "Max aggregator should survive packing");
        assertEq(parsed.validUntil, data.validUntil, "Max validUntil should survive packing");
        assertEq(parsed.validAfter, data.validAfter, "Max validAfter should survive packing");
    }
}
