// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.30;

import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";

/// @title TestHelpers
/// @notice Wrapper contract for testing ERC4337Utils validation data packing/parsing
contract TestHelpers {
    /// @notice Validation data struct for compatibility with existing tests
    struct ValidationData {
        address aggregator;
        uint48 validAfter;
        uint48 validUntil;
    }

    function parseValidationData(uint256 validationData) public pure returns (ValidationData memory) {
        (address aggregator, uint48 validAfter, uint48 validUntil) = ERC4337Utils.parseValidationData(validationData);
        return ValidationData({aggregator: aggregator, validAfter: validAfter, validUntil: validUntil});
    }

    function packValidationDataStruct(ValidationData memory data) public pure returns (uint256) {
        return ERC4337Utils.packValidationData(data.aggregator, data.validAfter, data.validUntil);
    }

    function packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) public pure returns (uint256) {
        return ERC4337Utils.packValidationData(!sigFailed, validAfter, validUntil);
    }
}
