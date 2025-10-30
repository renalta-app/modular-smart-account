// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract TestDelegateTarget {
    uint256 public stored;

    function setStored(uint256 value) external {
        stored = value;
    }

    function getNumber() external pure returns (uint256) {
        return 42;
    }
}
