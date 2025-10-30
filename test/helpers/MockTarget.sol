// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MockTarget
/// @notice Simple mock contract for testing arbitrary contract calls
/// @dev Used in SmartSession and other fork tests to verify contract interaction capabilities
contract MockTarget {
    uint256 public value;
    address public caller;
    bytes public data;

    event ValueSet(uint256 newValue, address indexed setter);
    event Called(address indexed caller, bytes data);

    function setValue(uint256 _value) external {
        value = _value;
        caller = msg.sender;
        emit ValueSet(_value, msg.sender);
    }

    function setValueWithData(uint256 _value, bytes calldata _data) external {
        value = _value;
        caller = msg.sender;
        data = _data;
        emit Called(msg.sender, _data);
        emit ValueSet(_value, msg.sender);
    }

    function getValue() external view returns (uint256) {
        return value;
    }

    function reset() external {
        value = 0;
        caller = address(0);
        data = "";
    }
}
