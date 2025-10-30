// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.30;

// Sample "receiver" contract, for testing "exec" from account.
contract TestCounter {
    mapping(address => uint256) public counters;

    function count() public {
        counters[msg.sender] = counters[msg.sender] + 1;
    }

    function countFail() public pure {
        revert("count failed");
    }

    function increment() public {
        counters[msg.sender]++;
    }

    function decrementWithRevert() public pure {
        revert("decrement always fails");
    }

    function justemit() public {
        emit CalledFrom(msg.sender);
    }

    event CalledFrom(address sender);

    mapping(uint256 => uint256) public xxx;
    uint256 public offset;

    function gasWaster(
        uint256 repeat,
        string calldata /*junk*/
    )
        external
    {
        for (uint256 i = 1; i <= repeat; i++) {
            offset++;
            xxx[offset] = i;
        }
    }
}
