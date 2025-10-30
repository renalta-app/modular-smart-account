// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title MockERC1271Wallet
/// @notice Mock ERC-1271 wallet for testing contract owner validation
/// @dev This contract validates signatures by checking if they were signed by a specific signer address
contract MockERC1271Wallet is IERC1271 {
    using ECDSA for bytes32;

    address public immutable SIGNER;

    constructor(address _signer) {
        SIGNER = _signer;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        address recovered = hash.recover(signature);
        if (recovered == SIGNER) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}
