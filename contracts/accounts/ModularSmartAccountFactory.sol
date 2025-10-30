// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "./ModularSmartAccount.sol";

/// @title ModularSmartAccountFactory
/// @notice Factory contract for deploying ModularSmartAccount instances via CREATE2
/// @dev Creates deterministic account addresses with ERC-1967 proxy pattern.
///      Compatible with ERC-4337 EntryPoint's account creation flow
contract ModularSmartAccountFactory {
    /// @notice The implementation contract for all deployed accounts
    ModularSmartAccount public immutable ACCOUNT_IMPLEMENTATION;

    /// @notice Emitted when a new account is created
    /// @param account The address of the newly created account
    /// @param owner The owner address of the account
    /// @param salt The CREATE2 salt used for deployment
    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    /// @notice Deploys the account implementation
    /// @param _entryPoint The ERC-4337 EntryPoint contract
    constructor(IEntryPoint _entryPoint) {
        ACCOUNT_IMPLEMENTATION = new ModularSmartAccount(_entryPoint);
    }

    /// @notice Create an account and return its address
    /// @dev Returns the address even if the account is already deployed.
    ///      This allows entryPoint.getSenderAddress() to work before/after creation.
    /// @param owner The owner address for the new account
    /// @param salt CREATE2 salt for deterministic deployment
    /// @return ret The ModularSmartAccount instance (whether existing or newly created)
    function createAccount(address owner, uint256 salt) public returns (ModularSmartAccount ret) {
        address addr = getAddress(owner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return ModularSmartAccount(payable(addr));
        }

        bytes memory initData = abi.encodeWithSignature("initialize(address)", owner);
        ret = ModularSmartAccount(
            payable(new ERC1967Proxy{salt: bytes32(salt)}(address(ACCOUNT_IMPLEMENTATION), initData))
        );
        emit AccountCreated(address(ret), owner, salt);
    }

    /// @notice Calculate the counterfactual address of an account
    /// @dev Computes the address as it would be returned by createAccount()
    /// @param owner The owner address for the account
    /// @param salt CREATE2 salt
    /// @return The deterministic address for the account
    function getAddress(address owner, uint256 salt) public view returns (address) {
        bytes memory initData = abi.encodeWithSignature("initialize(address)", owner);
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(ACCOUNT_IMPLEMENTATION), initData))
            )
        );
    }

    /// @notice Compute initCode for account creation via EntryPoint
    /// @dev Helper for off-chain clients to construct UserOp.initCode
    /// @param owner The owner address for the new account
    /// @param salt CREATE2 salt
    /// @return initCode The bytes to use in UserOperation.initCode
    function getInitCode(address owner, uint256 salt) external view returns (bytes memory) {
        return abi.encodePacked(address(this), abi.encodeCall(this.createAccount, (owner, salt)));
    }
}
