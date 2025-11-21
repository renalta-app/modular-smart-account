// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../contracts/accounts/ModularSmartAccountFactory.sol";

/// @title Deploy
/// @notice Minimal deployment script for ModularSmartAccount system
/// @dev Deploys factory and implementation using canonical EntryPoint v0.8
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
///
/// Environment variables:
///   - DEPLOYER_PRIVATE_KEY: Private key for deployment
///   - RPC_URL: Network RPC endpoint
///   - ETHERSCAN_API_KEY: Optional, for verification
contract Deploy is Script {
    /// @notice EntryPoint v0.8 canonical address (same on all EVM chains)
    address constant ENTRYPOINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    /// @notice CREATE2 salt for deterministic deployment
    bytes32 constant SALT = bytes32(uint256(0x0));

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation first
        ModularSmartAccount implementation = new ModularSmartAccount(IEntryPoint(ENTRYPOINT_V08));

        // Deploy factory with implementation address (deterministic via CREATE2)
        ModularSmartAccountFactory factory = new ModularSmartAccountFactory{salt: SALT}(address(implementation));

        vm.stopBroadcast();

        console2.log("Implementation:", address(implementation));
        console2.log("Factory:", address(factory));
    }
}
