// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
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

    /// @notice CREATE2 salt for deterministic deployment (uncomment to use)
    // bytes32 constant SALT = bytes32(uint256(0x0));

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Non-deterministic deployment (different addresses each time)
        ModularSmartAccountFactory factory = new ModularSmartAccountFactory(IEntryPoint(ENTRYPOINT_V08));

        // Deterministic deployment (same addresses across chains - uncomment to use)
        // ModularSmartAccountFactory factory = new ModularSmartAccountFactory{salt: SALT}(IEntryPoint(ENTRYPOINT_V08));

        vm.stopBroadcast();

        console2.log("Factory:", address(factory));
        console2.log("Implementation:", address(factory.ACCOUNT_IMPLEMENTATION()));
    }
}
