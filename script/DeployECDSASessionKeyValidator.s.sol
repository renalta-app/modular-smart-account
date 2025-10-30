// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ECDSASessionKeyValidator} from "../test/helpers/modules/ECDSASessionKeyValidator.sol";

/**
 * @title DeployECDSASessionKeyValidator
 * @notice Deployment script for ECDSASessionKeyValidator contract
 * @dev Deploys stateless ECDSA validator for SmartSession session keys
 *
 * Usage:
 *   forge script script/DeployECDSASessionKeyValidator.s.sol --rpc-url $RPC_URL --broadcast --verify
 *
 * Environment variables:
 *   - DEPLOYER_PRIVATE_KEY: Private key for deployment
 *   - RPC_URL: Network RPC endpoint
 *   - ETHERSCAN_API_KEY: Optional, for verification
 */
contract DeployECDSASessionKeyValidator is Script {
    /// @notice CREATE2 salt for deterministic deployment (uncomment to use)
    // bytes32 constant SALT = bytes32(uint256(0x0));

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Non-deterministic deployment (different addresses each time)
        ECDSASessionKeyValidator validator = new ECDSASessionKeyValidator();

        // Deterministic deployment (same addresses across chains - uncomment to use)
        // ECDSASessionKeyValidator validator = new ECDSASessionKeyValidator{salt: SALT}();

        vm.stopBroadcast();

        console2.log("ECDSASessionKeyValidator:", address(validator));
    }
}
