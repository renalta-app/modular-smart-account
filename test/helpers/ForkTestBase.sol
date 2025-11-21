// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7484Registry} from "../../contracts/interfaces/IERC7484.sol";
import {ModularAccountTestBase} from "./TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";

/// @title ForkTestBase
/// @notice Base contract for fork tests with real deployed contract addresses
/// @dev This contract provides addresses for real contracts deployed on Base mainnet
///      Use this for integration testing against actual on-chain state
///      Inherits from ModularAccountTestBase to share common utilities and constants
abstract contract ForkTestBase is ModularAccountTestBase {
    // =============================================================================
    // CHAIN CONFIGURATION
    // =============================================================================

    uint256 internal forkId;

    // =============================================================================
    // ENTRYPOINT V0.8 (CANONICAL DEPLOYMENT)
    // =============================================================================

    // EntryPoint instance (address defined in TestBase)
    IEntryPoint internal entryPoint;

    // =============================================================================
    // ERC-7484 REGISTRY (RHINESTONE)
    // =============================================================================

    // Registry for module attestations
    address internal constant ERC7484_REGISTRY = 0x000000000069E2a187AEFFb852bF3cCdC95151B2;
    IERC7484Registry internal registry;

    // =============================================================================
    // RHINESTONE CORE MODULES - VALIDATORS
    // =============================================================================

    // OwnableValidator - Owner-based validation
    address internal constant OWNABLE_VALIDATOR = 0x000000000013fdB5234E4E3162a810F54d9f7E98;

    // WebAuthnValidator - Passkey-based validation
    address internal constant WEBAUTHN_VALIDATOR = 0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69;

    // MultiFactorValidator - Multi-factor authentication
    address internal constant MULTI_FACTOR_VALIDATOR = 0xf6bDf42c9BE18cEcA5C06c42A43DAf7FBbe7896b;

    // =============================================================================
    // RHINESTONE CORE MODULES - EXECUTORS
    // =============================================================================

    // OwnableExecutor - Owner-controlled execution
    address internal constant OWNABLE_EXECUTOR = 0x4Fd8d57b94966982B62e9588C27B4171B55E8354;

    // ScheduledOrdersExecutor - Automated order execution
    address internal constant SCHEDULED_ORDERS_EXECUTOR = 0x40dc90D670C89F322fa8b9f685770296428DCb6b;

    // ScheduledTransfersExecutor - Automated transfers
    address internal constant SCHEDULED_TRANSFERS_EXECUTOR = 0xA8E374779aeE60413c974b484d6509c7E4DDb6bA;

    // =============================================================================
    // RHINESTONE CORE MODULES - HOOKS
    // =============================================================================

    // RegistryHook - Registry-based validation hook
    address internal constant REGISTRY_HOOK = 0xF6782ed057F95f334D04F0Af1Af4D14fb84DE549;

    // HookMultiplexer - Multiple hooks support
    address internal constant HOOK_MULTIPLEXER = 0xF6782ed057F95f334D04F0Af1Af4D14fb84DE549;

    // =============================================================================
    // RHINESTONE CORE MODULES - ADVANCED
    // =============================================================================

    // SmartSessions - Session key management
    address internal constant SMART_SESSIONS = 0x00000000008bDABA73cD9815d79069c247Eb4bDA;

    // =============================================================================
    // SETUP
    // =============================================================================

    /// @notice Set up fork environment
    /// @dev Call this in your test's setUp() function
    /// @dev Fork must be active before calling (use --fork-url or --rpc-url flag)
    function setupFork() internal {
        // Foundry automatically creates the fork when --fork-url is passed
        // We just need to verify we're in a fork and set up references
        require(block.chainid > 0, "Not in a fork environment");

        // Set up contract references
        entryPoint = IEntryPoint(ENTRYPOINT_V08);
        registry = IERC7484Registry(ERC7484_REGISTRY);

        // Log fork info
        console.log("Fork test running at block:", block.number);
        console.log("Chain ID:", block.chainid);
    }

    // =============================================================================
    // CONTRACT VERIFICATION HELPERS
    // =============================================================================

    /// @notice Verify that a contract exists at the given address
    /// @param contractAddress The address to check
    /// @param name Optional name for logging
    function verifyContractExists(address contractAddress, string memory name) internal view {
        uint256 size;
        assembly {
            size := extcodesize(contractAddress)
        }
        require(size > 0, string.concat(name, " contract not found at address"));
        console.log(name, "verified at:", contractAddress);
    }

    /// @notice Verify all essential contracts are deployed
    function verifyEssentialContracts() internal view {
        verifyContractExists(ENTRYPOINT_V08, "EntryPoint v0.8");
        verifyContractExists(ERC7484_REGISTRY, "ERC-7484 Registry");
        verifyContractExists(OWNABLE_VALIDATOR, "OwnableValidator");
    }

    // =============================================================================
    // BLOCK MANIPULATION (Fork-specific)
    // =============================================================================

    /// @notice Advance time by specified seconds
    function advanceTime(uint256 seconds_) internal {
        vm.warp(block.timestamp + seconds_);
    }

    /// @notice Advance blocks by specified number
    function advanceBlocks(uint256 blocks_) internal {
        vm.roll(block.number + blocks_);
    }

    // =============================================================================
    // ACCOUNT SETUP HELPERS (Fork-specific)
    // =============================================================================

    /// @notice Set up a new ModularSmartAccount using the factory pattern (standard for fork tests)
    /// @dev Creates factory, account via factory, and funds both owner and account
    /// @return factory The ModularSmartAccountFactory instance
    /// @return account The created ModularSmartAccount
    /// @return owner The owner address
    /// @return ownerKey The private key of the owner
    function setupForkAccount()
        internal
        returns (ModularSmartAccountFactory factory, ModularSmartAccount account, address owner, uint256 ownerKey)
    {
        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(implementation));
        account = factory.createAccount(owner, 0);
        fund(address(account), TEN_ETH);
    }

    /// @notice Set up a new ModularSmartAccount with custom salt
    /// @param salt The salt value for deterministic address generation
    /// @return factory The ModularSmartAccountFactory instance
    /// @return account The created ModularSmartAccount
    /// @return owner The owner address
    /// @return ownerKey The private key of the owner
    function setupForkAccount(uint256 salt)
        internal
        returns (ModularSmartAccountFactory factory, ModularSmartAccount account, address owner, uint256 ownerKey)
    {
        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(implementation));
        account = factory.createAccount(owner, salt);
        fund(address(account), TEN_ETH);
    }
}
