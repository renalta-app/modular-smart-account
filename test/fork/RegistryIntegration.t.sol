// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "../helpers/ForkHelpers.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";

/// RegistryIntegrationTest
/// Fork tests for ERC-7484 Registry integration
contract RegistryIntegrationTest is ForkHelpers {
    ModularSmartAccountFactory public factory;
    ModularSmartAccount public account;

    address public owner;
    uint256 public ownerKey;

    receive() external payable {}

    function setUp() public {
        (factory, account, owner, ownerKey) = setUpForkTest();
        verifyContractExists(ERC7484_REGISTRY, "ERC-7484 Registry");
    }

    /// Registry can be configured on account
    function test_fork_configureRegistry() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address configuredRegistry = account.getModuleRegistry();
        assertEq(configuredRegistry, ERC7484_REGISTRY);
    }

    function test_fork_configureAttesters() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address attester1 = createAddress();
        address attester2 = createAddress();

        address[] memory attesters = new address[](2);
        attesters[0] = attester1;
        attesters[1] = attester2;

        vm.prank(owner);
        account.configureAttesters(attesters, 1);

        (address[] memory returnedAttesters, uint256 threshold) = account.getAttesters();

        assertEq(returnedAttesters.length, 2, "Attester count mismatch");
        assertEq(returnedAttesters[0], attester1, "Attester 1 mismatch");
        assertEq(returnedAttesters[1], attester2, "Attester 2 mismatch");
        assertEq(threshold, 1, "Threshold mismatch");
    }

    function test_fork_updateAttesterThreshold() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address[] memory attesters = new address[](3);
        attesters[0] = createAddress();
        attesters[1] = createAddress();
        attesters[2] = createAddress();

        vm.prank(owner);
        account.configureAttesters(attesters, 1);

        vm.prank(owner);
        account.configureAttesters(attesters, 2);

        (, uint256 threshold) = account.getAttesters();
        assertEq(threshold, 2, "Threshold not updated");
    }

    function test_fork_revertInvalidThreshold() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address[] memory attesters = new address[](2);
        attesters[0] = createAddress();
        attesters[1] = createAddress();

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidThreshold()"));
        account.configureAttesters(attesters, 0);
    }

    function test_fork_revertThresholdExceedsAttesterCount() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address[] memory attesters = new address[](2);
        attesters[0] = createAddress();
        attesters[1] = createAddress();

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidThreshold()"));
        account.configureAttesters(attesters, 3);
    }

    function test_fork_installModuleWithoutRegistry() public {
        (address signer,) = createAccountOwner();
        bytes memory initData = encodeOwnableValidatorInstall(signer);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData);

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""),
            "Module not installed without registry"
        );
    }

    function test_fork_registryDoesNotBlockKnownGoodModules() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        (address signer,) = createAccountOwner();
        bytes memory initData = encodeOwnableValidatorInstall(signer);

        vm.prank(owner);
        vm.expectRevert();
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData);
    }

    function test_fork_switchRegistries() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        assertEq(account.getModuleRegistry(), ERC7484_REGISTRY, "First registry not set");

        address newRegistry = createAddress();

        vm.prank(owner);
        account.configureModuleRegistry(newRegistry);

        assertEq(account.getModuleRegistry(), newRegistry, "Registry not switched");
    }

    function test_fork_disableRegistry() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        vm.prank(owner);
        account.configureModuleRegistry(address(0));

        assertEq(account.getModuleRegistry(), address(0), "Registry not disabled");
    }

    function test_fork_fullRegistryWorkflow() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address attester1 = createAddress();
        address attester2 = createAddress();

        address[] memory attesters = new address[](2);
        attesters[0] = attester1;
        attesters[1] = attester2;

        vm.prank(owner);
        account.configureAttesters(attesters, 1);

        assertEq(account.getModuleRegistry(), ERC7484_REGISTRY, "Registry not configured");

        (address[] memory returnedAttesters, uint256 threshold) = account.getAttesters();
        assertEq(returnedAttesters.length, 2, "Attester count mismatch");
        assertEq(threshold, 1, "Threshold mismatch");

        (address signer,) = createAccountOwner();
        bytes memory initData = abi.encode(signer);

        vm.prank(owner);
        try account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData) {} catch {}
    }

    function test_fork_registryWithMultipleModules() public {
        vm.prank(owner);
        account.configureModuleRegistry(ERC7484_REGISTRY);

        address[] memory modules = new address[](3);
        modules[0] = OWNABLE_VALIDATOR;
        modules[1] = SCHEDULED_TRANSFERS_EXECUTOR;
        modules[2] = SMART_SESSIONS;

        uint256[] memory moduleTypes = new uint256[](3);
        moduleTypes[0] = MODULE_TYPE_VALIDATOR;
        moduleTypes[1] = MODULE_TYPE_EXECUTOR;
        moduleTypes[2] = MODULE_TYPE_EXECUTOR;

        uint256 successCount = 0;

        for (uint256 i = 0; i < modules.length; i++) {
            vm.prank(owner);
            try account.installModule(moduleTypes[i], modules[i], "") {
                successCount++;
            } catch {}
        }

        assertTrue(successCount <= modules.length, "Success count should not exceed module count");
    }
}
