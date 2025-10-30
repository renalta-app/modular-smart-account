// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestCounter} from "../mocks/TestCounter.sol";

/// @title OwnerTransferTest
/// @notice Tests for ownership transfer and access control
///
/// Test Categories:
/// - Basic Ownership Transfer
/// - Access Control After Transfer
/// - Module Management Permissions
/// - Execution Permissions
/// - Edge Cases & Security
contract OwnerTransferTest is ModularAccountTestBase {
    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);

    // Test modules (reused across tests)
    TestValidatorModule public validator;
    TestCounter public counter;

    // Error declarations for specific revert testing
    error Unauthorized();
    error NewOwnerIsZeroAddress();

    function setUp() public {
        validator = new TestValidatorModule();
        counter = new TestCounter();
    }

    // ============================================
    // BASIC OWNERSHIP TRANSFER
    // ============================================

    function test_ownerCanTransferOwnership() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        assertEq(account.owner(), oldOwner);

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        assertEq(account.owner(), newOwner);
    }

    function test_preventsTransferToZeroAddress() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        vm.expectRevert(NewOwnerIsZeroAddress.selector);
        account.transferOwnership(address(0));

        assertEq(account.owner(), owner);
    }

    function test_nonOwnerCannotTransferOwnership() public {
        (ModularSmartAccount account,,) = setupAccount();
        address attacker = createAddress();
        address newOwner = createAddress();

        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        account.transferOwnership(newOwner);
    }

    // ============================================
    // ACCESS CONTROL AFTER TRANSFER
    // ============================================

    function test_newOwnerCanPerformOwnerOperations() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        address mockRegistry = createAddress();
        vm.prank(newOwner);
        account.configureModuleRegistry(mockRegistry);

        assertEq(account.getModuleRegistry(), mockRegistry);
    }

    function test_oldOwnerLosesPermissionsAfterTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        address mockRegistry = createAddress();
        vm.prank(oldOwner);
        vm.expectRevert(Unauthorized.selector);
        account.configureModuleRegistry(mockRegistry);
    }

    function test_newOwnerCanExecuteTransactions() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(newOwner);
        account.execute(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1);
    }

    function test_oldOwnerCannotExecuteAfterTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(oldOwner);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        account.execute(MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 0);
    }

    // ============================================
    // MODULE MANAGEMENT PERMISSIONS
    // ============================================

    function test_newOwnerCanInstallModules() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        bytes memory initData = abi.encode(newOwner);
        vm.prank(newOwner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));
    }

    function test_oldOwnerCannotInstallModulesAfterTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        bytes memory initData = abi.encode(oldOwner);
        vm.prank(oldOwner);
        vm.expectRevert(Unauthorized.selector);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);
    }

    function test_newOwnerCanUninstallOldOwnerModules() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();
        TestValidatorModule validator1 = new TestValidatorModule();
        TestValidatorModule validator2 = new TestValidatorModule();

        bytes memory initData = abi.encode(oldOwner);
        vm.prank(oldOwner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), initData);
        vm.prank(oldOwner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        vm.prank(newOwner);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator1), "");

        assertFalse(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator1), ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator2), ""));
    }

    function test_modulesRemainInstalledAfterTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        bytes memory initData = abi.encode(oldOwner);
        vm.prank(oldOwner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1);
    }

    // ============================================
    // UPGRADE PERMISSIONS
    // ============================================

    function test_newOwnerCanUpgradeImplementation() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);

        vm.prank(newOwner);
        account.upgradeToAndCall(address(newImplementation), "");

        assertEq(account.owner(), newOwner);
    }

    function test_oldOwnerCannotUpgradeAfterTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);

        vm.prank(oldOwner);
        vm.expectRevert(Unauthorized.selector);
        account.upgradeToAndCall(address(newImplementation), "");
    }

    // ============================================
    // NOTE: EntryPoint deposit tests are covered in fork tests
    // since they require actual EntryPoint contract deployment
    // ============================================

    // ============================================
    // EDGE CASES
    // ============================================

    function test_canTransferOwnershipMultipleTimes() public {
        (ModularSmartAccount account,, address owner1) = setupAccount();
        address owner2 = createAddress();
        address owner3 = createAddress();

        vm.prank(owner1);
        account.transferOwnership(owner2);
        assertEq(account.owner(), owner2);

        vm.prank(owner2);
        account.transferOwnership(owner3);
        assertEq(account.owner(), owner3);

        address mockRegistry = createAddress();
        vm.prank(owner3);
        account.configureModuleRegistry(mockRegistry);
        assertEq(account.getModuleRegistry(), mockRegistry);
    }

    function test_transferOwnershipToSelfIsNoop() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.transferOwnership(owner);

        assertEq(account.owner(), owner);

        address mockRegistry = createAddress();
        vm.prank(owner);
        account.configureModuleRegistry(mockRegistry);
        assertEq(account.getModuleRegistry(), mockRegistry);
    }

    function test_attestersConfigurationPersistsAcrossTransfer() public {
        (ModularSmartAccount account,, address oldOwner) = setupAccount();
        address newOwner = createAddress();

        address[] memory attesters = new address[](2);
        attesters[0] = createAddress();
        attesters[1] = createAddress();
        vm.prank(oldOwner);
        account.configureAttesters(attesters, 2);

        vm.prank(oldOwner);
        account.transferOwnership(newOwner);

        (address[] memory storedAttesters, uint8 threshold) = account.getAttesters();
        assertEq(storedAttesters.length, 2);
        assertEq(threshold, 2);
        assertEq(storedAttesters[0], attesters[0]);
        assertEq(storedAttesters[1], attesters[1]);
    }
}
