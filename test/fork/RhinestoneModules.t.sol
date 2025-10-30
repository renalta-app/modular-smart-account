// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "../helpers/ForkHelpers.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// RhinestoneModulesTest
/// Fork tests validating ERC-7579 compatibility with real Rhinestone modules
contract RhinestoneModulesTest is ForkHelpers {
    ModularSmartAccountFactory public factory;
    ModularSmartAccount public account;

    address public owner;
    uint256 public ownerKey;

    receive() external payable {}

    function setUp() public {
        (factory, account, owner, ownerKey) = setUpForkTest();

        verifyContractExists(OWNABLE_VALIDATOR, "OwnableValidator");
        verifyContractExists(WEBAUTHN_VALIDATOR, "WebAuthnValidator");
        verifyContractExists(SMART_SESSIONS, "SmartSessions");
    }

    /// OwnableValidator can be installed and validates UserOps
    function test_fork_installOwnableValidator() public {
        (address signer, uint256 signerKey) = createAccountOwner();

        bytes memory initData = encodeOwnableValidatorInstall(signer);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData);

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""), "OwnableValidator not installed"
        );

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        depositFor(address(account), 1 ether);

        PackedUserOperation memory userOp = createAndSignUserOp(address(account), 0, callData, signerKey, true);

        submitUserOp(userOp);

        assertEq(recipient.balance, 0.1 ether, "Validator did not validate correctly");
    }

    /// Validators use OR logic - any installed validator can authorize
    function test_fork_ownableValidatorORLogic() public {
        (address signer, uint256 signerKey) = createAccountOwner();
        bytes memory initData = encodeOwnableValidatorInstall(signer);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData);

        depositFor(address(account), 2 ether);

        address recipient1 = createAddress();
        bytes memory executionData1 = encodeSingleExecution(recipient1, 0.1 ether, "");
        bytes memory callData1 =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData1);

        PackedUserOperation memory userOp1 = createAndSignUserOp(address(account), 0, callData1, signerKey, true);
        submitUserOp(userOp1);
        assertEq(recipient1.balance, 0.1 ether, "Validator signature failed");

        address recipient2 = createAddress();
        bytes memory executionData2 = encodeSingleExecution(recipient2, 0.1 ether, "");
        bytes memory callData2 =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData2);

        PackedUserOperation memory userOp2 = createAndSignUserOp(address(account), 1, callData2, ownerKey, false);
        submitUserOp(userOp2);
        assertEq(recipient2.balance, 0.1 ether, "Owner signature failed");
    }

    /// Must install a second validator first since last validator cannot be removed
    function test_fork_uninstallOwnableValidator() public {
        (address signer1,) = createAccountOwner();
        bytes memory initData1 = encodeOwnableValidatorInstall(signer1);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, initData1);
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""), "Not installed");

        (address signer2,) = createAccountOwner();
        bytes memory initData2 = encodeOwnableValidatorInstall(signer2);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, WEBAUTHN_VALIDATOR, initData2);
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, WEBAUTHN_VALIDATOR, ""), "Second validator not installed"
        );

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, "");

        assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""), "Still installed after uninstall"
        );
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, WEBAUTHN_VALIDATOR, ""), "Second validator removed");
    }

    function test_fork_installSmartSessions() public {
        bytes memory initData = "";

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, ""), "SmartSessions not installed");
    }

    /// ScheduledTransfersExecutor requires init data
    function test_fork_installScheduledTransfersExecutor() public {
        bytes memory initData = "";

        vm.prank(owner);
        vm.expectRevert();
        account.installModule(MODULE_TYPE_EXECUTOR, SCHEDULED_TRANSFERS_EXECUTOR, initData);
    }

    /// Multiple module types can be installed simultaneously
    function test_fork_installMultipleModuleTypes() public {
        (address signer1,) = createAccountOwner();
        bytes memory validatorInit1 = encodeOwnableValidatorInstall(signer1);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, validatorInit1);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, "");

        (address executorOwner,) = createAccountOwner();
        bytes memory executorInit = abi.encodePacked(executorOwner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, OWNABLE_EXECUTOR, executorInit);

        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""), "OwnableValidator not installed"
        );
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, ""), "SmartSessions not installed");
        assertTrue(
            account.isModuleInstalled(MODULE_TYPE_EXECUTOR, OWNABLE_EXECUTOR, ""), "OwnableExecutor not installed"
        );

        uint256 validatorCount = account.getModuleCount(MODULE_TYPE_VALIDATOR);
        uint256 executorCount = account.getModuleCount(MODULE_TYPE_EXECUTOR);

        assertGe(validatorCount, 2, "Expected at least 2 validators");
        assertGe(executorCount, 1, "Expected at least 1 executor");
    }
}
