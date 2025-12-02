// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";

/// @title SelfCallAuthorizationTest
/// @notice Tests that the account can call installModule/uninstallModule through self-calls
/// @dev This tests the fix for the issue where execute() -> installModule() fails due to
///      the onlyOwnerOrEntryPoint modifier not allowing msg.sender == address(this)
contract SelfCallAuthorizationTest is ModularAccountTestBase {
    TestValidatorModule public validator;

    error Unauthorized();

    function setUp() public {
        validator = new TestValidatorModule();
    }

    /// @notice Tests that installModule can be called through execute (self-call)
    /// @dev This mimics the standard ERC-7579 flow: execute() -> installModule()
    function test_installModuleThroughSelfCall() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);

        // Encode the installModule call
        bytes memory installCall = abi.encodeWithSignature(
            "installModule(uint256,address,bytes)",
            MODULE_TYPE_VALIDATOR,
            address(validator),
            initData
        );

        // Encode it as an execution
        bytes memory execData = encodeExecution(address(account), 0, installCall);

        // Call execute from owner - this creates a self-call: account.execute() -> account.installModule()
        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        // Verify the module was installed
        bool isInstalled = account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), "");
        assertTrue(isInstalled, "Module should be installed");
    }

    /// @notice Tests that uninstallModule can be called through execute (self-call)
    /// @dev This mimics the standard ERC-7579 flow: execute() -> uninstallModule()
    function test_uninstallModuleThroughSelfCall() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);

        // First install the module directly (not through execute)
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        // Verify it's installed
        bool isInstalled = account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), "");
        assertTrue(isInstalled, "Module should be installed");

        // Encode the uninstallModule call
        bytes memory uninstallCall = abi.encodeWithSignature(
            "uninstallModule(uint256,address,bytes)",
            MODULE_TYPE_VALIDATOR,
            address(validator),
            ""
        );

        // Encode it as an execution
        bytes memory execData = encodeExecution(address(account), 0, uninstallCall);

        // Call execute from owner - this creates a self-call: account.execute() -> account.uninstallModule()
        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        // Verify the module was uninstalled
        isInstalled = account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), "");
        assertFalse(isInstalled, "Module should be uninstalled");
    }

    /// @notice Tests the complete cycle: install via self-call, then uninstall via self-call
    function test_installAndUninstallThroughSelfCalls() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);

        // 1. Install through self-call
        bytes memory installCall = abi.encodeWithSignature(
            "installModule(uint256,address,bytes)",
            MODULE_TYPE_VALIDATOR,
            address(validator),
            initData
        );
        bytes memory installExecData = encodeExecution(address(account), 0, installCall);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, installExecData);

        bool isInstalled = account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), "");
        assertTrue(isInstalled, "Module should be installed after self-call install");

        // 2. Uninstall through self-call
        bytes memory uninstallCall = abi.encodeWithSignature(
            "uninstallModule(uint256,address,bytes)",
            MODULE_TYPE_VALIDATOR,
            address(validator),
            ""
        );
        bytes memory uninstallExecData = encodeExecution(address(account), 0, uninstallCall);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, uninstallExecData);

        isInstalled = account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), "");
        assertFalse(isInstalled, "Module should be uninstalled after self-call uninstall");
    }
}
