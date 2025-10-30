// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {NoopHook} from "../helpers/modules/NoopHook.sol";
import {RejectHook} from "../helpers/modules/RejectHook.sol";
import {TransferLimitHook} from "../helpers/modules/TransferLimitHook.sol";
import {AlwaysApproveValidator} from "../helpers/modules/AlwaysApproveValidator.sol";
import {MockERC20} from "solady/../test/utils/mocks/MockERC20.sol";

/// @title HookBehaviorTest
/// @notice Integration tests for hook module behavior and validation logic
/// @dev Tests various hook patterns: noop, reject, transfer limits, multiple hooks
contract HookBehaviorTest is ModularAccountTestBase {
    AlwaysApproveValidator public validator;
    address public recipient;

    function setUp() public {
        recipient = createAddress();
    }

    // ============================================
    // BASIC HOOK BEHAVIOR
    // ============================================

    /// @dev NoopHook allows operations without interference
    function test_noopHook_allowsOperations() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        validator = new AlwaysApproveValidator();
        NoopHook noopHook = new NoopHook();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(noopHook), "");

        fund(owner, ONE_ETH);
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");

        vm.prank(owner);
        account.execute{value: 0.1 ether}(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, 0.1 ether, "Transfer should have succeeded");
    }

    /// @dev RejectHook blocks operations
    function test_rejectHook_blocksOperations() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        validator = new AlwaysApproveValidator();
        RejectHook rejectHook = new RejectHook();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(rejectHook), "");

        fund(owner, ONE_ETH);
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");

        uint256 recipientBalanceBefore = recipient.balance;

        vm.prank(owner);
        vm.expectRevert();
        account.execute{value: 0.1 ether}(MODE_DEFAULT, executionData);

        assertEq(recipient.balance, recipientBalanceBefore, "Transfer should have been blocked by hook");
    }

    // ============================================
    // TRANSFER LIMIT HOOK
    // ============================================

    TransferLimitHook public transferHook;
    MockERC20 public token;
    uint256 constant TRANSFER_LIMIT = 1000 * 1e18;

    function _setupTransferLimitHook(ModularSmartAccount account, address owner) internal {
        validator = new AlwaysApproveValidator();
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        transferHook = new TransferLimitHook();
        token = new MockERC20("Test Token", "TEST", 18);
        token.mint(address(account), 10000 * 1e18);

        TransferLimitHook.TokenConfig memory config =
            TransferLimitHook.TokenConfig({token: address(token), limit: TRANSFER_LIMIT});
        bytes memory initData = abi.encode(config);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(transferHook), initData);
    }

    /// @dev Transfer within limit succeeds
    function test_transferLimitHook_allowsTransferWithinLimit() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        _setupTransferLimitHook(account, owner);

        uint256 transferAmount = TRANSFER_LIMIT;

        bytes memory transferCallData = abi.encodeWithSignature("transfer(address,uint256)", recipient, transferAmount);
        bytes memory executionData = encodeSingleExecution(address(token), 0, transferCallData);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, executionData);

        assertEq(token.balanceOf(recipient), transferAmount, "Transfer should have succeeded");
    }

    /// @dev Transfer exceeding limit is blocked
    function test_transferLimitHook_blocksTransferExceedingLimit() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        _setupTransferLimitHook(account, owner);

        uint256 transferAmount = TRANSFER_LIMIT + 1;

        bytes memory transferCallData = abi.encodeWithSignature("transfer(address,uint256)", recipient, transferAmount);
        bytes memory executionData = encodeSingleExecution(address(token), 0, transferCallData);

        vm.prank(owner);
        vm.expectRevert();
        account.execute(MODE_DEFAULT, executionData);

        assertEq(token.balanceOf(recipient), 0, "Transfer should have been blocked");
    }

    /// @dev Batch transfer with exceeding amount is blocked entirely
    function test_transferLimitHook_blocksBatchWithExceedingTransfer() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        _setupTransferLimitHook(account, owner);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(token);
        values[0] = 0;
        datas[0] = abi.encodeWithSignature("transfer(address,uint256)", recipient, TRANSFER_LIMIT / 2);

        targets[1] = address(token);
        values[1] = 0;
        datas[1] = abi.encodeWithSignature("transfer(address,uint256)", recipient, TRANSFER_LIMIT + 1);

        bytes memory executionData = encodeBatchExecution(targets, values, datas);

        vm.prank(owner);
        vm.expectRevert();
        account.execute(MODE_BATCH, executionData);

        assertEq(token.balanceOf(recipient), 0, "Batch should have been blocked");
    }

    // ============================================
    // MULTIPLE HOOKS
    // ============================================

    /// @dev Multiple hooks can be installed
    function test_multipleHooks_canBeInstalled() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        NoopHook noopHook = new NoopHook();
        RejectHook rejectHook = new RejectHook();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(noopHook), "");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(rejectHook), "");

        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(noopHook), ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(rejectHook), ""));
    }

    /// @dev Hooks can be uninstalled
    function test_hook_canBeUninstalled() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        NoopHook noopHook = new NoopHook();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(noopHook), "");

        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(noopHook), ""));

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_HOOK, address(noopHook), "");

        assertFalse(account.isModuleInstalled(MODULE_TYPE_HOOK, address(noopHook), ""));
    }
}
