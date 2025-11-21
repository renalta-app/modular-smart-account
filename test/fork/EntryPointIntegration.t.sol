// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "../helpers/ForkHelpers.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// EntryPointIntegrationTest
/// Fork tests for EntryPoint v0.8 integration on Base mainnet
contract EntryPointIntegrationTest is ForkHelpers {
    ModularSmartAccountFactory public factory;
    ModularSmartAccount public account;

    address public owner;
    uint256 public ownerKey;

    bytes4 private constant EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));

    error FailedOp(uint256 opIndex, string reason);
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    receive() external payable {}

    function setUp() public {
        setupFork();
        fund(address(this), 100 ether);
        verifyContractExists(ENTRYPOINT_V08, "EntryPoint v0.8");

        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(implementation));
    }

    function test_fork_entryPointExists() public view {
        uint256 size;
        address ep = ENTRYPOINT_V08;
        assembly {
            size := extcodesize(ep)
        }
        assertTrue(size > 0, "EntryPoint has no code");
        assertTrue(address(entryPoint) == ENTRYPOINT_V08, "EntryPoint address mismatch");
    }

    function test_fork_canDepositToEntryPoint() public {
        address testAccount = createAddress();
        uint256 depositAmount = 1 ether;

        depositFor(testAccount, depositAmount);

        uint256 balance = getDeposit(testAccount);
        assertEq(balance, depositAmount, "Deposit amount mismatch");
    }

    function test_fork_deployAccountViaFactory() public {
        address predictedAccount = factory.getAddress(owner, 0);

        ModularSmartAccount deployedAccountInstance = factory.createAccount(owner, 0);
        address deployedAccount = address(deployedAccountInstance);

        assertEq(deployedAccount, predictedAccount, "Account address mismatch");
        assertTrue(deployedAccount.code.length > 0, "Account has no code");
    }

    function test_fork_deployAccountViaUserOp() public {
        address accountAddress = factory.getAddress(owner, 0);

        fund(accountAddress, 1 ether);
        depositFor(accountAddress, 1 ether);

        bytes memory factoryData = abi.encodeWithSelector(factory.createAccount.selector, owner, 0);

        PackedUserOperation memory userOp =
            createUserOpWithFactory(accountAddress, 0, address(factory), factoryData, "");

        userOp.signature = signUserOp(userOp, ownerKey);
        submitUserOp(userOp);

        assertTrue(accountAddress.code.length > 0, "Account not deployed");

        ModularSmartAccount deployedAccount = ModularSmartAccount(payable(accountAddress));
        assertEq(deployedAccount.owner(), owner, "Owner mismatch");
    }

    function test_fork_executeSimpleTransferViaEntryPoint() public {
        account = factory.createAccount(owner, 0);
        address accountAddress = address(account);

        fund(accountAddress, 10 ether);
        depositFor(accountAddress, 1 ether);

        address recipient = createAddress();
        uint256 transferAmount = 1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createAndSignUserOp(accountAddress, 0, callData, ownerKey);

        uint256 recipientBalanceBefore = recipient.balance;

        submitUserOp(userOp);

        assertEq(recipient.balance, recipientBalanceBefore + transferAmount, "Transfer failed");
    }

    function test_fork_executeBatchTransfersViaEntryPoint() public {
        account = factory.createAccount(owner, 0);
        address accountAddress = address(account);

        fund(accountAddress, 10 ether);
        depositFor(accountAddress, 1 ether);

        address recipient1 = createAddress();
        address recipient2 = createAddress();
        address recipient3 = createAddress();

        address[] memory targets = new address[](3);
        targets[0] = recipient1;
        targets[1] = recipient2;
        targets[2] = recipient3;

        uint256[] memory values = new uint256[](3);
        values[0] = 0.5 ether;
        values[1] = 0.3 ether;
        values[2] = 0.2 ether;

        bytes[] memory datas = new bytes[](3);
        datas[0] = "";
        datas[1] = "";
        datas[2] = "";

        bytes memory executionData = encodeBatchExecution(targets, values, datas);
        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, MODE_BATCH, executionData);

        PackedUserOperation memory userOp = createAndSignUserOp(accountAddress, 0, callData, ownerKey);

        submitUserOp(userOp);

        assertEq(recipient1.balance, 0.5 ether, "Recipient 1 transfer failed");
        assertEq(recipient2.balance, 0.3 ether, "Recipient 2 transfer failed");
        assertEq(recipient3.balance, 0.2 ether, "Recipient 3 transfer failed");
    }

    function test_fork_nonceIncrements() public {
        account = factory.createAccount(owner, 0);
        address accountAddress = address(account);

        fund(accountAddress, 10 ether);
        depositFor(accountAddress, 2 ether);

        uint256 nonce1 = entryPoint.getNonce(accountAddress, 0);

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp1 = createAndSignUserOp(accountAddress, nonce1, callData, ownerKey);
        submitUserOp(userOp1);

        uint256 nonce2 = entryPoint.getNonce(accountAddress, 0);
        assertEq(nonce2, nonce1 + 1, "Nonce did not increment");

        PackedUserOperation memory userOp2 = createAndSignUserOp(accountAddress, nonce2, callData, ownerKey);
        submitUserOp(userOp2);

        uint256 nonce3 = entryPoint.getNonce(accountAddress, 0);
        assertEq(nonce3, nonce2 + 1, "Nonce did not increment on second op");
    }

    function test_fork_revertOnInvalidNonce() public {
        account = factory.createAccount(owner, 0);
        address accountAddress = address(account);

        fund(accountAddress, 10 ether);
        depositFor(accountAddress, 1 ether);

        uint256 currentNonce = entryPoint.getNonce(accountAddress, 0);

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createAndSignUserOp(accountAddress, currentNonce + 5, callData, ownerKey);

        vm.expectRevert(abi.encodeWithSelector(FailedOp.selector, 0, "AA25 invalid account nonce"));
        submitUserOp(userOp);
    }

    /// Complete user onboarding flow: deploy account, install module, execute transaction
    function test_fork_newUserOnboarding() public {
        (address user, uint256 userKey) = createAccountOwner();

        ModularSmartAccount newAccount = factory.createAccount(user, 0);
        address accountAddress = address(newAccount);

        fund(accountAddress, 5 ether);
        depositFor(accountAddress, 1 ether);

        (address validatorSigner,) = createAccountOwner();
        bytes memory validatorInit = encodeOwnableValidatorInstall(validatorSigner);

        vm.prank(user);
        newAccount.installModule(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, validatorInit);

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createAndSignUserOp(accountAddress, 0, callData, userKey);
        submitUserOp(userOp);

        assertEq(recipient.balance, 0.1 ether, "Transaction should succeed");
        assertTrue(
            newAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, OWNABLE_VALIDATOR, ""), "Validator should be installed"
        );
    }
}
