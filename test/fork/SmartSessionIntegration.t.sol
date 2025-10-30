// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SmartSessionTestBase} from "../helpers/SmartSessionTestBase.sol";
import {MockTarget} from "../helpers/MockTarget.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {PermissionId, PolicyData, Session} from "smartsessions/DataTypes.sol";
import {ISessionValidator} from "smartsessions/interfaces/ISessionValidator.sol";

import {SudoPolicy} from "smartsessions/external/policies/SudoPolicy.sol";
import {TimeFramePolicy} from "smartsessions/external/policies/TimeFramePolicy.sol";
import {ECDSASessionKeyValidator} from "../helpers/modules/ECDSASessionKeyValidator.sol";

/// SmartSessionIntegrationTest
/// Fork tests for SmartSession module with sudo and time-based policies
contract SmartSessionIntegrationTest is SmartSessionTestBase {
    SudoPolicy public sudoPolicy;
    TimeFramePolicy public timeFramePolicy;
    ECDSASessionKeyValidator public sessionValidator;

    function setUp() public {
        setUpSmartSessionBase();

        sudoPolicy = new SudoPolicy();
        timeFramePolicy = new TimeFramePolicy();
        sessionValidator = new ECDSASessionKeyValidator();
    }

    function test_fork_installWithSudoSession() public {
        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, ""), "SmartSessions not installed");
        assertTrue(smartSession.isInitialized(address(account)), "SmartSessions not initialized");
        assertTrue(smartSession.isPermissionEnabled(permissionIds[0], address(account)), "Sudo session not enabled");
    }

    function test_fork_sudoPolicy_simpleTransfer() public {
        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - transferAmount, "Account balance incorrect");
    }

    function test_fork_sudoPolicy_arbitraryContractCall() public {
        MockTarget target = new MockTarget();

        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);

        depositFor(address(account), 1 ether);
        uint256 accountBalanceBefore = getAccountBalance();

        bytes memory targetCallData = abi.encodeWithSelector(MockTarget.setValue.selector, uint256(1337));
        bytes memory executionData = encodeSingleExecution(address(target), 0, targetCallData);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertEq(target.value(), 1337, "Contract call failed");
        assertEq(getAccountBalance(), accountBalanceBefore, "Account balance should not change for 0-value call");
    }

    function test_fork_sudoPolicy_batchExecution() public {
        MockTarget target = new MockTarget();

        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);

        depositFor(address(account), 2 ether);
        uint256 accountBalanceBefore = getAccountBalance();

        address recipient1 = createAddress();
        address recipient2 = createAddress();

        address[] memory targets = new address[](3);
        targets[0] = recipient1;
        targets[1] = recipient2;
        targets[2] = address(target);

        uint256[] memory values = new uint256[](3);
        values[0] = 0.1 ether;
        values[1] = 0.2 ether;
        values[2] = 0;

        bytes[] memory datas = new bytes[](3);
        datas[0] = "";
        datas[1] = "";
        datas[2] = abi.encodeWithSelector(MockTarget.setValue.selector, uint256(9999));

        bytes memory executionData = encodeBatchExecution(targets, values, datas);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_BATCH, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient1, 0.1 ether, "First transfer failed");
        assertBalance(recipient2, 0.2 ether, "Second transfer failed");
        assertEq(target.value(), 9999, "Contract call failed");
        assertEq(getAccountBalance(), accountBalanceBefore - 0.3 ether, "Account balance incorrect");
    }

    function test_fork_installWithTimeFramePolicy() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, ""), "SmartSessions not installed");
        assertTrue(smartSession.isInitialized(address(account)), "SmartSessions not initialized");
        assertTrue(
            smartSession.isPermissionEnabled(permissionIds[0], address(account)), "TimeFrame session not enabled"
        );
    }

    function test_fork_timeFrame_allowsTransferWithinWindow() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(block.timestamp + 1);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - transferAmount, "Account balance incorrect");
    }

    function test_fork_timeFrame_allowsTransferAtValidAfter() public {
        uint48 validAfter = uint48(block.timestamp + 1 hours);
        uint48 validUntil = uint48(block.timestamp + 2 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(validAfter + 1);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - transferAmount, "Account balance incorrect");
    }

    function test_fork_timeFrame_allowsTransferBeforeValidUntil() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(validUntil - 1);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - transferAmount, "Account balance incorrect");
    }

    function test_fork_timeFrame_rejectsTransferBeforeValidAfter() public {
        uint48 validAfter = uint48(block.timestamp + 1 hours);
        uint48 validUntil = uint48(block.timestamp + 2 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        vm.expectRevert();
        submitUserOp(userOp);

        assertBalance(recipient, 0, "Transfer should have failed");
    }

    function test_fork_timeFrame_rejectsTransferAfterValidUntil() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(validUntil + 1);

        address recipient = createAddress();
        bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        vm.expectRevert();
        submitUserOp(userOp);

        assertBalance(recipient, 0, "Transfer should have failed");
    }

    function test_fork_timeFrame_validUntilZeroNeverExpires() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = 0;

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(block.timestamp + 365 days);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - transferAmount, "Account balance incorrect");
    }

    function test_fork_timeFrame_batchExecutionWithinWindow() public {
        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds = _installSmartSessionWithSessions(sessions);
        depositFor(address(account), 1 ether);

        vm.warp(block.timestamp + 1);

        uint256 accountBalanceBefore = getAccountBalance();
        address recipient1 = createAddress();
        address recipient2 = createAddress();

        address[] memory targets = new address[](2);
        targets[0] = recipient1;
        targets[1] = recipient2;

        uint256[] memory values = new uint256[](2);
        values[0] = 0.1 ether;
        values[1] = 0.2 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = "";
        datas[1] = "";

        bytes memory executionData = encodeBatchExecution(targets, values, datas);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_BATCH, executionData);

        PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient1, 0.1 ether, "First transfer failed");
        assertBalance(recipient2, 0.2 ether, "Second transfer failed");
        assertEq(getAccountBalance(), accountBalanceBefore - 0.3 ether, "Account balance incorrect");
    }

    function _createSudoSession() internal view returns (Session memory) {
        PolicyData[] memory sudoPolicies = new PolicyData[](1);
        sudoPolicies[0] = PolicyData({policy: address(sudoPolicy), initData: ""});

        return _createSession(
            ISessionValidator(address(sessionValidator)),
            abi.encodePacked(sessionKey),
            // casting to 'bytes32' is safe because the string is exactly 16 characters (padded to 32 bytes)
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32("sudo-session-v1"),
            sudoPolicies,
            sudoPolicies,
            false
        );
    }

    function _createTimeFrameSession(uint48 validAfter, uint48 validUntil) internal view returns (Session memory) {
        bytes12 timeFrameConfig = bytes12(uint96((uint256(validUntil) << 48) | uint256(validAfter)));

        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({policy: address(timeFramePolicy), initData: abi.encodePacked(timeFrameConfig)});

        return _createSession(
            ISessionValidator(address(sessionValidator)),
            abi.encodePacked(sessionKey),
            // casting to 'bytes32' is safe because the string is exactly 20 characters (padded to 32 bytes)
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32("timeframe-session-v1"),
            policies,
            policies,
            false
        );
    }
}
