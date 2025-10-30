// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SmartSessionTestBase} from "../helpers/SmartSessionTestBase.sol";
import {MockTarget} from "../helpers/MockTarget.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";

import {PermissionId, PolicyData, Session, SmartSessionMode} from "smartsessions/DataTypes.sol";
import {ISessionValidator} from "smartsessions/interfaces/ISessionValidator.sol";
import {SudoPolicy} from "smartsessions/external/policies/SudoPolicy.sol";
import {TimeFramePolicy} from "smartsessions/external/policies/TimeFramePolicy.sol";
import {ECDSASessionKeyValidator} from "../helpers/modules/ECDSASessionKeyValidator.sol";

/// @title EIP7702WithSmartSessionsTest
/// @notice Tests proving that SmartSessions work in EIP-7702 delegated mode
/// @dev This is a CRITICAL test suite that demonstrates the key improvement:
///      EOAs using EIP-7702 delegation can now use SmartSessions for advanced authorization.
///
/// WHAT THIS ENABLES:
/// - EOAs can delegate to the ModularSmartAccount implementation
/// - They can then install SmartSessions for fine-grained permissions
/// - Session keys can execute transactions with specific policies (time limits, spending limits, etc.)
/// - This brings smart account features to EOAs without requiring a proxy or separate account
///
/// WHY THIS WORKS NOW:
/// - EIP-7702 EOAs have persistent storage (per spec)
/// - The new signature validation checks modules BEFORE falling back to EOA signature
/// - SmartSessions module is checked first, enabling session key authentication
/// - EOA signature remains as fallback for admin actions
contract EIP7702WithSmartSessionsTest is SmartSessionTestBase {
    SudoPolicy public sudoPolicy;
    TimeFramePolicy public timeFramePolicy;
    ECDSASessionKeyValidator public sessionValidator;
    ModularSmartAccount public implementation;

    /// @notice Extended setUp that includes EIP-7702 specific initialization
    function setUp() public {
        setUpSmartSessionBase();

        sudoPolicy = new SudoPolicy();
        timeFramePolicy = new TimeFramePolicy();
        sessionValidator = new ECDSASessionKeyValidator();

        implementation = new ModularSmartAccount(entryPoint);
    }

    /// @dev Simulates EIP-7702 delegation by etching the delegation bytecode
    function setupEip7702Delegation(address eoa, address delegate) internal {
        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), delegate);
        vm.etch(eoa, delegationCode);
    }

    // =============================================================================
    // BASIC SMART SESSIONS IN EIP-7702 MODE
    // =============================================================================

    /// @notice TEST: SmartSessions can be installed on EIP-7702 delegated account
    /// @dev First step - verify module installation works
    function test_eip7702_installSmartSessions() public {
        (address eoa,) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount eoaAccount = ModularSmartAccount(payable(eoa));

        address delegate = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegate, address(implementation), "Delegation should be active");

        vm.prank(eoa);
        eoaAccount.initialize(eoa);

        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(sessions));

        vm.prank(eoa); // EOA calls its own (delegated) functions
        eoaAccount.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        assertTrue(
            eoaAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, ""),
            "SmartSessions should be installed on EIP-7702 account"
        );
        assertTrue(smartSession.isInitialized(address(eoaAccount)), "SmartSessions should be initialized");
        assertTrue(
            smartSession.isPermissionEnabled(permissionIds[0], address(eoaAccount)), "Sudo session should be enabled"
        );
    }

    /// @notice TEST: Session key can execute transactions on EIP-7702 delegated account
    /// @dev This is the core functionality test - session keys work in 7702 mode
    function test_eip7702_sessionKeyExecutesTransaction() public {
        (address eoa,) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount eoaAccount = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        eoaAccount.initialize(eoa);

        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(sessions));
        vm.prank(eoa);
        eoaAccount.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        depositFor(address(eoaAccount), 1 ether);

        address recipient = createAddress();
        uint256 transferAmount = 0.1 ether;

        bytes memory executionData = encodeSingleExecution(recipient, transferAmount, "");
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        // Create UserOp signed by SESSION KEY (not EOA!)
        PackedUserOperation memory userOp = createUserOp(address(eoaAccount), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertBalance(recipient, transferAmount, "Session key transfer should succeed in EIP-7702 mode");
    }

    /// @notice TEST: Session key can call arbitrary contracts on EIP-7702 account
    /// @dev Verifies more complex interactions work with session keys
    function test_eip7702_sessionKeyCallsContract() public {
        (address eoa,) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount eoaAccount = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        eoaAccount.initialize(eoa);

        Session memory session = _createSudoSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(sessions));
        vm.prank(eoa);
        eoaAccount.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        depositFor(address(eoaAccount), 1 ether);

        MockTarget target = new MockTarget();

        bytes memory targetCallData = abi.encodeWithSelector(MockTarget.setValue.selector, uint256(42069));
        bytes memory executionData = encodeSingleExecution(address(target), 0, targetCallData);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

        PackedUserOperation memory userOp = createUserOp(address(eoaAccount), 0, callData);
        userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

        submitUserOp(userOp);

        assertEq(target.value(), 42069, "Session key contract call should succeed in EIP-7702 mode");
    }

    // =============================================================================
    // TIME-BASED POLICY TESTS
    // =============================================================================

    /// @notice TEST: Time-based policies work in EIP-7702 mode
    /// @dev Demonstrates that policy enforcement works for delegated EOAs
    function test_eip7702_timeBasedPolicyEnforcement() public {
        (address eoa,) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));
        ModularSmartAccount eoaAccount = ModularSmartAccount(payable(eoa));

        vm.prank(eoa);
        eoaAccount.initialize(eoa);

        // Create time-limited session (valid for 1 hour from now)
        // validAfter must be 0 or before current time to allow immediate execution
        uint48 validAfter = 0; // 0 means valid immediately
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        Session memory session = _createTimeFrameSession(validAfter, validUntil);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(sessions));
        vm.prank(eoa);
        eoaAccount.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        depositFor(address(eoaAccount), 1 ether);

        // TEST 1: Transaction within time window should succeed
        {
            address recipient = createAddress();
            bytes memory executionData = encodeSingleExecution(recipient, 0.1 ether, "");
            bytes memory callData =
                abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

            PackedUserOperation memory userOp = createUserOp(address(eoaAccount), 0, callData);
            userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

            submitUserOp(userOp);
            assertBalance(recipient, 0.1 ether, "Transaction within time window should succeed");
        }

        // TEST 2: Transaction after time window should fail
        {
            vm.warp(block.timestamp + 2 hours); // Move past validUntil

            address recipient2 = createAddress();
            bytes memory executionData = encodeSingleExecution(recipient2, 0.1 ether, "");
            bytes memory callData =
                abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), MODE_DEFAULT, executionData);

            PackedUserOperation memory userOp = createUserOp(address(eoaAccount), 1, callData);
            userOp.signature = _encodeSessionSignature(userOp, sessionKeyPrivateKey, permissionIds[0]);

            vm.expectRevert();
            submitUserOp(userOp);

            assertBalance(recipient2, 0, "Transaction after time window should fail");
        }
    }

    // =============================================================================
    // HELPER FUNCTIONS
    // =============================================================================

    /// @dev Creates a sudo (unrestricted) session for testing
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
