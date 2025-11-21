// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "./ForkHelpers.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {
    PermissionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context,
    Session,
    SmartSessionMode
} from "smartsessions/DataTypes.sol";
import {ISmartSession} from "smartsessions/ISmartSession.sol";
import {ISessionValidator} from "smartsessions/interfaces/ISessionValidator.sol";

/// @title SmartSessionTestBase
/// @notice Base contract for SmartSession fork tests with shared setup and helpers
/// @dev Extends ForkHelpers with SmartSession-specific functionality
abstract contract SmartSessionTestBase is ForkHelpers {
    ModularSmartAccountFactory public factory;
    ModularSmartAccount public account;
    ISmartSession public smartSession;

    address public owner;
    uint256 public ownerKey;

    address public sessionKey;
    uint256 public sessionKeyPrivateKey;

    receive() external payable {}

    /// @notice Common setup for SmartSession tests
    /// @dev Call this from your test's setUp() function
    function setUpSmartSessionBase() internal {
        setupFork();
        fund(address(this), 100 ether);

        verifyEssentialContracts();
        verifyContractExists(SMART_SESSIONS, "SmartSessions");

        (owner, ownerKey) = createAccountOwner();
        fund(owner, TEN_ETH);

        (sessionKey, sessionKeyPrivateKey) = createAccountOwner();
        fund(sessionKey, ONE_ETH);

        ModularSmartAccount implementation = new ModularSmartAccount(entryPoint);
        factory = new ModularSmartAccountFactory(address(implementation));
        account = factory.createAccount(owner, 0);
        fund(address(account), 10 ether);

        smartSession = ISmartSession(SMART_SESSIONS);
    }

    /// @notice Create a session with custom validator and policies
    /// @param validator The session validator to use
    /// @param validatorInitData Initialization data for the validator
    /// @param salt Unique salt for the session
    /// @param userOpPolicies Policies to apply to UserOps
    /// @param actionPolicies Policies to apply to actions (uses fallback target/selector)
    /// @param permitPaymaster Whether to permit ERC-4337 paymasters
    function _createSession(
        ISessionValidator validator,
        bytes memory validatorInitData,
        bytes32 salt,
        PolicyData[] memory userOpPolicies,
        PolicyData[] memory actionPolicies,
        bool permitPaymaster
    ) internal pure returns (Session memory) {
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(1), // FALLBACK_TARGET_FLAG
            actionTargetSelector: bytes4(0x00000001), // FALLBACK_TARGET_SELECTOR_FLAG
            actionPolicies: actionPolicies
        });

        return Session({
            sessionValidator: validator,
            sessionValidatorInitData: validatorInitData,
            salt: salt,
            userOpPolicies: userOpPolicies,
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: new ERC7739Context[](0), erc1271Policies: new PolicyData[](0)
            }),
            actions: actions,
            permitERC4337Paymaster: permitPaymaster
        });
    }

    /// @notice Encode SmartSession signature for UserOp
    /// @dev Uses eth_sign format (adds "Ethereum Signed Message" prefix) for ECDSA validators
    /// @param userOp The UserOperation to sign
    /// @param signerKey Private key of the session signer
    /// @param permissionId The permission ID for this session
    function _encodeSessionSignature(PackedUserOperation memory userOp, uint256 signerKey, PermissionId permissionId)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sessionSignature = signUserOp(userOp, signerKey, true);

        return abi.encodePacked(SmartSessionMode.USE, permissionId, sessionSignature);
    }

    /// @notice Enable sessions via the account's execute function (as owner)
    /// @param sessions Array of sessions to enable
    /// @return permissionIds Array of computed permission IDs
    function _enableSessionsViaOwner(Session[] memory sessions) internal returns (PermissionId[] memory) {
        bytes memory callData = abi.encodeWithSelector(ISmartSession.enableSessions.selector, sessions);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, encodeSingleExecution(SMART_SESSIONS, 0, callData));

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        return permissionIds;
    }

    /// @notice Install SmartSession module with sessions enabled
    /// @param sessions Array of sessions to enable during installation
    /// @return permissionIds Array of computed permission IDs
    function _installSmartSessionWithSessions(Session[] memory sessions) internal returns (PermissionId[] memory) {
        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(sessions));

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, SMART_SESSIONS, initData);

        PermissionId[] memory permissionIds = new PermissionId[](sessions.length);
        for (uint256 i = 0; i < sessions.length; i++) {
            permissionIds[i] = smartSession.getPermissionId(sessions[i]);
        }

        return permissionIds;
    }

    /// @notice Helper to assert balance changes correctly
    /// @param recipient The recipient address
    /// @param expectedBalance Expected final balance
    /// @param message Assertion message
    function assertBalance(address recipient, uint256 expectedBalance, string memory message) internal view {
        assertEq(recipient.balance, expectedBalance, message);
    }

    /// @notice Helper to get account balance
    function getAccountBalance() internal view returns (uint256) {
        return address(account).balance;
    }
}
