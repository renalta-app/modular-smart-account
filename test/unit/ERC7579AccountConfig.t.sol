// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @title ERC7579AccountConfigTest
/// @notice Tests for ERC-7579 AccountConfig interface compliance
/// @dev Tests accountId(), supportsExecutionMode(), and supportsModule()
contract ERC7579AccountConfigTest is ModularAccountTestBase {
    ModularSmartAccount public account;
    address public owner;
    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);

    function setUp() public {
        (account,, owner) = setupAccount();
    }

    // ============================================
    // ACCOUNT ID TESTS
    // ============================================

    function test_accountIdReturnsCorrectIdentifier() public view {
        string memory accountId = account.accountId();
        assertEq(accountId, "renalta.modular-smart-account.0.1.0", "Account ID mismatch");
    }

    // ============================================
    // EXECUTION MODE SUPPORT TESTS
    // ============================================

    function test_supportsAllExecutionModes() public view {
        bytes32 modeSingle = bytes32(uint256(uint8(LibERC7579.CALLTYPE_SINGLE)) << 248);
        assertTrue(account.supportsExecutionMode(modeSingle), "Should support SINGLE mode");

        bytes32 modeBatch = bytes32(uint256(uint8(LibERC7579.CALLTYPE_BATCH)) << 248);
        assertTrue(account.supportsExecutionMode(modeBatch), "Should support BATCH mode");

        bytes32 modeDelegate = bytes32(uint256(uint8(LibERC7579.CALLTYPE_DELEGATECALL)) << 248);
        assertTrue(account.supportsExecutionMode(modeDelegate), "Should support DELEGATECALL mode");

        bytes32 modeStatic = bytes32(uint256(uint8(LibERC7579.CALLTYPE_STATICCALL)) << 248);
        assertTrue(account.supportsExecutionMode(modeStatic), "Should support STATICCALL mode");
    }

    function test_rejectsUnsupportedExecutionModes() public view {
        bytes32 modeInvalid1 = bytes32(uint256(0x02) << 248);
        assertFalse(account.supportsExecutionMode(modeInvalid1), "Should reject call type 0x02");

        bytes32 modeInvalid2 = bytes32(uint256(0x03) << 248);
        assertFalse(account.supportsExecutionMode(modeInvalid2), "Should reject call type 0x03");

        bytes32 modeInvalid3 = bytes32(uint256(0x10) << 248);
        assertFalse(account.supportsExecutionMode(modeInvalid3), "Should reject call type 0x10");
    }

    function test_supportsExecutionModeWithAdditionalData() public view {
        bytes32 modeSingleWithData = bytes32(uint256(uint8(LibERC7579.CALLTYPE_SINGLE)) << 248 | 0x123456);
        assertTrue(account.supportsExecutionMode(modeSingleWithData), "Should support SINGLE mode with additional data");

        bytes32 modeBatchWithExec = bytes32(uint256(uint8(LibERC7579.CALLTYPE_BATCH)) << 248 | uint256(0x01) << 240);
        assertTrue(account.supportsExecutionMode(modeBatchWithExec), "Should support BATCH mode with exec type");
    }

    // ============================================
    // MODULE TYPE SUPPORT TESTS
    // ============================================

    function test_supportsAllModuleTypes() public view {
        assertTrue(account.supportsModule(MODULE_TYPE_VALIDATOR), "Should support VALIDATOR modules");
        assertTrue(account.supportsModule(MODULE_TYPE_EXECUTOR), "Should support EXECUTOR modules");
        assertTrue(account.supportsModule(MODULE_TYPE_FALLBACK), "Should support FALLBACK modules");
        assertTrue(account.supportsModule(MODULE_TYPE_HOOK), "Should support HOOK modules");
    }

    function test_rejectsUnsupportedModuleTypes() public view {
        assertFalse(account.supportsModule(0), "Should reject module type 0");
        assertFalse(account.supportsModule(8), "Should reject module type 8");
        assertFalse(account.supportsModule(999), "Should reject module type 999");
        assertFalse(account.supportsModule(type(uint256).max), "Should reject max uint256");
    }

    function test_moduleTypeBoundaries() public view {
        assertFalse(account.supportsModule(MODULE_TYPE_VALIDATOR - 1), "Should reject type below VALIDATOR");
        assertFalse(account.supportsModule(8), "Should reject type above STATELESS_VALIDATOR");
        assertTrue(account.supportsModule(MODULE_TYPE_VALIDATOR), "Should support first valid type");
        assertTrue(account.supportsModule(MODULE_TYPE_HOOK), "Should support HOOK type");
        assertTrue(account.supportsModule(5), "Should support POLICY type");
        assertTrue(account.supportsModule(6), "Should support SIGNER type");
        assertTrue(account.supportsModule(7), "Should support STATELESS_VALIDATOR type");
    }

    // ============================================
    // INTEGRATION TESTS
    // ============================================

    function test_accountConfigInterfaceComplete() public view {
        string memory id = account.accountId();
        bool supportsMode = account.supportsExecutionMode(MODE_DEFAULT);
        bool supportsModuleType = account.supportsModule(MODULE_TYPE_VALIDATOR);

        assertTrue(bytes(id).length > 0, "Account ID should not be empty");
        assertTrue(supportsMode, "Should support default mode");
        assertTrue(supportsModuleType, "Should support validator modules");
    }
}
