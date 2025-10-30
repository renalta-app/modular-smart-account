// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {UserOpHelpers} from "../helpers/UserOpHelpers.sol";

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {TestCounter} from "../mocks/TestCounter.sol";
import {TestDelegateTarget} from "../mocks/TestDelegateTarget.sol";
import {MockERC7484Registry} from "../mocks/MockERC7484Registry.sol";

import {TestValidatorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestExecutorModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestHookModule} from "../helpers/modules/TestERC7579Modules.sol";
import {RevertingHookModule} from "../helpers/modules/TestERC7579Modules.sol";
import {TestFallbackModule} from "../helpers/modules/TestERC7579Modules.sol";

import {OwnerValidatorModule} from "../helpers/modules/OwnerValidatorModule.sol";
import {DirectCallExecutorModule} from "../helpers/modules/DirectCallExecutorModule.sol";
import {ActivityLogHookModule} from "../helpers/modules/ActivityLogHookModule.sol";

import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// @title ModularSmartAccountTest
/// @notice Comprehensive test suite for ModularSmartAccount ERC-7579 implementation
contract ModularSmartAccountTest is ModularAccountTestBase {
    using UserOpHelpers for UserOpHelpers.UserOperation;

    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    uint256 public chainId;

    // Test modules (reused across tests)
    TestValidatorModule public validator;
    TestExecutorModule public executor;
    TestHookModule public hook;
    TestFallbackModule public fallbackModule;
    TestCounter public counter;
    OwnerValidatorModule public ownerValidator;
    DirectCallExecutorModule public directCallExecutor;
    ActivityLogHookModule public activityLogHook;

    // Events
    event ModuleInstalled(uint256 moduleTypeId, address module);

    function setUp() public {
        chainId = block.chainid;
        validator = new TestValidatorModule();
        executor = new TestExecutorModule();
        hook = new TestHookModule();
        fallbackModule = new TestFallbackModule();
        counter = new TestCounter();
        ownerValidator = new OwnerValidatorModule();
        directCallExecutor = new DirectCallExecutorModule();
        activityLogHook = new ActivityLogHookModule();
    }

    // ============================================
    // HELPER FUNCTIONS
    // ============================================

    function packModuleInstallData(address signer) internal pure returns (bytes memory) {
        return abi.encode(signer);
    }

    // ============================================
    // VALIDATOR MODULE TESTS
    // ============================================

    function test_ownerCanInstallValidatorModuleAndPreventDuplicates() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory initData = packModuleInstallData(moduleSigner);

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit ModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator));
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));

        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ModuleAlreadyInstalled(uint256,address)", MODULE_TYPE_VALIDATOR, address(validator)
            )
        );
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);
    }

    function test_validateUserOpUsesValidatorModuleSignatures() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        // Validation should fail before module is installed
        vm.prank(address(entryPoint));
        uint256 beforeInstall = account.validateUserOp(packed, userOpHash, 0);
        assertEq(beforeInstall, VALIDATION_FAILED);

        bytes memory initData = packModuleInstallData(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        // Validation should succeed after module is installed
        vm.prank(address(entryPoint));
        uint256 afterInstall = account.validateUserOp(packed, userOpHash, 0);
        assertEq(afterInstall, VALIDATION_SUCCESS);
    }

    function test_erc1271ValidationRoutesThroughModules() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = packModuleInstallData(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_SUCCESS);

        bytes4 result = account.isValidSignature(userOpHash, userOp.signature);
        assertEq(result, ERC1271_MAGIC_VALUE);
    }

    // ============================================
    // EXECUTOR MODULE TESTS
    // ============================================

    function test_preventsUnauthorizedExecuteFromExecutorUsage() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("ModuleNotInstalled(uint256,address)", MODULE_TYPE_EXECUTOR, owner));
        account.executeFromExecutor(MODE_DEFAULT, execData);
    }

    function test_allowsInstalledExecutorModuleToTriggerAccountCalls() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        executor.proxyExecute(IERC7579Execution(address(account)), MODE_DEFAULT, execData);

        assertEq(counter.counters(address(account)), 1);
    }

    function test_supportsDelegatecallModeThroughExecutor() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestDelegateTarget delegateTarget = new TestDelegateTarget();

        bytes memory callData = abi.encodeWithSignature("getNumber()");
        // encodeDelegateExecution for delegate calls (no value field)
        bytes memory execData = encodeDelegateExecution(address(delegateTarget), callData);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        bytes[] memory results = executor.proxyExecute(IERC7579Execution(address(account)), MODE_DELEGATE, execData);

        assertEq(results.length, 1);
        uint256 value = abi.decode(results[0], (uint256));
        assertEq(value, 42);
    }

    function test_supportsStaticcallModeThroughExecutor() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestDelegateTarget delegateTarget = new TestDelegateTarget();

        bytes memory callData = abi.encodeWithSignature("getNumber()");
        bytes memory execData = encodeExecution(address(delegateTarget), 0, callData);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        bytes[] memory results = executor.proxyExecute(IERC7579Execution(address(account)), MODE_STATIC, execData);

        uint256 value = abi.decode(results[0], (uint256));
        assertEq(value, 42);

        assertEq(delegateTarget.stored(), 0);
    }

    function test_revertsWhenSendingValueWithDelegateOrStaticMode() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestDelegateTarget delegateTarget = new TestDelegateTarget();

        bytes memory callData = abi.encodeWithSignature("getNumber()");

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        // Delegate calls don't parse value from execution data (format: abi.encodePacked(target, calldata))
        // so we only test staticcall value validation
        bytes memory execStatic = encodeExecution(address(delegateTarget), 1, callData);
        vm.expectRevert(abi.encodeWithSignature("ValueNotAllowedForCallType(uint8)", CALLTYPE_STATICCALL));
        executor.proxyExecute(IERC7579Execution(address(account)), MODE_STATIC, execStatic);
    }

    // ============================================
    // HOOK MODULE TESTS
    // ============================================

    function test_invokesHooksInInstallOrder() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestHookModule hookA = new TestHookModule();
        TestHookModule hookB = new TestHookModule();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hookA), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hookB), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.recordLogs();
        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        // Expected order: hookA.pre -> hookB.pre -> execution -> hookA.post -> hookB.post
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 hookPreTopic = keccak256("HookPre(address,address,uint256,bytes,uint256)");
        bytes32 hookPostTopic = keccak256("HookPost(address,bytes,uint256)");

        address[] memory preOrder = extractEventEmitters(logs, hookPreTopic);
        address[] memory postOrder = extractEventEmitters(logs, hookPostTopic);

        require(preOrder.length == 2, "Should have 2 pre-hook events");
        require(postOrder.length == 2, "Should have 2 post-hook events");
        assertEq(preOrder[0], address(hookA), "First pre-hook should be hookA");
        assertEq(preOrder[1], address(hookB), "Second pre-hook should be hookB");
        assertEq(postOrder[0], address(hookA), "First post-hook should be hookA");
        assertEq(postOrder[1], address(hookB), "Second post-hook should be hookB");
    }

    // ============================================
    // FALLBACK MODULE TESTS
    // ============================================

    function test_revertsWhenNoFallbackHandlerInstalled() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        // Should revert when calling unknown selector with no fallback handler
        vm.prank(owner);
        // casting to 'bytes4' is safe because hex"deadbeef" is exactly 4 bytes
        // forge-lint: disable-next-line(unsafe-typecast)
        vm.expectRevert(abi.encodeWithSignature("FallbackNotConfigured(bytes4)", bytes4(hex"deadbeef")));
        (bool success,) = address(account).call(hex"deadbeef");
        assertFalse(success, "Call should revert");
    }

    function test_delegatesFallbackCallsToInstalledHandler() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes4 selector = 0x12345678;
        bytes memory initData = abi.encodePacked(selector);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), initData);

        vm.recordLogs();
        vm.prank(owner);
        (bool success,) = address(account).call(abi.encodePacked(selector));
        assertTrue(success);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 fallbackTopic = keccak256("FallbackHandled(address,address,bytes,uint256)");

        (bool foundEvent, uint256 logIndex) = findEventInLogs(logs, fallbackTopic);
        assertTrue(foundEvent, "FallbackHandled event not found");
        assertEq(logs[logIndex].emitter, address(fallbackModule), "Event should be emitted by fallback module");
    }

    function test_supportsMultipleFallbackHandlersForDifferentSelectors() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestFallbackModule fallbackModule2 = new TestFallbackModule();

        bytes4 selector1 = 0x11111111;
        bytes4 selector2 = 0x22222222;

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector1));
        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule2), abi.encodePacked(selector2));

        assertEq(account.getFallbackHandler(selector1), address(fallbackModule));
        assertEq(account.getFallbackHandler(selector2), address(fallbackModule2));

        vm.prank(owner);
        (bool success1,) = address(account).call(abi.encodePacked(selector1));
        assertTrue(success1);

        vm.prank(owner);
        (bool success2,) = address(account).call(abi.encodePacked(selector2));
        assertTrue(success2);
    }

    function test_preventsInstallingSameSelectorTwice() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestFallbackModule fallbackModule2 = new TestFallbackModule();

        bytes4 selector = 0x12345678;

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("FallbackAlreadySet(bytes4)", selector));
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule2), abi.encodePacked(selector));
    }

    function test_allowsReplacingFallbackHandlerAfterUninstalling() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        TestFallbackModule fallbackModule2 = new TestFallbackModule();

        bytes4 selector = 0x12345678;

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector));
        assertEq(account.getFallbackHandler(selector), address(fallbackModule));

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector));
        assertEq(account.getFallbackHandler(selector), address(0));

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule2), abi.encodePacked(selector));
        assertEq(account.getFallbackHandler(selector), address(fallbackModule2));
    }

    function test_revertsOnUninstallWithWrongSelector() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes4 selector1 = 0x12345678;
        bytes4 selector2 = 0x87654321;

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector1));

        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSignature(
                "FallbackMismatch(bytes4,address,address)", selector2, address(0), address(fallbackModule)
            )
        );
        account.uninstallModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector2));
    }

    function test_passesERC2771OriginalSenderCorrectly() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes4 selector = 0x12345678;

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), abi.encodePacked(selector));

        vm.recordLogs();
        vm.prank(owner);
        (bool success,) = address(account).call(abi.encodePacked(selector));
        assertTrue(success);

        // Event signature: FallbackHandled(address indexed account, address indexed caller, bytes data, uint256 value)
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 fallbackTopic = keccak256("FallbackHandled(address,address,bytes,uint256)");

        (bool foundEvent, uint256 logIndex) = findEventInLogs(logs, fallbackTopic);
        assertTrue(foundEvent, "FallbackHandled event not found");

        // Decode the indexed caller parameter (topics[2])
        address caller = address(uint160(uint256(logs[logIndex].topics[2])));
        assertEq(caller, owner, "Caller should be the original sender");
    }

    // ============================================
    // REFERENCE BASELINE MODULE TESTS
    // ============================================

    function test_ownerValidatorModuleValidatesSignatures() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit ModuleInstalled(MODULE_TYPE_VALIDATOR, address(ownerValidator));
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), initData);

        UserOpHelpers.UserOperation memory userOp = UserOpHelpers.createUserOp(address(account), 0);
        userOp = UserOpHelpers.signUserOp(vm, userOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory packed = UserOpHelpers.packUserOp(userOp);
        bytes32 userOpHash = UserOpHelpers.getUserOpHash(userOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);
        assertEq(validation, VALIDATION_SUCCESS);
    }

    function test_ownerValidatorModuleAllowsOwnerRotation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner, uint256 moduleSignerKey) = createAccountOwner();

        bytes memory initData = abi.encode(moduleSigner);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(ownerValidator), initData);

        (address newSigner, uint256 newSignerKey) = createAccountOwner();
        bytes memory rotateCalldata = abi.encodeWithSignature("updateOwner(address)", newSigner);
        bytes memory execData = encodeExecution(address(ownerValidator), 0, rotateCalldata);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, execData);

        assertEq(ownerValidator.ownerOf(address(account)), newSigner);

        // Old signer should fail validation
        UserOpHelpers.UserOperation memory oldUserOp = UserOpHelpers.createUserOp(address(account), 0);
        oldUserOp = UserOpHelpers.signUserOp(vm, oldUserOp, moduleSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory oldPacked = UserOpHelpers.packUserOp(oldUserOp);
        bytes32 oldHash = UserOpHelpers.getUserOpHash(oldUserOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 oldValidation = account.validateUserOp(oldPacked, oldHash, 0);
        assertEq(oldValidation, VALIDATION_FAILED);

        // New signer should succeed
        UserOpHelpers.UserOperation memory newUserOp = UserOpHelpers.createUserOp(address(account), 0);
        newUserOp = UserOpHelpers.signUserOp(vm, newUserOp, newSignerKey, address(entryPoint), chainId);

        PackedUserOperation memory newPacked = UserOpHelpers.packUserOp(newUserOp);
        bytes32 newHash = UserOpHelpers.getUserOpHash(newUserOp, address(entryPoint), chainId);

        vm.prank(address(entryPoint));
        uint256 newValidation = account.validateUserOp(newPacked, newHash, 0);
        assertEq(newValidation, VALIDATION_SUCCESS);
    }

    function test_directCallExecutorModuleRoutesExecutions() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(directCallExecutor), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);
        bytes memory executorCall = abi.encodeWithSignature("execute(bytes32,bytes)", MODE_DEFAULT, execPayload);
        bytes memory outerExec = encodeExecution(address(directCallExecutor), 0, executorCall);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, outerExec);

        assertEq(counter.counters(address(account)), 1);
        assertTrue(directCallExecutor.isInstalled(address(account)));
    }

    function test_activityLogHookModuleTracksExecutions() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(directCallExecutor), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(activityLogHook), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, callData);
        bytes memory executorCall = abi.encodeWithSignature("execute(bytes32,bytes)", MODE_DEFAULT, execPayload);
        bytes memory outerExec = encodeExecution(address(directCallExecutor), 0, executorCall);

        vm.prank(owner);
        account.execute(MODE_DEFAULT, outerExec);

        // Hook invoked twice: outer execute + inner execute
        assertEq(activityLogHook.invocationCount(address(account)), 2);
    }

    // ============================================
    // MODULE ENUMERATION TESTS
    // ============================================

    function test_getModuleCountTracksValidatorCountCorrectly() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        TestValidatorModule validator1 = new TestValidatorModule();
        TestValidatorModule validator2 = new TestValidatorModule();

        bytes memory initData = abi.encode(moduleSigner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), initData);
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 2);

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator1), "");
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1); // One remains
    }

    function test_getInstalledModulesReturnsAllInstalledValidators() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        TestValidatorModule validator1 = new TestValidatorModule();
        TestValidatorModule validator2 = new TestValidatorModule();

        bytes memory initData = abi.encode(moduleSigner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), initData);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);

        address[] memory validators = account.getInstalledModules(MODULE_TYPE_VALIDATOR);
        assertEq(validators.length, 2);

        bool foundValidator1 = false;
        bool foundValidator2 = false;
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == address(validator1)) foundValidator1 = true;
            if (validators[i] == address(validator2)) foundValidator2 = true;
        }
        assertTrue(foundValidator1);
        assertTrue(foundValidator2);
    }

    function test_getInstalledModulesReturnsAllInstalledExecutors() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        address[] memory executors = account.getInstalledModules(MODULE_TYPE_EXECUTOR);
        assertEq(executors.length, 1);
        assertEq(executors[0], address(executor));
    }

    function test_getInstalledModulesReturnsAllInstalledHooks() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook), "");

        address[] memory hooks = account.getInstalledModules(MODULE_TYPE_HOOK);
        assertEq(hooks.length, 1);
        assertEq(hooks[0], address(hook));
    }

    function test_getInstalledModulesUpdatesAfterModuleRemoval() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        TestValidatorModule validator1 = new TestValidatorModule();
        TestValidatorModule validator2 = new TestValidatorModule();

        bytes memory initData = abi.encode(moduleSigner);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), initData);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), initData);

        address[] memory validators = account.getInstalledModules(MODULE_TYPE_VALIDATOR);
        assertEq(validators.length, 2);

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator1), "");

        validators = account.getInstalledModules(MODULE_TYPE_VALIDATOR);
        assertEq(validators.length, 1);
        assertEq(validators[0], address(validator2));
    }

    function test_getFallbackHandlerReturnsTheInstalledFallbackHandler() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes4 selector = 0x12345678;
        bytes memory initData = abi.encodePacked(selector);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), initData);

        assertEq(account.getFallbackHandler(selector), address(fallbackModule));
    }

    function test_getFallbackHandlerReturnsZeroAddressAfterUninstalling() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes4 selector = 0x12345678;
        bytes memory initData = abi.encodePacked(selector);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), initData);
        assertEq(account.getFallbackHandler(selector), address(fallbackModule));

        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_FALLBACK, address(fallbackModule), initData);
        assertEq(account.getFallbackHandler(selector), address(0));
    }

    function test_enumerationFunctionsWorkWithMixedModuleTypes() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();

        bytes memory validatorInitData = abi.encode(moduleSigner);
        bytes4 fallbackSelector = 0x12345678;
        bytes memory fallbackInitData = abi.encodePacked(fallbackSelector);

        // Install all module types
        vm.prank(owner);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator), validatorInitData);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook), "");
        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), fallbackInitData);

        // Verify counts
        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1);
        assertEq(account.getModuleCount(MODULE_TYPE_EXECUTOR), 1);
        assertEq(account.getModuleCount(MODULE_TYPE_HOOK), 1);

        // Verify installed modules
        address[] memory validators = account.getInstalledModules(MODULE_TYPE_VALIDATOR);
        address[] memory executors = account.getInstalledModules(MODULE_TYPE_EXECUTOR);
        address[] memory hooks = account.getInstalledModules(MODULE_TYPE_HOOK);

        assertEq(validators.length, 1);
        assertEq(validators[0], address(validator));
        assertEq(executors.length, 1);
        assertEq(executors[0], address(executor));
        assertEq(hooks.length, 1);
        assertEq(hooks[0], address(hook));

        // Verify fallback handler
        assertEq(account.getFallbackHandler(fallbackSelector), address(fallbackModule));
    }

    // ============================================
    // ERC-165 INTERFACE SUPPORT TESTS
    // ============================================

    function test_supportsAllRequiredInterfaces() public {
        (ModularSmartAccount account,,) = setupAccount();

        assertTrue(account.supportsInterface(INTERFACE_ID_ERC165)); // ERC-165
        assertTrue(account.supportsInterface(INTERFACE_ID_ERC1271)); // ERC-1271

        // IERC7579AccountConfig
        bytes4 accountIdSelector = bytes4(keccak256("accountId()"));
        bytes4 supportsExecutionModeSelector = bytes4(keccak256("supportsExecutionMode(bytes32)"));
        bytes4 supportsModuleSelector = bytes4(keccak256("supportsModule(uint256)"));
        bytes4 accountConfigId = accountIdSelector ^ supportsExecutionModeSelector ^ supportsModuleSelector;
        assertTrue(account.supportsInterface(accountConfigId));

        // IERC7579ModuleConfig
        bytes4 installSelector = bytes4(keccak256("installModule(uint256,address,bytes)"));
        bytes4 uninstallSelector = bytes4(keccak256("uninstallModule(uint256,address,bytes)"));
        bytes4 isInstalledSelector = bytes4(keccak256("isModuleInstalled(uint256,address,bytes)"));
        bytes4 moduleConfigId = installSelector ^ uninstallSelector ^ isInstalledSelector;
        assertTrue(account.supportsInterface(moduleConfigId));

        // IERC7579Execution
        bytes4 executeSelector = bytes4(keccak256("execute(bytes32,bytes)"));
        bytes4 executeFromExecutorSelector = bytes4(keccak256("executeFromExecutor(bytes32,bytes)"));
        bytes4 executionId = executeSelector ^ executeFromExecutorSelector;
        assertTrue(account.supportsInterface(executionId));
    }

    function test_rejectsUnsupportedInterfaces() public {
        (ModularSmartAccount account,,) = setupAccount();

        assertFalse(account.supportsInterface(0xffffffff));
        assertFalse(account.supportsInterface(0x00000000));
        assertFalse(account.supportsInterface(0xdeadbeef));
    }

    // ============================================
    // HOOK ENFORCEMENT TESTS (Standard ERC-7579 Behavior)
    // ============================================

    function test_transactionRevertsWhenPreCheckHookReverts() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        RevertingHookModule revertingPreHook = new RevertingHookModule(true, false);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(revertingPreHook), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("HookPreCheckAlwaysFails()"));
        account.execute(MODE_DEFAULT, execData);

        // Execution should have reverted, counter not incremented
        assertEq(counter.counters(address(account)), 0);
    }

    function test_transactionRevertsWhenPostCheckHookReverts() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        RevertingHookModule revertingPostHook = new RevertingHookModule(false, true);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(revertingPostHook), "");

        bytes memory callData = abi.encodeWithSignature("count()");
        bytes memory execData = encodeExecution(address(counter), 0, callData);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("HookPostCheckAlwaysFails()"));
        account.execute(MODE_DEFAULT, execData);

        // Execution reverted, counter not incremented
        assertEq(counter.counters(address(account)), 0);
    }

    function test_canUninstallBuggyHookEvenWhenItReverts() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        RevertingHookModule revertingPreHook = new RevertingHookModule(true, false);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(revertingPreHook), "");

        assertEq(account.getModuleCount(MODULE_TYPE_HOOK), 1);

        // Module lifecycle calls don't trigger hooks, so buggy hook can be uninstalled
        vm.prank(owner);
        account.uninstallModule(MODULE_TYPE_HOOK, address(revertingPreHook), "");

        assertEq(account.getModuleCount(MODULE_TYPE_HOOK), 0);
    }

    // ============================================
    // ERC-7484 MODULE REGISTRY INTEGRATION TESTS
    // ============================================

    function test_modulesInstallNormallyWithoutRegistryConfigured() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        // No registry configured
        assertEq(account.getModuleRegistry(), address(0));

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        assertTrue(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
    }

    function test_ownerCanConfigureModuleRegistry() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        MockERC7484Registry registry = new MockERC7484Registry();

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit ModularSmartAccount.ModuleRegistryConfigured(address(registry));
        account.configureModuleRegistry(address(registry));

        assertEq(account.getModuleRegistry(), address(registry));
    }

    function test_ownerCanConfigureAttestersAndThreshold() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        address attester1 = address(0x1111);
        address attester2 = address(0x2222);
        address[] memory attesters = new address[](2);
        attesters[0] = attester1;
        attesters[1] = attester2;
        uint8 threshold = 2;

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit ModularSmartAccount.AttestersConfigured(attesters, threshold);
        account.configureAttesters(attesters, threshold);

        (address[] memory storedAttesters, uint8 storedThreshold) = account.getAttesters();
        assertEq(storedAttesters.length, 2);
        assertEq(storedAttesters[0], attester1);
        assertEq(storedAttesters[1], attester2);
        assertEq(storedThreshold, 2);
    }

    // ============================================
    // FUZZ TESTS
    // ============================================

    function testFuzz_multipleValidatorsCanBeInstalledAndRemoved(uint8 numValidators) public {
        vm.assume(numValidators > 0 && numValidators <= 10);

        (ModularSmartAccount account,, address owner) = setupAccount();
        (address moduleSigner,) = createAccountOwner();
        bytes memory initData = abi.encode(moduleSigner);

        TestValidatorModule[] memory validators = new TestValidatorModule[](numValidators);
        for (uint256 i = 0; i < numValidators; i++) {
            validators[i] = new TestValidatorModule();
            vm.prank(owner);
            account.installModule(MODULE_TYPE_VALIDATOR, address(validators[i]), initData);
        }

        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), numValidators);

        // Remove all but one (must keep at least one validator)
        for (uint256 i = 0; i < numValidators - 1; i++) {
            vm.prank(owner);
            account.uninstallModule(MODULE_TYPE_VALIDATOR, address(validators[i]), "");
        }

        assertEq(account.getModuleCount(MODULE_TYPE_VALIDATOR), 1);
    }

    function testFuzz_fallbackHandlerWorksWithArbitrarySelectors(bytes4 selector) public {
        vm.assume(!isReservedSelector(selector)); // Avoid collisions with reserved selectors

        (ModularSmartAccount account,, address owner) = setupAccount();

        bytes memory initData = abi.encodePacked(selector);
        vm.prank(owner);
        account.installModule(MODULE_TYPE_FALLBACK, address(fallbackModule), initData);

        assertEq(account.getFallbackHandler(selector), address(fallbackModule));

        vm.prank(owner);
        (bool success,) = address(account).call(abi.encodePacked(selector));
        assertTrue(success);
    }

    function testFuzz_executionWithVariousValues(uint96 value) public {
        vm.assume(value > 0 && value < 1 ether);

        (ModularSmartAccount account,, address owner) = setupAccount();

        fund(address(account), TEN_ETH);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");

        address recipient = address(0x9999);
        uint256 accountBalanceBefore = address(account).balance;
        uint256 recipientBalanceBefore = recipient.balance;

        bytes memory execData = encodeExecution(recipient, value, "");
        executor.proxyExecute(IERC7579Execution(address(account)), MODE_DEFAULT, execData);

        assertEq(recipient.balance, recipientBalanceBefore + value, "Recipient should receive exact value");
        assertEq(address(account).balance, accountBalanceBefore - value, "Account should decrease by exact value");
    }

    function testFuzz_moduleInstallationWithVariousInitData(bytes memory initData) public {
        vm.assume(initData.length <= 1024); // Reasonable size limit

        (ModularSmartAccount account,, address owner) = setupAccount();

        vm.prank(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), initData);

        vm.prank(owner);
        account.installModule(MODULE_TYPE_HOOK, address(hook), initData);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(hook), ""));
    }

    // ============================================
    // EXECUTE USER OP TESTS
    // ============================================

    function test_executeUserOpCallsExecuteViaDelegatecall() public {
        (ModularSmartAccount account,,) = setupAccount();
        fund(address(account), 1 ether);

        bytes memory counterCallData = abi.encodeWithSignature("count()");
        bytes memory execPayload = encodeExecution(address(counter), 0, counterCallData);
        bytes memory executeCallData = abi.encodeWithSignature("execute(bytes32,bytes)", MODE_DEFAULT, execPayload);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(
                bytes4(keccak256("executeUserOp(PackedUserOperation,bytes32)")), executeCallData
            ),
            accountGasLimits: bytes32(uint256(200000) << 128 | 200000),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei),
            paymasterAndData: "",
            signature: ""
        });

        vm.prank(address(entryPoint));
        account.executeUserOp(userOp, bytes32(0));

        assertEq(counter.counters(address(account)), 1); // Delegatecall executed
    }

    function test_executeUserOpRevertsIfNotCalledByEntryPoint() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(
                bytes4(keccak256("executeUserOp(PackedUserOperation,bytes32)")),
                abi.encodeWithSignature("execute(bytes32,bytes)", MODE_DEFAULT, "")
            ),
            accountGasLimits: bytes32(uint256(200000) << 128 | 200000),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei),
            paymasterAndData: "",
            signature: ""
        });

        // Should revert when called by non-EntryPoint address
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("NotFromEntryPoint()"));
        account.executeUserOp(userOp, bytes32(0));
    }

    // ============================================
    // UUPS UPGRADE TESTS
    // ============================================

    function test_ownerCanUpgradeImplementation() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);

        vm.prank(owner);
        account.upgradeToAndCall(address(newImplementation), "");

        assertEq(account.owner(), owner, "Owner should be preserved after upgrade");
    }

    function test_upgradePreservesOwnerStorage() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);

        vm.prank(owner);
        account.upgradeToAndCall(address(newImplementation), "");

        assertEq(account.owner(), owner, "Owner storage should be preserved after upgrade");
    }

    function test_preventsNonOwnerFromUpgrading() public {
        (ModularSmartAccount account,,) = setupAccount();
        address attacker = createAddress();

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        account.upgradeToAndCall(address(newImplementation), "");
    }

    function test_upgradeToAndCallExecutesInitializerData() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        ModularSmartAccount newImplementation = new ModularSmartAccount(entryPoint);
        bytes memory data = "";

        vm.prank(owner);
        account.upgradeToAndCall(address(newImplementation), data);

        assertEq(account.owner(), owner, "Owner should be preserved after upgrade with empty data");
    }

    // ============================================
    // ERC-721 TOKEN RECEIVING TESTS
    // ============================================

    function test_canReceiveERC721Token() public {
        (ModularSmartAccount account,,) = setupAccount();

        address nftContract = address(0x721);
        address from = address(0x123);
        uint256 tokenId = 42;

        bytes4 response = account.onERC721Received(nftContract, from, tokenId, "");

        assertEq(response, IERC721Receiver.onERC721Received.selector, "Should return ERC721 selector");
        assertEq(response, bytes4(0x150b7a02), "Should return ERC721 magic value");
    }

    // ============================================
    // ERC-1155 TOKEN RECEIVING TESTS
    // ============================================

    function test_canReceiveERC1155SingleToken() public {
        (ModularSmartAccount account,,) = setupAccount();

        address operator = address(0x1155);
        address from = address(0x123);
        uint256 tokenId = 1;
        uint256 amount = 100;

        bytes4 response = account.onERC1155Received(operator, from, tokenId, amount, "");

        assertEq(response, IERC1155Receiver.onERC1155Received.selector, "Should return ERC1155 single selector");
        assertEq(response, bytes4(0xf23a6e61), "Should return ERC1155 single magic value");
    }

    function test_canReceiveERC1155BatchTokens() public {
        (ModularSmartAccount account,,) = setupAccount();

        address operator = address(0x1155);
        address from = address(0x123);
        uint256[] memory tokenIds = new uint256[](3);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokenIds[2] = 3;
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 10;
        amounts[1] = 20;
        amounts[2] = 30;

        bytes4 response = account.onERC1155BatchReceived(operator, from, tokenIds, amounts, "");

        assertEq(response, IERC1155Receiver.onERC1155BatchReceived.selector, "Should return ERC1155 batch selector");
        assertEq(response, bytes4(0xbc197c81), "Should return ERC1155 batch magic value");
    }

    // ============================================
    // NATIVE ETH RECEIVING TESTS
    // ============================================

    function test_canReceiveNativeETH() public {
        (ModularSmartAccount account,,) = setupAccount();

        uint256 balanceBefore = address(account).balance;
        uint256 sendAmount = 1 ether;

        (bool success,) = address(account).call{value: sendAmount}("");
        assertTrue(success, "ETH transfer should succeed");

        assertEq(address(account).balance, balanceBefore + sendAmount, "Balance should increase by send amount");
    }

    function test_receiveETHViaTransfer() public {
        (ModularSmartAccount account,,) = setupAccount();
        address sender = createAddress();
        fund(sender, 10 ether);

        uint256 balanceBefore = address(account).balance;

        vm.prank(sender);
        payable(address(account)).transfer(2 ether);

        assertEq(address(account).balance, balanceBefore + 2 ether, "Balance should increase by transfer amount");
    }

    function test_receiveETHViaSend() public {
        (ModularSmartAccount account,,) = setupAccount();
        address sender = createAddress();
        fund(sender, 10 ether);

        vm.prank(sender);
        bool success = payable(address(account)).send(1 ether);
        assertTrue(success, "ETH send should succeed");
    }

    // ============================================
    // FUZZ TESTS
    // ============================================

    function testFuzz_canReceiveArbitraryETHAmounts(uint96 amount) public {
        vm.assume(amount > 0 && amount < 100 ether);

        (ModularSmartAccount account,,) = setupAccount();

        (bool success,) = address(account).call{value: amount}("");
        assertTrue(success, "ETH transfer should succeed");
        assertEq(address(account).balance, amount, "Balance should match sent amount");
    }
}
