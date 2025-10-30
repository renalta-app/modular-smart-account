// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccountFactory} from "../../contracts/accounts/ModularSmartAccountFactory.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @title ModularSmartAccountFactoryTest
/// @notice Test suite for ModularSmartAccountFactory deterministic account deployment
contract ModularSmartAccountFactoryTest is ModularAccountTestBase {
    ModularSmartAccountFactory public factory;
    IEntryPoint public entryPoint = IEntryPoint(ENTRYPOINT_V08);
    address public owner;
    address public randomCaller;

    function setUp() public {
        (owner,) = createAccountOwner();
        (randomCaller,) = createAccountOwner();

        fund(randomCaller, 1 ether);

        factory = new ModularSmartAccountFactory(entryPoint);
    }

    /// @notice Test factory deploys with correct entryPoint
    /// @dev Verifies the factory's account implementation references the correct entryPoint
    function test_deployWithCorrectEntryPoint() public {
        ModularSmartAccount implementation = factory.ACCOUNT_IMPLEMENTATION();
        assertEq(address(implementation.entryPoint()), address(entryPoint), "EntryPoint mismatch");
    }

    // Note: senderCreator is not exposed as a public getter on the factory

    /// @notice Test create account from any caller (not just senderCreator)
    function test_createAccountFromAnyCaller() public {
        uint256 salt = 0;

        vm.prank(randomCaller);
        factory.createAccount(owner, salt);
    }

    /// @notice Test deployer can create account and emits event
    function test_deployerCanCreateAccountAndEmitsEvent() public {
        uint256 salt = 0;
        address predictedAddress = factory.getAddress(owner, salt);

        vm.expectEmit(true, true, true, false);
        emit AccountCreated(predictedAddress, owner, salt);

        ModularSmartAccount accountContract = factory.createAccount(owner, salt);
        address accountAddr = address(accountContract);

        assertTrue(accountAddr.code.length > 0, "Account should have code");
        assertEq(accountAddr, predictedAddress, "Account address should match prediction");
    }

    // Event declaration for expectEmit
    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    /// @notice Test createAccount is idempotent
    function test_createAccountIsIdempotent() public {
        uint256 salt = 42;

        factory.createAccount(owner, salt);
        address addr1 = factory.getAddress(owner, salt);

        factory.createAccount(owner, salt);
        address addr2 = factory.getAddress(owner, salt);

        assertEq(addr1, addr2, "Address should be same on repeated calls");
    }

    /// @notice Test account created at deterministic address
    function test_createAccountAtDeterministicAddress() public {
        uint256 salt = 123;
        address predictedAddress = factory.getAddress(owner, salt);

        assertEq(predictedAddress.code.length, 0, "Address should have no code before deployment");

        factory.createAccount(owner, salt);

        assertTrue(predictedAddress.code.length > 0, "Address should have code after deployment");
    }

    /// @notice Test account initialized with correct owner
    function test_initializeAccountWithCorrectOwner() public {
        uint256 salt = 456;
        factory.createAccount(owner, salt);

        address accountAddress = factory.getAddress(owner, salt);
        ModularSmartAccount account = ModularSmartAccount(payable(accountAddress));

        assertEq(account.owner(), owner, "Owner should be set correctly");
    }

    /// @notice Test different salts create different accounts
    function test_differentSaltsCreateDifferentAccounts() public {
        uint256 salt1 = 100;
        uint256 salt2 = 200;

        factory.createAccount(owner, salt1);
        factory.createAccount(owner, salt2);

        address addr1 = factory.getAddress(owner, salt1);
        address addr2 = factory.getAddress(owner, salt2);

        assertNotEq(addr1, addr2, "Different salts should produce different addresses");
    }

    /// @notice Test different owners create different accounts
    function test_differentOwnersCreateDifferentAccounts() public {
        address owner2 = createAddress();
        uint256 salt = 0;

        factory.createAccount(owner, salt);
        factory.createAccount(owner2, salt);

        address addr1 = factory.getAddress(owner, salt);
        address addr2 = factory.getAddress(owner2, salt);

        assertNotEq(addr1, addr2, "Different owners should produce different addresses");
    }

    /// @notice Test getAddress returns same address before and after deployment
    function test_getAddressConsistentBeforeAndAfterDeployment() public {
        uint256 salt = 789;
        address addressBefore = factory.getAddress(owner, salt);

        factory.createAccount(owner, salt);

        address addressAfter = factory.getAddress(owner, salt);
        assertEq(addressBefore, addressAfter, "getAddress should be consistent before and after deployment");
    }

    /// @notice Test getInitCode returns valid initCode
    function test_getInitCodeReturnsValidInitCode() public {
        uint256 salt = 111;
        bytes memory initCode = factory.getInitCode(owner, salt);

        assertTrue(initCode.length >= 24, "InitCode too short");

        bytes memory expected = abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner, salt)));
        assertEq(keccak256(initCode), keccak256(expected), "InitCode structure mismatch");
    }

    /// @notice Test initCode factory address matches
    function test_initCodeFactoryAddressMatches() public {
        uint256 salt = 222;
        bytes memory initCode = factory.getInitCode(owner, salt);

        address factoryAddressFromInitCode;
        assembly {
            factoryAddressFromInitCode := mload(add(initCode, 20))
        }
        assertEq(factoryAddressFromInitCode, address(factory), "Factory address in initCode mismatch");
    }

    /// @notice Fuzz test: getAddress is deterministic for same inputs
    function testFuzz_getAddressIsDeterministic(address _owner, uint256 salt) public {
        address addr1 = factory.getAddress(_owner, salt);
        address addr2 = factory.getAddress(_owner, salt);

        assertEq(addr1, addr2, "getAddress should be deterministic");
    }

    /// @notice Fuzz test: different salts always produce different addresses
    function testFuzz_differentSaltsProduceDifferentAddresses(address _owner, uint256 salt1, uint256 salt2) public {
        vm.assume(salt1 != salt2);

        address addr1 = factory.getAddress(_owner, salt1);
        address addr2 = factory.getAddress(_owner, salt2);

        assertNotEq(addr1, addr2, "Different salts should produce different addresses");
    }

    /// @notice Fuzz test: different owners always produce different addresses
    function testFuzz_differentOwnersProduceDifferentAddresses(address owner1, address owner2, uint256 salt) public {
        vm.assume(owner1 != owner2);

        address addr1 = factory.getAddress(owner1, salt);
        address addr2 = factory.getAddress(owner2, salt);

        assertNotEq(addr1, addr2, "Different owners should produce different addresses");
    }

    /// @notice Fuzz test: createAccount is always idempotent
    function testFuzz_createAccountIsIdempotent(address _owner, uint256 salt) public {
        vm.assume(_owner != address(0));

        factory.createAccount(_owner, salt);
        address addr1 = factory.getAddress(_owner, salt);

        factory.createAccount(_owner, salt);
        address addr2 = factory.getAddress(_owner, salt);

        assertEq(addr1, addr2, "Address should be same on repeated calls");
    }
}
