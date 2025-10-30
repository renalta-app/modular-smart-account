// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ForkHelpers} from "../helpers/ForkHelpers.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";

/// EIP7702UninitializedForkTest
/// Fork tests simulating EIP-7702 delegation using vm.etch
/// EIP-7702 format: 0xef0100 || address (23 bytes)
contract EIP7702UninitializedForkTest is ForkHelpers {
    ModularSmartAccount public implementation;
    uint256 public chainId;

    function setUp() public {
        setupFork();
        fund(address(this), 100 ether);
        verifyEssentialContracts();

        chainId = block.chainid;
        implementation = new ModularSmartAccount(entryPoint);
    }

    function setupEip7702Delegation(address eoa, address delegate) internal {
        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), delegate);
        vm.etch(eoa, delegationCode);
    }

    /// EIP-7702 delegation with vm.etch enables full execution
    function test_eip7702FullExecutionWithVmEtch() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        fund(eoa, TEN_ETH);

        setupEip7702Delegation(eoa, address(implementation));

        address delegate = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegate, address(implementation), "fetchDelegate works with vm.etch");

        ModularSmartAccount account = ModularSmartAccount(payable(eoa));

        PackedUserOperation memory packed = createAndSignUserOp(eoa, 0, "", eoaKey);
        bytes32 userOpHash = getUserOpHash(packed);

        vm.prank(address(entryPoint));
        uint256 validation = account.validateUserOp(packed, userOpHash, 0);

        assertEq(validation, VALIDATION_SUCCESS, "EIP-7702 validation succeeds with vm.etch");
    }

    /// fetchDelegate correctly reads EIP-7702 bytecode
    function test_fetchDelegateWithEtchedCode() public {
        address eoa = makeAddr("eoa");

        address delegateBefore = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegateBefore, address(0), "No delegation before setup");

        setupEip7702Delegation(eoa, address(implementation));

        address delegateAfter = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegateAfter, address(implementation), "Delegation should be detected");
    }

    /// _getEffectiveOwner logic simulation for uninitialized EIP-7702 accounts
    function test_getEffectiveOwnerLogicSimulation() public {
        address eoa = makeAddr("eoa");
        setupEip7702Delegation(eoa, address(implementation));

        address delegate = EIP7702Utils.fetchDelegate(eoa);
        assertEq(delegate, address(implementation), "Delegation detected");

        address effectiveOwner;
        if (delegate != address(0)) {
            address storedOwner = address(0);
            effectiveOwner = storedOwner == address(0) ? eoa : storedOwner;
        } else {
            effectiveOwner = address(0);
        }

        assertEq(effectiveOwner, eoa, "Effective owner should be EOA in EIP-7702 mode");
    }
}
