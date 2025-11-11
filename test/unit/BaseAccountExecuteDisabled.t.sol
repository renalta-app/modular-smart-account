// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ModularAccountTestBase} from "../helpers/TestBase.sol";
import {ModularSmartAccount} from "../../contracts/accounts/ModularSmartAccount.sol";
import {BaseAccount} from "../../contracts/core/BaseAccount.sol";

/// @title BaseAccountExecuteDisabledTest
/// @notice Verifies BaseAccount.execute() and executeBatch() are disabled to prevent hook bypass
contract BaseAccountExecuteDisabledTest is ModularAccountTestBase {
    bytes4 constant BASE_ACCOUNT_EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 constant BASE_ACCOUNT_EXECUTE_BATCH_SELECTOR = 0x47e1da2a;

    /// @dev BaseAccount.execute(address,uint256,bytes) must revert from owner
    function test_baseAccountExecute_revertsFromOwner() public {
        (ModularSmartAccount account,, address owner) = setupAccount();
        address recipient = createAddress();

        vm.prank(owner);
        (bool success, bytes memory returnData) =
            address(account).call(abi.encodeWithSelector(BASE_ACCOUNT_EXECUTE_SELECTOR, recipient, 0, ""));
        assertFalse(success, "Call should have failed");
        assertEq(
            string(returnData),
            string(abi.encodeWithSignature("Error(string)", "ModularSmartAccount: use execute(bytes32,bytes)"))
        );
    }

    /// @dev BaseAccount.execute(address,uint256,bytes) must revert even from EntryPoint
    function test_baseAccountExecute_revertsFromEntryPoint() public {
        (ModularSmartAccount account,,) = setupAccount();
        address recipient = createAddress();

        vm.prank(ENTRYPOINT_V08);
        (bool success, bytes memory returnData) =
            address(account).call(abi.encodeWithSelector(BASE_ACCOUNT_EXECUTE_SELECTOR, recipient, 0, ""));
        assertFalse(success, "Call should have failed");
        assertEq(
            string(returnData),
            string(abi.encodeWithSignature("Error(string)", "ModularSmartAccount: use execute(bytes32,bytes)"))
        );
    }

    /// @dev BaseAccount.executeBatch(Call[]) must revert from owner
    function test_baseAccountExecuteBatch_revertsFromOwner() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        BaseAccount.Call[] memory calls = new BaseAccount.Call[](1);
        calls[0] = BaseAccount.Call({target: createAddress(), value: 0, data: ""});

        vm.prank(owner);
        (bool success,) = address(account).call(abi.encodeWithSelector(BASE_ACCOUNT_EXECUTE_BATCH_SELECTOR, calls));
        assertFalse(success, "Call should have failed");
    }

    /// @dev BaseAccount.executeBatch(Call[]) must revert even from EntryPoint
    function test_baseAccountExecuteBatch_revertsFromEntryPoint() public {
        (ModularSmartAccount account,,) = setupAccount();

        BaseAccount.Call[] memory calls = new BaseAccount.Call[](1);
        calls[0] = BaseAccount.Call({target: createAddress(), value: 0, data: ""});

        vm.prank(ENTRYPOINT_V08);
        (bool success,) = address(account).call(abi.encodeWithSelector(BASE_ACCOUNT_EXECUTE_BATCH_SELECTOR, calls));
        assertFalse(success, "Call should have failed");
    }
}
