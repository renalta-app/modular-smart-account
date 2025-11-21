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
        vm.expectRevert(ModularSmartAccount.DirectExecuteDisabled.selector);
        account.execute(recipient, 0, "");
    }

    /// @dev BaseAccount.execute(address,uint256,bytes) must revert even from EntryPoint
    function test_baseAccountExecute_revertsFromEntryPoint() public {
        (ModularSmartAccount account,,) = setupAccount();
        address recipient = createAddress();

        vm.prank(ENTRYPOINT_V08);
        vm.expectRevert(ModularSmartAccount.DirectExecuteDisabled.selector);
        account.execute(recipient, 0, "");
    }

    /// @dev BaseAccount.executeBatch(Call[]) must revert from owner
    function test_baseAccountExecuteBatch_revertsFromOwner() public {
        (ModularSmartAccount account,, address owner) = setupAccount();

        BaseAccount.Call[] memory calls = new BaseAccount.Call[](1);
        calls[0] = BaseAccount.Call({target: createAddress(), value: 0, data: ""});

        vm.prank(owner);
        vm.expectRevert(ModularSmartAccount.DirectExecuteBatchDisabled.selector);
        account.executeBatch(calls);
    }

    /// @dev BaseAccount.executeBatch(Call[]) must revert even from EntryPoint
    function test_baseAccountExecuteBatch_revertsFromEntryPoint() public {
        (ModularSmartAccount account,,) = setupAccount();

        BaseAccount.Call[] memory calls = new BaseAccount.Call[](1);
        calls[0] = BaseAccount.Call({target: createAddress(), value: 0, data: ""});

        vm.prank(ENTRYPOINT_V08);
        vm.expectRevert(ModularSmartAccount.DirectExecuteBatchDisabled.selector);
        account.executeBatch(calls);
    }
}
