// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";

/// @notice Dedicated Certora harness for the S-01 stale-selector regression property.
/// Kept separate from the shared DefaultSecurityHookHarness to avoid file collisions.
/// Exposes the internal view `_checkCall` (which keys off msg.sender as the account) and
/// the APPROVE blocked-selector constant.
/// @author taek <leekt216@gmail.com>
contract S01Harness is DefaultSecurityHook {
    /// @notice External wrapper over internal view `_checkCall`; msg.sender is the account.
    function checkCall(address target, uint256 value, bytes calldata data) external view {
        _checkCall(target, value, data);
    }

    /// @notice The ERC-20 approve selector — a blocked selector under _isBlockedSelector.
    function approveSelector() external pure returns (bytes4) {
        return APPROVE;
    }

    /// @notice Leading 4-byte selector of `data` (mirrors `bytes4(data[:4])` in _checkCall).
    /// Lets the spec constrain the selector without CVL calldata slicing.
    function leadingSelector(bytes calldata data) external pure returns (bytes4) {
        return bytes4(data[:4]);
    }

    /// @notice True iff the (account,target) allowlist entry is pristine: not allowed,
    /// no tracked selectors, and the specific selector unset. Lets the spec pin a clean
    /// freshly-initialized start state (the audit scenario) — CVL cannot see the mapping
    /// inside AllowlistEntry, so cleanliness must be asserted through this observable read.
    function entryPristine(address account, address target, bytes4 selector) external view returns (bool) {
        AllowlistEntry storage entry = allowlist[account][target];
        return
            !entry.allowed && !entry.allSelectorsAllowed && entry.selectorList.length == 0 && !entry.selectors[selector];
    }
}
