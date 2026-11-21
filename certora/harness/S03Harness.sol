// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";

/// @notice Dedicated Certora harness for the S-03 uninstall/reinstall stale-state property.
/// Follows the S01Harness pattern (kept separate to avoid file collisions). Exposes only
/// observable reads of storage that CVL cannot reach through the struct-embedded mapping;
/// it does NOT reimplement any clear logic.
/// @author taek <leekt216@gmail.com>
contract S03Harness is DefaultSecurityHook {
    /// @notice Number of tracked targets for an account (observable read of allowlistedTargets).
    function allowlistedTargetsLength(address account) external view returns (uint256) {
        return allowlistedTargets[account].length;
    }

    /// @notice True iff the (account,target) allowlist entry is pristine: not allowed,
    /// no all-selectors flag, no tracked selectors, and the specific selector unset.
    /// Lets the spec pin a clean freshly-initialized start state — CVL cannot see the
    /// in-struct mapping, so pre-state cleanliness is asserted through this observable read.
    /// It does NOT recompute the clear loop; it only READS the four observable fields.
    function entryPristine(address account, address target, bytes4 selector) external view returns (bool) {
        AllowlistEntry storage entry = allowlist[account][target];
        return
            !entry.allowed && !entry.allSelectorsAllowed && entry.selectorList.length == 0 && !entry.selectors[selector];
    }
}
