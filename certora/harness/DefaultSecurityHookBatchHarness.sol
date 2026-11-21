// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";

/// @notice Certora harness for the DSH-BATCH-01 (spec ^req-17) all-or-nothing BATCH property.
/// Dedicated to that property to stay decoupled from the shared DefaultSecurityHookHarness.
///
/// `checkBatch` is a faithful replica of the production BATCH branch of `preCheck`:
///     for (i) { (t,v,d) = getExecution(pointers,i); _checkCall(t,v,d); }
/// The loop body is the SAME internal `_checkCall` the production code invokes per decoded
/// pointer, so the all-or-nothing revert AGGREGATION is the real code. This isolates that
/// aggregation from LibERC7579's calldata-pointer decoding (a decoder concern, not ^req-17).
/// A revert in any iteration aborts the whole call, exactly as production.
/// @author taek <leekt216@gmail.com>
contract DefaultSecurityHookBatchHarness is DefaultSecurityHook {
    /// @notice A single sub-call of a BATCH execution.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Replica of the production CALLTYPE_BATCH loop over `_checkCall`.
    function checkBatch(Call[] calldata calls) external view {
        for (uint256 i; i < calls.length; i++) {
            _checkCall(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    // ---- read-only accessors into AllowlistEntry (mapping members are not auto-exposed) ----

    function h_allowed(address account, address target) external view returns (bool) {
        return allowlist[account][target].allowed;
    }

    function h_allSelectorsAllowed(address account, address target) external view returns (bool) {
        return allowlist[account][target].allSelectorsAllowed;
    }
}
