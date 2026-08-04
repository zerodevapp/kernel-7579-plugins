// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";

/// @notice Certora harness for DefaultSecurityHook.
/// Exposes the internal, view `_checkCall` as an external entrypoint so the
/// allowlist-gating property (DSH-ALLOW-01) can assert the observable revert/success
/// outcome directly, without routing through preCheck's calldata-decoding assembly
/// and LibERC7579 machinery.
///
/// The `_isModule` internal probe is summarized in the spec (see methods block) so the
/// module branch is deterministic; here we only surface `_checkCall` and read-only
/// accessors into the AllowlistEntry struct (its mapping member is not auto-exposed).
/// @author taek <leekt216@gmail.com>
contract DefaultSecurityHookHarness is DefaultSecurityHook {
    /// @notice External, reverting wrapper over the internal view `_checkCall`.
    /// msg.sender here is the account (matches `_checkCall`'s use of msg.sender).
    /// The spec constrains the leading 4 bytes of `data` to a blocked selector.
    function checkCall(address target, uint256 value, bytes calldata data) external view {
        _checkCall(target, value, data);
    }

    /// @notice The leading-4-byte selector of `data`, exactly as `_checkCall` reads it
    /// (`bytes4(data[:4])`). Lets the spec obtain the selector value CVL cannot slice,
    /// and query the allowlist mapping with the SAME key `_checkCall` uses. This is a
    /// calldata slice, not a reimplementation of blocked-set membership.
    function selOf(bytes calldata data) external pure returns (bytes4) {
        return bytes4(data[:4]);
    }

    // ---- read-only accessors into AllowlistEntry (mapping member not auto-exposed) ----

    function h_allowed(address account, address target) external view returns (bool) {
        return allowlist[account][target].allowed;
    }

    function h_allSelectorsAllowed(address account, address target) external view returns (bool) {
        return allowlist[account][target].allSelectorsAllowed;
    }

    function h_selectorMapped(address account, address target, bytes4 selector) external view returns (bool) {
        return allowlist[account][target].selectors[selector];
    }
}
