/*
 * S-03 (audit regression, uninstall/reinstall stale-state): onUninstall clears ALL
 * per-account allowlist state so no stale entry survives a reinstall roundtrip.
 *
 * PROPERTY:
 *   For an initialized account with a non-trivial allowlist covering BOTH branches of
 *   _setAllowlist:
 *     - target t1 with a real selector s1 (allSelectorsAllowed=false, selectorList=[s1])
 *     - target t2 with empty selectors (allSelectorsAllowed=true)
 *   after onUninstall():
 *     isAllowlisted(account, t1)            == false
 *     isAllowlisted(account, t2)            == false
 *     isSelectorAllowed(account, t1, s1)    == false
 *     isSelectorAllowed(account, t2, ANY)   == false
 *     allowlistedTargetsLength(account)     == 0
 *   and a subsequent onInstall() with empty data (reinstall) must NOT re-expose any prior
 *   selector: the same view reads stay false.
 *
 * Target : src/hooks/DefaultSecurityHook.sol
 *   onUninstall  (clear loop over allowlistedTargets + delete + initialized=false)
 *   _clearAllowlist (zeroes selectors mapping, deletes selectorList, allowed/all=false)
 *   isAllowlisted / isSelectorAllowed (observable view reads)
 *   allowlistedTargets (observable length read via harness)
 *
 * TAUTOLOGY CHECK: the postcondition reads observable view outputs (isAllowlisted,
 *   isSelectorAllowed) and the allowlistedTargets length. It never re-runs the clear loop
 *   nor recomputes _clearAllowlist / selectorList zeroing. Observable, not tautological.
 *
 * REACHABILITY: rules s03_prestate_reachable and s03_post_read_reachable prove the
 *   non-trivial pre-state (both branches populated, initialized) and the post-uninstall
 *   observable read are actually reachable. satisfy => non-vacuous.
 *
 * MODELING (TCB-disclosed):
 *   - solc 0.8.30, LEGACY codegen (solc_via_ir OFF, see .conf). The via-ir + optimizer
 *     pipeline mis-models the struct-embedded `mapping(bytes4=>bool) selectors` co-located
 *     with `bytes4[] selectorList`, producing spurious CEs (same shape as DSH-STALE-01).
 *     Legacy codegen models this storage layout correctly.
 *   - Pre-state cleanliness pinned via entryPristine (observable READ, not a clear-loop
 *     recompute), because CVL cannot read the in-struct mapping directly.
 *   - loop_iter=2: allowlistedTargets bounded at 2 targets, each selectorList at <=1.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function onInstall(bytes data) external;
    function onUninstall(bytes data) external;
    function setAllowlist(address target, bytes4[] selectors) external;
    function isInitialized(address account) external returns (bool) envfree;
    function isAllowlisted(address account, address target) external returns (bool) envfree;
    function isSelectorAllowed(address account, address target, bytes4 selector) external returns (bool) envfree;
    function allowlistedTargetsLength(address account) external returns (uint256) envfree;
    function entryPristine(address account, address target, bytes4 selector) external returns (bool) envfree;
}

/*
 * Sets up a non-trivial two-target allowlist for `account` covering both _setAllowlist
 * branches, starting from a pristine uninitialized account. Returns nothing; leaves the
 * hook installed with t1=[s1] and t2=all-selectors.
 */
function setupTwoTargets(env eInstall, env eSet1, env eSet2, address account,
                         address t1, bytes4 s1, address t2) {
    // same account performs install + both sets
    require eInstall.msg.sender == account;
    require eSet1.msg.sender == account;
    require eSet2.msg.sender == account;

    // pristine, uninitialized start (BOTH targets must start clean so both
    // _setAllowlist calls take the push branch -> allowlistedTargets == [t1, t2])
    require !isInitialized(account);
    require entryPristine(account, t1, s1);
    require entryPristine(account, t2, s1);
    require t1 != t2;

    bytes empty;
    require empty.length == 0;
    onInstall(eInstall, empty);   // initialized = true, no configs

    // branch 1: t1 with a real selector s1 (allSelectorsAllowed = false)
    bytes4[] sel1;
    require sel1.length == 1;
    require sel1[0] == s1;
    setAllowlist(eSet1, t1, sel1);

    // branch 2: t2 with empty selectors (allSelectorsAllowed = true)
    bytes4[] sel2;
    require sel2.length == 0;
    setAllowlist(eSet2, t2, sel2);
}

/*
 * MAIN PROPERTY (S-03).
 * After onUninstall, no stale allowlist state survives, and a reinstall does not re-expose
 * any prior selector.
 */
rule noStaleStateAfterUninstallRoundtrip(address t1, bytes4 s1, address t2, bytes4 anySel) {
    env eInstall; env eSet1; env eSet2; env eUninstall; env eReinstall;

    address account = eInstall.msg.sender;
    require eUninstall.msg.sender == account;
    require eReinstall.msg.sender == account;

    setupTwoTargets(eInstall, eSet1, eSet2, account, t1, s1, t2);

    // Pre-state is actually populated (setup, not the fix under test). Pinning the
    // tracked-target count to the concrete post-setup value (both pushes taken) tames the
    // Prover's havoc of the mapping(address=>address[]) length so the onUninstall loop
    // iterates over the real [t1, t2]. s03_prestate_reachable is a satisfy-witness proving
    // allowlistedTargetsLength==2 with both targets allowlisted IS reachable -> not vacuous.
    require isAllowlisted(account, t1);
    require isAllowlisted(account, t2);
    require allowlistedTargetsLength(account) == 2;

    bytes empty;
    require empty.length == 0;
    onUninstall(eUninstall, empty);

    // OBSERVABLE post-uninstall reads (not a recompute of _clearAllowlist).
    assert isAllowlisted(account, t1) == false, "t1 remained allowlisted after uninstall";
    assert isAllowlisted(account, t2) == false, "t2 remained allowlisted after uninstall";
    assert isSelectorAllowed(account, t1, s1) == false, "s1 stayed permitted on t1 after uninstall";
    assert isSelectorAllowed(account, t2, anySel) == false, "t2 still permitted a selector after uninstall";
    assert allowlistedTargetsLength(account) == 0, "allowlistedTargets not emptied after uninstall";

    // reinstall must not re-expose any prior selector
    onInstall(eReinstall, empty);
    assert isAllowlisted(account, t1) == false, "t1 re-exposed after reinstall";
    assert isAllowlisted(account, t2) == false, "t2 re-exposed after reinstall";
    assert isSelectorAllowed(account, t1, s1) == false, "s1 re-exposed on t1 after reinstall";
    assert isSelectorAllowed(account, t2, anySel) == false, "t2 selector re-exposed after reinstall";
}

/*
 * REACHABILITY WITNESS 1 (mandatory): the non-trivial pre-state is reachable — both
 * targets allowlisted with both branches exercised, account initialized.
 */
rule s03_prestate_reachable(address t1, bytes4 s1, address t2) {
    env eInstall; env eSet1; env eSet2;
    address account = eInstall.msg.sender;

    setupTwoTargets(eInstall, eSet1, eSet2, account, t1, s1, t2);

    satisfy isInitialized(account)
        && isAllowlisted(account, t1)
        && isAllowlisted(account, t2)
        && isSelectorAllowed(account, t1, s1)
        && allowlistedTargetsLength(account) == 2;
}

/*
 * REACHABILITY WITNESS 2 (mandatory): the post-uninstall observable read of a formerly-true
 * selector is actually executed (not a dead branch) and yields false.
 */
rule s03_post_read_reachable(address t1, bytes4 s1, address t2) {
    env eInstall; env eSet1; env eSet2; env eUninstall;
    address account = eInstall.msg.sender;
    require eUninstall.msg.sender == account;

    setupTwoTargets(eInstall, eSet1, eSet2, account, t1, s1, t2);
    require isSelectorAllowed(account, t1, s1);  // formerly true

    bytes empty;
    require empty.length == 0;
    onUninstall(eUninstall, empty);

    satisfy isSelectorAllowed(account, t1, s1) == false
        && allowlistedTargetsLength(account) == 0;
}
