/*
 * DSH-BATCH-01 (spec ^req-17, audit Medium): BATCH-mode all-or-nothing deny enforcement.
 *
 * PROPERTY (no partial acceptance):
 *   In BATCH mode, preCheck loops over the decoded sub-calls and invokes _checkCall on each
 *   (src/hooks/DefaultSecurityHook.sol, CALLTYPE_BATCH branch). A revert in ANY iteration
 *   aborts the whole call. Therefore:
 *     (1) if ANY sub-call is a deny violation, the WHOLE batch reverts (a bad sub-call can
 *         never slip through by being batched with clean sub-calls); and
 *     (2) a batch whose sub-calls are ALL allowlisted-clean returns without revert.
 *
 * TARGET / LOOP:
 *   The aggregation is the loop `for (i) { (t,v,d)=getExecution(pointers,i); _checkCall(t,v,d); }`.
 *   The harness `checkBatch(Call[])` is a faithful replica of that loop body: it calls the SAME
 *   internal `_checkCall` per element. This isolates the all-or-nothing revert aggregation
 *   (the ^req-17 claim) from LibERC7579's calldata-pointer decoding, which is a decoder concern.
 *   loop_iter=3 fully unrolls the N=2 batches used here.
 *
 * VIOLATION MODELED:  a SELF-CALL to a non-allowlisted target. _checkCall reverts at
 *   `if (target == msg.sender) revert SelfCallNotAllowed()` BEFORE the _isModule probe, so the
 *   revert is deterministic and independent of the _isModule summary.
 * CLEAN MODELED:      an allowlisted target with allSelectorsAllowed. _checkCall returns at the
 *   first branch `if (entry.allowed) { if (allSelectorsAllowed) return; }`, also before _isModule.
 *
 * TAUTOLOGY CHECK: postconditions assert the aggregate revert / return outcome of checkBatch
 *   (lastReverted / !lastReverted). They do NOT recompute the per-call deny checks. Observable.
 *
 * REACHABILITY (mandatory): rule cleanBatchReturns_witness `satisfy`s a fully-clean 2-element
 *   batch that returns (non-vacuous); the deny rules assert on batches whose clean element
 *   proves the reverting element is not the only reachable configuration.
 *
 * MODELING (TCB-disclosed):
 *   - _isModule's low-level staticcall to target.isModuleType is an unresolved external call;
 *     summarized NONDET. SOUND and in fact never reached on the paths these rules exercise
 *     (both the self-call violation and the allowlisted-clean path short-circuit earlier).
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function checkBatch(DefaultSecurityHookBatchHarness.Call[] calls) external;
    function h_allowed(address account, address target) external returns (bool) envfree;
    function h_allSelectorsAllowed(address account, address target) external returns (bool) envfree;

    // _isModule staticcall to arbitrary target: unresolved -> NONDET (sound; unreached here).
    function _.isModuleType(uint256) external => NONDET;
}

/*
 * MAIN PROPERTY (DSH-BATCH-01): no partial acceptance.
 * A 2-element batch: one element is a clean allowlisted call, the other is a self-call to a
 * non-allowlisted target (a deny violation). Whichever position (bad in {0,1}) the violation
 * occupies, the WHOLE checkBatch must revert. A bad sub-call cannot slip through by batching.
 */
rule anyBadSubcallRevertsWholeBatch(uint256 bad) {
    env e;
    address account = e.msg.sender;

    DefaultSecurityHookBatchHarness.Call[] calls;
    require calls.length == 2;
    require bad < 2;
    uint256 good = bad == 0 ? 1 : 0;

    // The clean element: an allowlisted target with all selectors allowed (returns immediately).
    address cleanTarget = calls[good].target;
    require cleanTarget != account;                       // not a self-call
    require h_allowed(account, cleanTarget);
    require h_allSelectorsAllowed(account, cleanTarget);

    // The bad element: a self-call to a NON-allowlisted target (reverts: SelfCallNotAllowed).
    require calls[bad].target == account;
    require !h_allowed(account, account);

    checkBatch@withrevert(e, calls);

    assert lastReverted,
        "a deny-violating sub-call slipped through by being batched with a clean sub-call";
}

/*
 * CLEAN-BATCH RETURN (converse) + REACHABILITY WITNESS.
 * A 2-element batch where BOTH sub-calls are allowlisted-clean must be able to return
 * without reverting. `satisfy` proves this state is reachable (non-vacuous), simultaneously
 * establishing the converse: an all-clean batch is NOT forced to revert.
 */
rule cleanBatchReturns_witness {
    env e;
    address account = e.msg.sender;

    DefaultSecurityHookBatchHarness.Call[] calls;
    require calls.length == 2;

    address t0 = calls[0].target;
    address t1 = calls[1].target;
    require t0 != account && t1 != account;              // no self-calls
    require h_allowed(account, t0) && h_allSelectorsAllowed(account, t0);
    require h_allowed(account, t1) && h_allSelectorsAllowed(account, t1);

    checkBatch@withrevert(e, calls);

    satisfy !lastReverted;
}
