/*
 * TL-LIFECYCLE-01: the inert-proposal state machine cannot be short-circuited.
 *
 * Target: src/policies/TimelockPolicy.sol
 *   _handleProposalExecutionInternal  status gate :253 ("if status!=Pending return FAILED"),
 *                                     epoch gate :256, set Executed :259, return window :263
 *   cancelProposal                    status gate :161-163 (revert ProposalNotPending),
 *                                     set Cancelled :165
 *
 * The four observable sub-claims (all state-machine safety over multi-call sequences):
 *   (a) execution validates for the timelock window ONLY from status==Pending AND matching
 *       epoch; from None/Executed/Cancelled (or epoch mismatch) it returns FAILED and does
 *       NOT change the status.
 *   (b) execution moves Pending->Executed exactly once: a re-submitted identical userOp then
 *       returns FAILED (no double-execution).
 *   (c) cancelProposal acts ONLY on status==Pending — it reverts ProposalNotPending on any
 *       other status — and on success moves Pending->Cancelled.
 *   (d) a Cancelled proposal can never be executed and an Executed proposal can never be
 *       cancelled (no resurrection).
 *
 * TAUTOLOGY CHECK: every postcondition reads the OBSERVABLE result — the raw status enum via
 *   statusOf (a real `proposals` mapping read on the same key), the FAILED return sentinel (1),
 *   and the revert outcome of cancelProposal. No rule re-derives the status-enum arithmetic or
 *   re-runs a gate; the harness setters only PLANT pre-state, the transitions run the real
 *   internal/external functions. Observable, not tautological.
 *
 * REACHABILITY (mandatory, non-vacuity): rules reach_PendingToExecuted and
 *   reach_PendingToCancelled are `satisfy` witnesses proving both legitimate live transitions
 *   are actually reachable — the direct, sound evidence that the "never double-execute / never
 *   resurrect" claims are not vacuously true. (Note: Certora `basic` per-rule sanity's vacuity
 *   heuristic conservatively flags the assert-rules below, because it havocs the external
 *   `execUserOp` / `cancelProposal` calls in its vacuity variant and cannot then see a live
 *   non-reverting path — most obviously for the two `assert lastReverted` must-revert rules,
 *   where by design NO non-reverting path exists. The `satisfy` rules are the authoritative
 *   non-vacuity proof; sanity stays enabled and is not disabled to mask this.)
 *
 * MODELING (TCB-disclosed):
 *   - Same storage slot across execute/cancel/read is pinned by fixing ONE (account, callData,
 *     nonce) triple; keccak256 injectivity is assumed via optimistic_hashing (the real key and
 *     the harness read both compute keccak256(abi.encode(account, keccak256(callData), nonce))
 *     — identical inputs => identical slot). callData length is bounded to hashing_length_bound;
 *     the key is a hash, so one representative length is fully general. No ECDSA involved.
 *   - execUserOp calls the REAL internal _handleProposalExecutionInternal directly with a
 *     calldata PackedUserOperation (no memory->calldata self-hop); the userOp's sender/callData/
 *     nonce are constrained to the planted proposal's key.
 *   - Compiled WITH solc --via-ir (see .conf). The DSH-STALE-01 legacy-codegen decision was
 *     specifically to dodge a via-ir mis-modeling of a struct-EMBEDDED mapping (AllowlistEntry
 *     had `mapping(bytes4=>bool) selectors` co-located with a `bytes4[]`, and the clear-loop
 *     write did not alias reads). That hazard does NOT apply here: the `Proposal` struct has NO
 *     mapping members — only scalar fields (status, validAfter, validUntil, epoch) — so there is
 *     no in-struct-mapping aliasing to mis-model. Legacy codegen additionally cannot compile
 *     this contract (stack-too-deep in _handleProposalCreationInternal), so via-ir is required.
 *     The Foundry BTT suite independently confirms the impl on real EVM semantics.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function cancelProposal(bytes32 id, address account, bytes callData, uint256 nonce) external;
    function execUserOp(bytes32 id, TimelockPolicyHarness.PackedUserOperation userOp, address account) external returns (uint256);
    function statusOf(bytes32 id, address wallet, address account, bytes callData, uint256 nonce) external returns (uint8) envfree;
    function epochOf(bytes32 id, address wallet, address account, bytes callData, uint256 nonce) external returns (uint256) envfree;
    function initConfig(bytes32 id, address wallet, uint48 delay, uint48 expirationPeriod, address guardian, uint256 epoch) external envfree;
    function plantProposal(bytes32 id, address wallet, address account, bytes callData, uint256 nonce, uint8 status, uint48 validAfter, uint48 validUntil, uint256 epoch) external envfree;
    function currentEpoch(bytes32, address) external returns (uint256) envfree;
}

// ProposalStatus enum ordinals (src/policies/TimelockPolicy.sol:43-48) and the ERC-4337
// failure sentinel (SIG_VALIDATION_FAILED_UINT = 1). Literals, no envfree indirection.
definition ST_NONE()      returns uint8 = 0;
definition ST_PENDING()   returns uint8 = 1;
definition ST_EXECUTED()  returns uint8 = 2;
definition ST_CANCELLED() returns uint8 = 3;
definition FAILED()       returns uint256 = 1;

// Install config with a definite current epoch, and plant an arbitrary starting proposal.
function setup(bytes32 id, address wallet, address account, bytes callData, uint256 nonce,
              uint8 status, uint48 va, uint48 vu, uint256 propEpoch, uint256 curEpoch) {
    require callData.length <= 32;         // keep keccak within hashing_length_bound (key is a hash)
    require status <= ST_CANCELLED();      // real enum universe {None,Pending,Executed,Cancelled}
    initConfig(id, wallet, 1, 1, 0, curEpoch);
    plantProposal(id, wallet, account, callData, nonce, status, va, vu, propEpoch);
}

// Build a PackedUserOperation whose derived key targets the planted proposal (sender=account,
// same callData, same nonce). Returns the exec result of the REAL internal handler.
function execFor(env e, bytes32 id, address account, bytes callData, uint256 nonce) returns uint256 {
    TimelockPolicyHarness.PackedUserOperation userOp;
    require userOp.sender == account;
    require userOp.callData == callData;   // identical bytes => identical keccak(callData) => same slot key
    require userOp.nonce == nonce;
    return execUserOp(e, id, userOp, account);
}

/* ---------------------------------------------------------------------------------------------
 * (a) EXECUTION VALIDATES ONLY FROM Pending + MATCHING EPOCH.
 * If (status != Pending) OR (epoch != currentEpoch), execUserOp returns FAILED and leaves the
 * status unchanged. The Pending+match success case is covered positively in rule (b).
 * ------------------------------------------------------------------------------------------- */
rule execValidatesOnlyFromPendingMatchingEpoch(
    bytes32 id, address account, bytes callData, uint256 nonce,
    uint8 status, uint48 va, uint48 vu, uint256 propEpoch, uint256 curEpoch
) {
    env e;
    setup(id, account, account, callData, nonce, status, va, vu, propEpoch, curEpoch);
    require status != ST_PENDING() || propEpoch != curEpoch;   // the "should not validate" universe

    uint8 before = statusOf(id, account, account, callData, nonce);
    uint256 result = execFor(e, id, account, callData, nonce);
    uint8 after = statusOf(id, account, account, callData, nonce);

    assert result == FAILED(),
        "execution validated (non-FAILED) from a non-Pending or epoch-mismatched proposal";
    assert after == before,
        "execution changed proposal status despite not being executable";
}

/* ---------------------------------------------------------------------------------------------
 * (b) EXECUTE-ONCE: Pending + matching epoch -> Executed, success; a second identical execUserOp
 * returns FAILED (no double-execution).
 * ------------------------------------------------------------------------------------------- */
rule executeOncePendingToExecuted(
    bytes32 id, address account, bytes callData, uint256 nonce, uint48 va, uint48 vu, uint256 epoch
) {
    env e1;
    env e2;
    setup(id, account, account, callData, nonce, ST_PENDING(), va, vu, epoch, epoch);

    uint256 r1 = execFor(e1, id, account, callData, nonce);
    uint8 mid = statusOf(id, account, account, callData, nonce);

    assert r1 != FAILED(), "first execution of a live Pending proposal failed";
    assert mid == ST_EXECUTED(), "first execution did not move Pending -> Executed";

    uint256 r2 = execFor(e2, id, account, callData, nonce);
    uint8 fin = statusOf(id, account, account, callData, nonce);

    assert r2 == FAILED(), "second execution of the same userOp validated -> DOUBLE EXECUTION";
    assert fin == ST_EXECUTED(), "status left Executed after a rejected second execution";
}

/* ---------------------------------------------------------------------------------------------
 * (c) CANCEL ONLY FROM Pending.
 * ------------------------------------------------------------------------------------------- */
rule cancelRevertsUnlessPending(
    bytes32 id, address account, bytes callData, uint256 nonce,
    uint8 status, uint48 va, uint48 vu, uint256 propEpoch, uint256 curEpoch
) {
    env e;
    require e.msg.sender == account;   // account is authorized to cancel
    require e.msg.value == 0;
    setup(id, account, account, callData, nonce, status, va, vu, propEpoch, curEpoch);
    require status != ST_PENDING();

    cancelProposal@withrevert(e, id, account, callData, nonce);

    assert lastReverted,
        "cancelProposal succeeded on a non-Pending proposal (should revert ProposalNotPending)";
}

rule cancelPendingToCancelled(
    bytes32 id, address account, bytes callData, uint256 nonce,
    uint48 va, uint48 vu, uint256 propEpoch, uint256 curEpoch
) {
    env e;
    require e.msg.sender == account;
    require e.msg.value == 0;
    setup(id, account, account, callData, nonce, ST_PENDING(), va, vu, propEpoch, curEpoch);

    cancelProposal@withrevert(e, id, account, callData, nonce);
    bool reverted = lastReverted;
    uint8 after = statusOf(id, account, account, callData, nonce);

    assert !reverted, "cancel of a Pending proposal by the account reverted";
    assert after == ST_CANCELLED(), "cancel did not move Pending -> Cancelled";
}

/* ---------------------------------------------------------------------------------------------
 * (d) NO RESURRECTION.
 * ------------------------------------------------------------------------------------------- */
rule cancelledNeverExecutes(
    bytes32 id, address account, bytes callData, uint256 nonce, uint48 va, uint48 vu, uint256 epoch
) {
    env e;
    setup(id, account, account, callData, nonce, ST_CANCELLED(), va, vu, epoch, epoch);  // even with epoch match

    uint256 result = execFor(e, id, account, callData, nonce);
    uint8 after = statusOf(id, account, account, callData, nonce);

    assert result == FAILED(), "a Cancelled proposal validated for execution";
    assert after == ST_CANCELLED(), "a Cancelled proposal transitioned out of Cancelled";
}

rule executedNeverCancels(
    bytes32 id, address account, bytes callData, uint256 nonce,
    uint48 va, uint48 vu, uint256 propEpoch, uint256 curEpoch
) {
    env e;
    require e.msg.sender == account;
    require e.msg.value == 0;
    setup(id, account, account, callData, nonce, ST_EXECUTED(), va, vu, propEpoch, curEpoch);

    cancelProposal@withrevert(e, id, account, callData, nonce);

    assert lastReverted, "an Executed proposal was cancelled (should revert ProposalNotPending)";
}

/* ---------------------------------------------------------------------------------------------
 * REACHABILITY WITNESSES (mandatory, non-vacuity). Both legitimate live transitions reachable.
 * ------------------------------------------------------------------------------------------- */
rule reach_PendingToExecuted(
    bytes32 id, address account, bytes callData, uint256 nonce, uint48 va, uint48 vu, uint256 epoch
) {
    env e;
    setup(id, account, account, callData, nonce, ST_PENDING(), va, vu, epoch, epoch);
    uint256 result = execFor(e, id, account, callData, nonce);
    satisfy result != FAILED()
        && statusOf(id, account, account, callData, nonce) == ST_EXECUTED();
}

rule reach_PendingToCancelled(
    bytes32 id, address account, bytes callData, uint256 nonce, uint48 va, uint48 vu, uint256 epoch
) {
    env e;
    require e.msg.sender == account;
    require e.msg.value == 0;
    setup(id, account, account, callData, nonce, ST_PENDING(), va, vu, epoch, epoch);
    cancelProposal(e, id, account, callData, nonce);
    satisfy statusOf(id, account, account, callData, nonce) == ST_CANCELLED();
}
