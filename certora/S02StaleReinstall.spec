/*
 * S-02 (TOB-2): a proposal created under a PRIOR installation can never validate for execution
 * after a reinstall.
 *
 * Target: src/policies/TimelockPolicy.sol
 *   _policyOninstall            :113  currentEpoch[id][msg.sender]++   (bump on every install)
 *   creation                    :227-232 stamps proposal.epoch = currentEpoch[id][account]
 *   _handleProposalExecutionInternal :256 if (proposal.epoch != currentEpoch) return FAILED
 *
 * PROPERTY (main, genuine trace — NOT a planted epoch):
 *   install(id) [epoch 0->1]  ->  createProposal(triple) [stamps epoch 1]
 *   uninstall(id)  ->  install(id) [reinstall, epoch 1->2]
 *   execUserOp(triple)  ==  FAILED   AND   proposal stays Pending (never Executed).
 * The staleness is produced by the REAL install bump, not by the spec choosing the epoch — so
 * this witnesses the multi-step state machine the audit finding is about.
 *
 * TAUTOLOGY CHECK: the postcondition reads the OBSERVABLE execution return sentinel (FAILED==1)
 *   and the OBSERVABLE proposal status (statusOf on the real mapping). It never recomputes the
 *   epoch counter nor re-runs the :256 gate. The harness install/create/exec paths all run the
 *   REAL contract code (currentEpoch++ and the epoch comparison are the production expressions).
 *   Observable, not tautological.
 *
 * REACHABILITY (mandatory, non-vacuity):
 *   - reach_successWithoutReinstall: WITHOUT a reinstall the same trace EXECUTES successfully
 *     (non-FAILED, status Executed). Proves the failure in the main rule is a real epoch
 *     discriminator, not because execution always fails.
 *   - reach_staleCrossEpochState: the cross-epoch stale state (proposal.epoch < currentEpoch,
 *     status Pending) is actually reachable through the real bump.
 *
 * MODELING (TCB-disclosed):
 *   - solc 0.8.30 via-ir + optimizer (matches production build); Prover rule_sanity=basic.
 *   - One (account, callData, nonce) triple fixed across create/execute/read; keccak injectivity
 *     assumed via optimistic_hashing so all ops hit the same slot. No ECDSA in these paths.
 *   - Install driven through the real PolicyBase.onInstall; the wallet is the harness's
 *     msg.sender (currentEpoch keyed by msg.sender inside _policyOninstall). No unresolved
 *     external calls; no summaries needed.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function install(bytes32 id, bytes config) external;
    function uninstall(bytes32 id, bytes data) external;
    function createProposal(bytes32 id, address account, bytes callData, uint256 nonce, uint48 validAfter, uint48 validUntil) external;
    function execUserOp(bytes32 id, address account, bytes callData, uint256 nonce) external returns (uint256);
    function statusOf(bytes32 id, address wallet, address account, bytes callData, uint256 nonce) external returns (uint8) envfree;
    function epochOf(bytes32 id, address wallet, address account, bytes callData, uint256 nonce) external returns (uint256) envfree;
    function currentEpochOf(bytes32 id, address wallet) external returns (uint256) envfree;
    function isInitialized(bytes32 id, address wallet) external returns (bool) envfree;
    function ST_PENDING() external returns (uint8) envfree;
    function sigFailedSentinel() external returns (uint256) envfree;
}

/* ---------------------------------------------------------------------------------------------
 * MAIN: proposal from a prior installation cannot validate after reinstall.
 *
 * `cfg1`/`cfg2` are symbolic install-config bytes handed to the REAL _policyOninstall. A
 * non-@withrevert call whose config fails a guard (delay/exp/overflow, or the AlreadyInitialized
 * check) is an infeasible path the Prover drops — so the rule reasons only over config bytes for
 * which both installs actually succeed and the epoch really bumped 0->1 then 1->2.
 * ------------------------------------------------------------------------------------------- */
rule staleProposalNeverValidatesAfterReinstall(
    bytes32 id, bytes callData, uint256 nonce, uint48 va, uint48 vu, bytes cfg1, bytes cfg2, bytes ucfg
) {
    env eInstall1; env eCreate; env eUninstall; env eInstall2; env eExec;

    address account = eInstall1.msg.sender;
    // The wallet in currentEpoch/config is keyed by the installer's msg.sender; keep one wallet.
    require eUninstall.msg.sender == account;
    require eInstall2.msg.sender == account;

    // Fresh start: never installed, epoch 0.
    require !isInitialized(id, account);
    require currentEpochOf(id, account) == 0;

    // Install #1: real _policyOninstall bumps epoch 0 -> 1.
    install(eInstall1, id, cfg1);

    // Create a Pending proposal under installation #1 (stamps the real current epoch = 1).
    createProposal(eCreate, id, account, callData, nonce, va, vu);

    // Reinstall: uninstall then install #2 -> real bump 1 -> 2.
    uninstall(eUninstall, id, ucfg);
    install(eInstall2, id, cfg2);

    // The proposal is now stale (epoch 1 != currentEpoch 2).
    uint8 before = statusOf(id, account, account, callData, nonce);
    uint256 result = execUserOp(eExec, id, account, callData, nonce);
    uint8 after = statusOf(id, account, account, callData, nonce);

    assert result == sigFailedSentinel(),
        "a proposal from a prior installation validated for execution after reinstall (TOB-2)";
    assert after == before,
        "execution of a stale proposal changed its status";
}

/* ---------------------------------------------------------------------------------------------
 * REACHABILITY #1 (mandatory): the SUCCESS path is reachable when there is NO reinstall.
 * Same trace minus the reinstall must execute successfully -> the main-rule failure is a genuine
 * epoch discriminator, not universal execution failure.
 * ------------------------------------------------------------------------------------------- */
rule reach_successWithoutReinstall(
    bytes32 id, bytes callData, uint256 nonce, uint48 va, uint48 vu, bytes cfg1
) {
    env eInstall1; env eCreate; env eExec;
    address account = eInstall1.msg.sender;

    require !isInitialized(id, account);
    require currentEpochOf(id, account) == 0;

    install(eInstall1, id, cfg1);
    createProposal(eCreate, id, account, callData, nonce, va, vu);

    uint256 result = execUserOp(eExec, id, account, callData, nonce);

    satisfy result != sigFailedSentinel()
        && statusOf(id, account, account, callData, nonce) != ST_PENDING();
}

/* ---------------------------------------------------------------------------------------------
 * REACHABILITY #2 (mandatory): a genuine cross-epoch stale state is reachable through the real
 * install bump (proposal Pending, its stamped epoch strictly below currentEpoch).
 * ------------------------------------------------------------------------------------------- */
rule reach_staleCrossEpochState(
    bytes32 id, bytes callData, uint256 nonce, uint48 va, uint48 vu, bytes cfg1, bytes cfg2, bytes ucfg
) {
    env eInstall1; env eCreate; env eUninstall; env eInstall2;
    address account = eInstall1.msg.sender;
    require eUninstall.msg.sender == account;
    require eInstall2.msg.sender == account;

    require !isInitialized(id, account);
    require currentEpochOf(id, account) == 0;

    install(eInstall1, id, cfg1);
    createProposal(eCreate, id, account, callData, nonce, va, vu);
    uninstall(eUninstall, id, ucfg);
    install(eInstall2, id, cfg2);

    satisfy statusOf(id, account, account, callData, nonce) == ST_PENDING()
        && epochOf(id, account, account, callData, nonce) < currentEpochOf(id, account);
}
