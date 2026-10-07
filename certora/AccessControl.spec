/*
 * AC-01 (audit Low, raised in FV as a signature-gating access-control invariant):
 *   validateUserOp returns a success validationData (i.e. NOT SIG_VALIDATION_FAILED_UINT)
 *   ONLY IF the address recovered from userOp.signature over toEthSignedMessageHash(userOpHash)
 *   is a CURRENT guardian for the calling kernel (guardian[recovered][msg.sender].weight != 0).
 *
 * Equivalently: any userOp whose signature does NOT recover to an enabled guardian yields
 * SIG_VALIDATION_FAILED_UINT, regardless of proposal.status (Approved), getApproval.passed,
 * or paymasterAndData contents. There is NO signature-less success path.
 *
 * Target : src/validators/WeightedECDSAValidator.sol:204-272
 * Success return sites:
 *   - Ongoing branch  (line 259): gated by `passed && guardian[signer][sender].weight != 0`
 *                                  where signer = recover(toEthSignedMessageHash(userOpHash), lastSig) (line 248)
 *   - Approved/passed branch (line 268): gated by `guardian[signer][sender].weight != 0`
 *                                  where signer = recover(toEthSignedMessageHash(userOpHash), userOp.signature) (line 265)
 * Pre-fix bug: the Approved/paymaster sub-branch returned VALID with NO signature recovery.
 *
 * MODELING (TCB-disclosed):
 *   - ECDSA.recover(bytes32,bytes memory)  -> uninterpreted `recoverGhost(hash)`.
 *   - ECDSA.toEthSignedMessageHash(bytes32) -> uninterpreted `ethHashGhost(userOpHash)`.
 *   - getApproval(...)                      -> NONDET (attacker gets `passed` and `totalWeight`
 *                                              for free; SOUND over-approximation, and removes
 *                                              the unbounded guardian linked-list loop).
 *   recoverGhost is keyed on the *hash* argument only. This is sound for THIS property: the
 *   success gate depends solely on recover over toEthSignedMessageHash(userOpHash); collapsing
 *   distinct-signature-same-hash recoveries can only shrink the reachable state, never hide a
 *   success-with-non-guardian state (which is driven by the userOpHash recovery alone).
 *
 * TAUTOLOGY CHECK: the postcondition asserts an access-control OUTCOME (success => the
 *   userOpHash signer is an enabled guardian). It does not recompute recover or the weight
 *   lookup; it reads guardian weight and compares the return code. Observable, not tautological.
 *
 * REACHABILITY: two witness rules below prove (i) success IS reachable on the Approved branch
 *   with a real guardian signer (non-vacuous), and (ii) the exact pre-fix bypass
 *   (paymasterAndData set, signature recovering to a non-guardian) now returns FAILED.
 *
 * @author taek <leekt216@gmail.com>
 */

using WeightedECDSAValidatorHarness as v;

methods {
    function weightOf(address, address) external returns (uint24) envfree;

    // Uninterpreted ECDSA.recover: deterministic per message hash.
    function ECDSA.recover(bytes32 hash, bytes memory) internal returns (address) => recoverGhost(hash);
    // Uninterpreted EIP-191 prefixing: deterministic per raw hash.
    function ECDSA.toEthSignedMessageHash(bytes32 h) internal returns (bytes32) => ethHashGhost(h);
    // EIP-712 typed-data hashing for the Approve struct hash (Ongoing loop only). NONDET is
    // sound: those recoveries feed the getApproval-independent vote tally, never the final gate.
    function _.toEthSignedMessageHash(bytes32 h) external => ethHashGhost(h) expect bytes32;

    // Guardian linked-list tally: fully symbolic (attacker-favourable). Removes the loop.
    function getApproval(address, bytes32) external returns (uint256, bool) => NONDET;
}

ghost recoverGhost(bytes32) returns address;
ghost ethHashGhost(bytes32) returns bytes32;

definition FAILED() returns uint256 = 1; // SIG_VALIDATION_FAILED_UINT

/*
 * MAIN PROPERTY.
 * If validateUserOp does NOT return FAILED, then the signer recovered from userOp.signature
 * over toEthSignedMessageHash(userOpHash) is a current guardian of the calling kernel.
 * Covers BOTH success branches (Ongoing line 259 and Approved/passed line 268) and every
 * value of proposal.status / passed / paymasterAndData, because the assertion is on the
 * return value irrespective of which branch produced it.
 */
rule successImpliesGuardianSigned(env e, WeightedECDSAValidator.PackedUserOperation userOp, bytes32 userOpHash) {
    uint256 ret = v.validateUserOp(e, userOp, userOpHash);

    address recovered = recoverGhost(ethHashGhost(userOpHash));

    assert ret != FAILED() => weightOf(recovered, e.msg.sender) != 0,
        "validateUserOp returned success but the userOpHash signer is not a current guardian";
}

/*
 * REACHABILITY WITNESS (i) -- success is reachable (non-vacuous).
 * A userOp on the Approved branch whose signature recovers to a real guardian CAN succeed.
 * Stated as a violated `assert false` under satisfiable preconditions: if the tool finds a
 * model, success-with-guardian is reachable.
 */
rule successReachableWithGuardian(env e, WeightedECDSAValidator.PackedUserOperation userOp, bytes32 userOpHash) {
    address recovered = recoverGhost(ethHashGhost(userOpHash));
    // recovered is an enabled guardian
    require weightOf(recovered, e.msg.sender) != 0;

    uint256 ret = v.validateUserOp(e, userOp, userOpHash);

    satisfy ret != FAILED();
}

/*
 * REACHABILITY WITNESS (ii) -- the exact pre-fix bypass is now BLOCKED.
 * paymasterAndData is set and the signature recovers to a NON-guardian; the call must FAIL.
 * (This is a specialization of the main rule pinned to the pre-fix exploit shape, kept
 * separate so the counterexample, if any, isolates the paymaster path.)
 */
rule paymasterNonGuardianFails(env e, WeightedECDSAValidator.PackedUserOperation userOp, bytes32 userOpHash) {
    require userOp.paymasterAndData.length != 0;                 // paymaster-sponsored
    address recovered = recoverGhost(ethHashGhost(userOpHash));
    require weightOf(recovered, e.msg.sender) == 0;              // signer is NOT a guardian

    uint256 ret = v.validateUserOp(e, userOp, userOpHash);

    assert ret == FAILED(),
        "paymaster-sponsored op with non-guardian signature returned success (pre-fix bypass)";
}
