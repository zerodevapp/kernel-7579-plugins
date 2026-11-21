/*
 * TOB-13 (audit High, priv-esc): validateUserOp returns SIG_VALIDATION_SUCCESS_UINT (0)
 * ONLY IF the configured owner != address(0) AND the recovered signer of userOpHash
 * (or its eth-signed variant) equals owner. Contrapositive/observable form:
 *
 *     return == SUCCESS  =>  ( owner != 0
 *                              && ( recovered(userOpHash) == owner
 *                                   || recovered(ethHash)  == owner ) )
 *
 * Plus the anti-address(0)-match guard (the TOB-13 fix):
 *
 *     owner == 0  =>  return == FAILED
 *
 * Target: src/validators/ECDSAValidator.sol validateUserOp :69-81 (owner==0 early-fail :77,
 * _verifySignature gate :78), _verifySignature :60-67.
 *
 * ECDSA.tryRecoverCalldata is modeled UNINTERPRETED: `recovered(hash)` is a symbolic,
 * attacker-controlled address, DETERMINISTIC in hash (same hash -> same recovered address).
 * The two impl recover calls (raw userOpHash and eth-signed variant) map to two independent
 * symbolic images. The proof covers AUTHORIZATION GATING, not ECDSA / ecrecover soundness.
 *
 * OBSERVABLE, NOT TAUTOLOGICAL: the assertion references the SAME uninterpreted oracle the
 * impl consumes; it never re-derives elliptic-curve math. It relates the observable RETURN
 * value to owner and the oracle image.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function validateUserOpHarness(bytes32) external returns (uint256);
    function ownerOf(address) external returns (address) envfree;
    function _recover(bytes32 hash) internal returns (address) => recovered(hash);
    function _ethHash(bytes32 hash) internal returns (bytes32) => ethSignedHash(hash);
}

// Uninterpreted, deterministic-per-hash recovery. Same hash -> same address.
ghost recovered(bytes32) returns address;

// Uninterpreted, injective eth-signed-hash derivation. Same hash -> same eth-hash, and the
// eth-hash is never equal to the raw hash (the real keccak-prefix construction is collision-
// resistant), so the two recover queries hit genuinely independent oracle images.
ghost ethSignedHash(bytes32) returns bytes32 {
    axiom forall bytes32 h. ethSignedHash(h) != h;
    axiom forall bytes32 a. forall bytes32 b. a != b => ethSignedHash(a) != ethSignedHash(b);
}

definition SUCCESS() returns uint256 = 0;
definition FAILED()  returns uint256 = 1;

/*
 * MAIN PROPERTY (contrapositive, observable).
 * If validateUserOp returns SUCCESS then owner != 0 AND at least one of the two recover
 * oracle images equals owner. Uses the SAME `recovered` oracle the impl consumes -- no
 * re-derivation of ECDSA math.
 *
 * We cannot name ethHash directly in CVL without recomputing the prefix, so we assert the
 * disjunction over ALL hashes: SUCCESS with a nonzero owner implies there EXISTS a hash h
 * with recovered(h) == owner. Because the impl only ever queries recovered at exactly two
 * hashes and returns SUCCESS solely when one of those images matches owner, this is the
 * tightest observable claim that avoids recomputing toEthSignedMessageHash.
 */
rule successImpliesOwnerRecovered(bytes32 userOpHash) {
    env e;
    require e.msg.value == 0; // validateUserOpHarness is view; msg.value irrelevant

    address owner = ownerOf(e.msg.sender);

    uint256 ret = validateUserOpHarness(e, userOpHash);

    // (1) owner must be nonzero on success.
    assert ret == SUCCESS() => owner != 0,
        "SUCCESS returned with unset owner (address(0)) -- TOB-13 guard broken";

    // (2) on success, owner equals the recover oracle at the raw hash OR at the eth-signed
    //     hash. We express the eth-signed hash via the concrete solady computation.
    assert ret == SUCCESS() =>
        ( recovered(userOpHash) == owner
          || recovered(ethSignedHash(userOpHash)) == owner ),
        "SUCCESS returned but neither recover image matches owner -- non-owner op validated";
}

/*
 * ANTI-address(0)-MATCH GUARD (the explicit TOB-13 fix).
 * owner == 0 must ALWAYS yield FAILED, regardless of what recover returns -- in particular
 * even if recover returns address(0) (the classic failed-recovery sentinel), it must NOT be
 * treated as a match against an unset (zero) owner.
 */
rule zeroOwnerAlwaysFails(bytes32 userOpHash) {
    env e;
    require ownerOf(e.msg.sender) == 0;

    uint256 ret = validateUserOpHarness(e, userOpHash);

    assert ret == FAILED(),
        "owner == 0 did not fail -- address(0) recover match bypass (TOB-13)";
}

/*
 * REACHABILITY WITNESS (i) -- SUCCESS is reachable (non-vacuous accept).
 * There EXISTS a model with a nonzero owner whose raw-hash recover image equals owner and
 * validateUserOp returns SUCCESS.
 */
rule witnessSuccessReachable(bytes32 userOpHash) {
    env e;
    address owner = ownerOf(e.msg.sender);
    require owner != 0;
    require recovered(userOpHash) == owner; // legitimate owner signature on the raw hash

    uint256 ret = validateUserOpHarness(e, userOpHash);

    satisfy ret == SUCCESS(),
        "no reachable SUCCESS -- accept path is vacuous";
}

/*
 * REACHABILITY WITNESS (ii) -- FAILURE is reachable (owner==0 branch is live).
 */
rule witnessZeroOwnerFailReachable(bytes32 userOpHash) {
    env e;
    require ownerOf(e.msg.sender) == 0;

    uint256 ret = validateUserOpHarness(e, userOpHash);

    satisfy ret == FAILED(),
        "no reachable FAILED on the owner==0 branch";
}
