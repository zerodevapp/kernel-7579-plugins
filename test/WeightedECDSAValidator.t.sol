// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {WeightedECDSAValidator, WeightedECDSAValidatorV09} from "src/validators/WeightedECDSAValidator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {WeightedThresholdBase} from "src/base/WeightedThresholdBase.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    MODULE_TYPE_VALIDATOR
} from "src/types/Constants.sol";

/// @title WeightedECDSAValidatorTest
/// @notice Unit tests for the guardian multisig validator after the WeightedThresholdBase refactor.
///         WALLET plays the role of the "kernel" — msg.sender for install/validate calls.
///         The validator adopts the signer's split-signature scheme: first N-1 sigs over the EIP712
///         Proposal(id=0) hash (strictly ASCENDING), last sig over the ep-specific final userOp hash.
contract WeightedECDSAValidatorTest is Test {
    WeightedECDSAValidator internal validator;
    IEntryPoint internal ENTRYPOINT;

    address constant WALLET = address(0x1234);

    address[3] internal guardianAddrs;
    uint256[3] internal guardianKeys;

    uint24 constant W1 = 50;
    uint24 constant W2 = 30;
    uint24 constant W3 = 20;
    uint24 constant THRESHOLD = 60; // needs at least two of the three guardians

    string internal domainName = "WeightedECDSAValidator";

    function setUp() public virtual {
        validator = _deploy();
        ENTRYPOINT = EntryPointLib.deploy();

        (address a1, uint256 k1) = makeAddrAndKey("g1");
        (address a2, uint256 k2) = makeAddrAndKey("g2");
        (address a3, uint256 k3) = makeAddrAndKey("g3");

        address[] memory addrs = new address[](3);
        uint256[] memory keys = new uint256[](3);
        addrs[0] = a1;
        addrs[1] = a2;
        addrs[2] = a3;
        keys[0] = k1;
        keys[1] = k2;
        keys[2] = k3;

        // sort ascending by address (guardian0 lowest) so split-signature ordering is easy to reason about
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = 0; j < 2 - i; j++) {
                if (addrs[j] > addrs[j + 1]) {
                    (addrs[j], addrs[j + 1]) = (addrs[j + 1], addrs[j]);
                    (keys[j], keys[j + 1]) = (keys[j + 1], keys[j]);
                }
            }
        }

        guardianAddrs = [addrs[0], addrs[1], addrs[2]];
        guardianKeys = [keys[0], keys[1], keys[2]];
    }

    // ---- variant hooks (V09 subclass overrides these two) ----

    function _deploy() internal virtual returns (WeightedECDSAValidator) {
        return new WeightedECDSAValidator();
    }

    /// @dev The final userOp hash the LAST signature must sign. ep0.7 = eth-signed; ep0.9 = raw.
    function _finalHash(bytes32 userOpHash) internal view virtual returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(userOpHash);
    }

    /// @dev The "wrong" convention (must fail): opposite of _finalHash.
    function _wrongFinalHash(bytes32 userOpHash) internal view virtual returns (bytes32) {
        return userOpHash;
    }

    // ============ helpers ============

    function _weights() internal pure returns (uint24[] memory weights) {
        weights = new uint24[](3);
        weights[0] = W1;
        weights[1] = W2;
        weights[2] = W3;
    }

    function _guardians() internal view returns (address[] memory guardians) {
        guardians = new address[](3);
        guardians[0] = guardianAddrs[0];
        guardians[1] = guardianAddrs[1];
        guardians[2] = guardianAddrs[2];
    }

    function _installData() internal view returns (bytes memory) {
        return abi.encode(_guardians(), _weights(), THRESHOLD);
    }

    function _install() internal {
        vm.prank(WALLET);
        validator.onInstall(_installData());
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(domainName)),
                keccak256("0.0.4"),
                block.chainid,
                address(validator)
            )
        );
    }

    function _proposalHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(),
                keccak256(
                    abi.encode(
                        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                        userOp.sender,
                        bytes32(0),
                        keccak256(userOp.callData),
                        userOp.nonce
                    )
                )
            )
        );
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _userOp(bytes memory callData, uint256 nonce) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    // ============ onInstall ============

    function test_onInstall_HappyPath_SetsStorage() public {
        _install();

        (uint24 totalWeight, uint24 threshold, address firstGuardian) = validator.weightedStorage(WALLET);
        assertEq(totalWeight, W1 + W2 + W3, "totalWeight");
        assertEq(threshold, THRESHOLD, "threshold");
        assertEq(firstGuardian, guardianAddrs[2], "firstGuardian is last-inserted");

        (uint24 g0Weight, address g0Next) = validator.guardian(guardianAddrs[0], WALLET);
        assertEq(g0Weight, W1, "guardian0 weight");
        assertEq(g0Next, WALLET, "guardian0.next is sentinel (msg.sender)");

        (uint24 g1Weight, address g1Next) = validator.guardian(guardianAddrs[1], WALLET);
        assertEq(g1Weight, W2, "guardian1 weight");
        assertEq(g1Next, guardianAddrs[0], "guardian1.next -> guardian0");

        (uint24 g2Weight, address g2Next) = validator.guardian(guardianAddrs[2], WALLET);
        assertEq(g2Weight, W3, "guardian2 weight");
        assertEq(g2Next, guardianAddrs[1], "guardian2.next -> guardian1");

        assertTrue(validator.isInitialized(WALLET), "isInitialized true");
    }

    function test_onInstall_EmitsGuardianAdded() public {
        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianAdded(guardianAddrs[0], WALLET, W1);
        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianAdded(guardianAddrs[1], WALLET, W2);
        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianAdded(guardianAddrs[2], WALLET, W3);

        vm.prank(WALLET);
        validator.onInstall(_installData());
    }

    function test_onInstall_RevertWhen_AlreadyInitialized() public {
        _install();
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, WALLET));
        validator.onInstall(_installData());
    }

    function test_onInstall_RevertWhen_LengthMismatch() public {
        address[] memory guardians = new address[](2);
        guardians[0] = guardianAddrs[0];
        guardians[1] = guardianAddrs[1];
        uint24[] memory weights = new uint24[](1);
        weights[0] = W1;

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.LengthMismatch.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_RevertWhen_EmptyGuardians() public {
        address[] memory guardians = new address[](0);
        uint24[] memory weights = new uint24[](0);
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.EmptyGuardians.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_RevertWhen_ZeroThreshold() public {
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.ZeroThreshold.selector);
        validator.onInstall(abi.encode(_guardians(), _weights(), uint24(0)));
    }

    function test_onInstall_RevertWhen_GuardianIsSelf() public {
        address[] memory guardians = new address[](1);
        guardians[0] = WALLET;
        uint24[] memory weights = new uint24[](1);
        weights[0] = W1;

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.GuardianCannotBeSelf.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_RevertWhen_GuardianIsZeroAddress() public {
        address[] memory guardians = new address[](1);
        guardians[0] = address(0);
        uint24[] memory weights = new uint24[](1);
        weights[0] = W1;

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.ZeroAddressGuardian.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_RevertWhen_WeightIsZero() public {
        address[] memory guardians = new address[](1);
        guardians[0] = guardianAddrs[0];
        uint24[] memory weights = new uint24[](1);
        weights[0] = 0;

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.ZeroWeight.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_RevertWhen_DuplicateGuardian() public {
        address[] memory guardians = new address[](2);
        guardians[0] = guardianAddrs[0];
        guardians[1] = guardianAddrs[0];
        uint24[] memory weights = new uint24[](2);
        weights[0] = W1;
        weights[1] = W1;

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.GuardianAlreadyEnabled.selector);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
    }

    function test_onInstall_NoSortRequired_UnsortedSucceeds() public {
        // Unlike the old validator, install no longer requires a sorted guardian array.
        address[] memory guardians = new address[](3);
        guardians[0] = guardianAddrs[1];
        guardians[1] = guardianAddrs[0];
        guardians[2] = guardianAddrs[2];
        uint24[] memory weights = new uint24[](3);
        weights[0] = W2;
        weights[1] = W1;
        weights[2] = W3;

        vm.prank(WALLET);
        validator.onInstall(abi.encode(guardians, weights, THRESHOLD));
        assertTrue(validator.isInitialized(WALLET), "unsorted install accepted");
    }

    function test_onInstall_RevertWhen_ThresholdExceedsTotalWeight() public {
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.ThresholdExceedsTotalWeight.selector);
        validator.onInstall(abi.encode(_guardians(), _weights(), uint24(W1 + W2 + W3 + 1)));
    }

    function test_onInstall_ThresholdEqualsTotalWeight_Succeeds() public {
        vm.prank(WALLET);
        validator.onInstall(abi.encode(_guardians(), _weights(), uint24(W1 + W2 + W3)));
        (uint24 totalWeight, uint24 threshold,) = validator.weightedStorage(WALLET);
        assertEq(threshold, totalWeight, "threshold == totalWeight boundary");
    }

    function test_isModuleType_Validator() public view {
        assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(validator.isModuleType(999));
    }

    // ============ onUninstall ============

    function test_onUninstall_RevertWhen_NotInitialized() public {
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        validator.onUninstall("");
    }

    function test_onUninstall_ClearsGuardiansAndStorage() public {
        _install();

        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianRemoved(guardianAddrs[2], WALLET);
        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianRemoved(guardianAddrs[1], WALLET);
        vm.expectEmit(true, true, false, true, address(validator));
        emit WeightedECDSAValidator.GuardianRemoved(guardianAddrs[0], WALLET);

        vm.prank(WALLET);
        validator.onUninstall("");

        (uint24 totalWeight, uint24 threshold, address firstGuardian) = validator.weightedStorage(WALLET);
        assertEq(totalWeight, 0, "totalWeight cleared");
        assertEq(threshold, 0, "threshold cleared");
        assertEq(firstGuardian, address(0), "firstGuardian cleared");

        for (uint256 i = 0; i < 3; i++) {
            (uint24 w, address next) = validator.guardian(guardianAddrs[i], WALLET);
            assertEq(w, 0, "guardian weight cleared");
            assertEq(next, address(0), "guardian next cleared");
        }
        assertFalse(validator.isInitialized(WALLET), "not initialized after uninstall");
    }

    function test_onInstall_AfterUninstall_Reinstalls() public {
        _install();
        vm.prank(WALLET);
        validator.onUninstall("");
        _install();
        assertTrue(validator.isInitialized(WALLET), "reinstall after uninstall works");
    }

    // ============ validateUserOp (split-signature scheme) ============

    /// @dev Happy path: guardian0 (W1=50) signs proposalHash, guardian1 (W2=30) signs finalHash.
    ///      Combined weight 80 >= 60. proposalSigner < finalSigner not required (only 1 proposal sig).
    function test_validateUserOp_TwoSig_ThresholdMet_Success() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[0], _proposalHash(userOp)), // proposal sig
            _sign(guardianKeys[1], _finalHash(userOpHash)) // final sig
        );

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_SUCCESS_UINT, "threshold met");
    }

    /// @dev Single final signature: guardian0 alone (W1=50) is below threshold 60 -> fail.
    function test_validateUserOp_SingleFinalSig_BelowThreshold_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        userOp.signature = _sign(guardianKeys[0], _finalHash(userOpHash));

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_FAILED_UINT, "below threshold");
    }

    /// @dev The final signature must use THIS variant's convention. Signing with the wrong final
    ///      hash yields a non-guardian recovered address -> last-signer zero weight -> fail.
    function test_validateUserOp_WrongFinalHashConvention_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[0], _proposalHash(userOp)),
            _sign(guardianKeys[1], _wrongFinalHash(userOpHash)) // wrong convention
        );

        vm.prank(WALLET);
        assertEq(
            validator.validateUserOp(userOp, userOpHash),
            SIG_VALIDATION_FAILED_UINT,
            "wrong final-hash convention rejected"
        );
    }

    /// @dev Last signer not a guardian -> fail (returns false, no revert), even though the
    ///      proposal sigs alone already meet threshold.
    function test_validateUserOp_LastSignerNotGuardian_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        (, uint256 strangerKey) = makeAddrAndKey("stranger");

        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[0], _proposalHash(userOp)),
            _sign(guardianKeys[1], _proposalHash(userOp)),
            _sign(strangerKey, _finalHash(userOpHash)) // last signer not a guardian
        );

        // guardianKeys[0] < guardianKeys[1] by address (ascending) required for the two proposal sigs
        // guardianAddrs is sorted ascending, so keys[0]..keys[1] are ascending too.
        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_FAILED_UINT, "last signer not guardian");
    }

    /// @dev Non-last (proposal) signer with zero weight must REVERT ZeroWeightSigner.
    function test_validateUserOp_RevertWhen_NonLastSignerZeroWeight() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        (, uint256 strangerKey) = makeAddrAndKey("stranger-nonlast");

        userOp.signature = abi.encodePacked(
            _sign(strangerKey, _proposalHash(userOp)), // proposal signer, zero weight -> revert
            _sign(guardianKeys[0], _finalHash(userOpHash))
        );

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.ZeroWeightSigner.selector);
        validator.validateUserOp(userOp, userOpHash);
    }

    /// @dev De-dup: same guardian signs the proposal AND the final hash. Its weight is counted
    ///      once. guardian0 alone (W1=50) < 60, so a self-duplicate must NOT reach threshold.
    function test_validateUserOp_FinalSignerAlsoProposalSigner_NoDoubleCount_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[0], _proposalHash(userOp)),
            _sign(guardianKeys[0], _finalHash(userOpHash)) // same guardian as final signer
        );

        vm.prank(WALLET);
        assertEq(
            validator.validateUserOp(userOp, userOpHash),
            SIG_VALIDATION_FAILED_UINT,
            "final signer weight not double-counted"
        );
    }

    /// @dev De-dup positive: two distinct proposal signers reach threshold; the final sig repeats
    ///      one of them (already counted) but the two distinct proposal weights already pass.
    function test_validateUserOp_DedupWithEnoughDistinctWeight_Success() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        // guardian0 (50) + guardian1 (30) as proposal sigs (ascending) = 80 >= 60; final repeats guardian0
        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[0], _proposalHash(userOp)),
            _sign(guardianKeys[1], _proposalHash(userOp)),
            _sign(guardianKeys[0], _finalHash(userOpHash))
        );

        vm.prank(WALLET);
        assertEq(
            validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_SUCCESS_UINT, "distinct proposal weight passes"
        );
    }

    /// @dev Proposal signers out of ascending order must REVERT SignersNotSorted.
    function test_validateUserOp_RevertWhen_ProposalSignersNotSorted() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        // guardian1 then guardian0 as proposal sigs = descending -> not sorted
        userOp.signature = abi.encodePacked(
            _sign(guardianKeys[1], _proposalHash(userOp)),
            _sign(guardianKeys[0], _proposalHash(userOp)),
            _sign(guardianKeys[2], _finalHash(userOpHash))
        );

        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSAValidator.SignersNotSorted.selector);
        validator.validateUserOp(userOp, userOpHash);
    }

    function test_validateUserOp_ThresholdZero_NotInstalled_Fails() public {
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _sign(guardianKeys[0], _finalHash(userOpHash));

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_FAILED_UINT, "threshold==0 -> fail");
    }

    /// @dev Signature length not a multiple of 65 -> fail (no revert).
    function test_validateUserOp_SigLengthNotMultipleOf65_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = hex"deadbeef"; // 4 bytes

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_FAILED_UINT, "bad sig length");
    }

    /// @dev Empty signature -> sigCount == 0 -> fail (no revert).
    function test_validateUserOp_EmptySignature_Fails() public {
        _install();
        PackedUserOperation memory userOp = _userOp(hex"aabb", 0);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = "";

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, userOpHash), SIG_VALIDATION_FAILED_UINT, "empty sig");
    }

    // ============ isValidSignatureWithSender (ERC-1271, ep-agnostic) ============

    function test_isValidSignatureWithSender_ReturnsInvalid_WhenNotInstalled() public {
        bytes32 hash = keccak256("not installed");
        bytes memory sig = _sign(guardianKeys[0], hash);
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sig), ERC1271_INVALID, "threshold==0");
    }

    function test_isValidSignatureWithSender_EmptyData_ReturnsInvalid() public {
        _install();
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), keccak256("empty"), ""), ERC1271_INVALID, "zero sigs");
    }

    function test_isValidSignatureWithSender_SingleSigBelowThreshold_ReturnsInvalid() public {
        _install();
        bytes32 hash = keccak256("single");
        bytes memory sig = _sign(guardianKeys[2], hash); // W3=20 < 60
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sig), ERC1271_INVALID, "below threshold");
    }

    function test_isValidSignatureWithSender_MultiSigMeetsThreshold_ReturnsMagicValue() public {
        _install();
        bytes32 hash = keccak256("multi");
        // ascending signers: guardian0 then guardian1 (guardianAddrs sorted ascending)
        bytes memory sigs = abi.encodePacked(_sign(guardianKeys[0], hash), _sign(guardianKeys[1], hash));
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sigs), ERC1271_MAGICVALUE, "80 >= 60");
    }

    function test_isValidSignatureWithSender_OrderingViolation_ReturnsInvalid() public {
        _install();
        bytes32 hash = keccak256("unordered");
        // descending order (guardian1 before guardian0) violates strictly-ascending; combined
        // weight would be 80 but ordering rejects before the last-sig threshold check
        bytes memory sigs = abi.encodePacked(_sign(guardianKeys[1], hash), _sign(guardianKeys[0], hash));
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sigs), ERC1271_INVALID, "descending rejected");
    }

    /// @dev Ordering violation among NON-last signers (3 sigs, first two descending) -> INVALID.
    ///      Exercises the `_verifySorted` in-loop ordering early-return (not the last-sig path).
    function test_isValidSignatureWithSender_NonLastOrderingViolation_ReturnsInvalid() public {
        _install();
        bytes32 hash = keccak256("nonlast-order");
        // guardian1 then guardian0 (descending) as first two, guardian2 last -> in-loop violation
        bytes memory sigs =
            abi.encodePacked(_sign(guardianKeys[1], hash), _sign(guardianKeys[0], hash), _sign(guardianKeys[2], hash));
        vm.prank(WALLET);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, sigs), ERC1271_INVALID, "non-last ordering rejected"
        );
    }

    /// @dev A NON-last signer whose weight alone reaches threshold returns MAGICVALUE early,
    ///      before the last signature is processed. Exercises the in-loop threshold return.
    function test_isValidSignatureWithSender_NonLastMeetsThreshold_ReturnsMagicValue() public {
        // Install a set where guardian0 alone (weight 100) exceeds threshold 60, on a fresh sender.
        address acct = address(0xBEEF);
        (address big, uint256 bigKey) = makeAddrAndKey("bigGuardian");
        (address small, uint256 smallKey) = makeAddrAndKey("smallGuardian");
        // ensure big < small so big is a non-last signer in ascending order
        if (big > small) {
            (big, small) = (small, big);
            (bigKey, smallKey) = (smallKey, bigKey);
        }
        address[] memory gs = new address[](2);
        gs[0] = big;
        gs[1] = small;
        uint24[] memory ws = new uint24[](2);
        ws[0] = 100;
        ws[1] = 5;
        vm.prank(acct);
        validator.onInstall(abi.encode(gs, ws, uint24(60)));

        bytes32 hash = keccak256("nonlast-threshold");
        bytes memory sigs = abi.encodePacked(_sign(bigKey, hash), _sign(smallKey, hash));
        vm.prank(acct);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, sigs),
            ERC1271_MAGICVALUE,
            "non-last signer meets threshold early"
        );
    }

    function test_isValidSignatureWithSender_NonGuardianSigner_ReturnsInvalid() public {
        _install();
        bytes32 hash = keccak256("stranger");
        (, uint256 strangerKey) = makeAddrAndKey("strangerSigner");
        bytes memory sig = _sign(strangerKey, hash);
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sig), ERC1271_INVALID, "zero weight");
    }

    /// @dev A NON-last signer with zero weight must REVERT ZeroWeightSigner. Installs a single
    ///      guardian with a deliberately high address on a fresh account, then finds a stranger key
    ///      that recovers to a lower address so it sorts FIRST (non-last).
    function test_isValidSignatureWithSender_RevertWhen_NonLastSignerZeroWeight() public {
        bytes32 hash = keccak256("griefing");

        // Deterministically find a real guardian and a stranger with stranger < guardian.
        (address realAddr, uint256 realKey) = makeAddrAndKey("griefing-real-guardian");
        address stranger;
        uint256 strangerKey;
        for (uint256 i = 0; i < 50; i++) {
            (stranger, strangerKey) = makeAddrAndKey(string(abi.encodePacked("griefer", vm.toString(i))));
            if (stranger < realAddr) break;
        }
        require(stranger < realAddr, "could not construct witness");

        address acct = address(0xCAFE);
        address[] memory gs = new address[](1);
        gs[0] = realAddr;
        uint24[] memory ws = new uint24[](1);
        ws[0] = 60;
        vm.prank(acct);
        validator.onInstall(abi.encode(gs, ws, uint24(60)));

        // stranger (zero weight, sorts first/non-last) then real guardian (last)
        bytes memory sigs = abi.encodePacked(_sign(strangerKey, hash), _sign(realKey, hash));
        vm.prank(acct);
        vm.expectRevert(WeightedECDSAValidator.ZeroWeightSigner.selector);
        validator.isValidSignatureWithSender(address(0), hash, sigs);
    }

    /// @dev All signers valid & distinct but combined weight below threshold -> INVALID
    ///      (exercises the final `return false` after the last-signature path).
    function test_isValidSignatureWithSender_TwoLowWeight_BelowThreshold_ReturnsInvalid() public {
        _install();
        bytes32 hash = keccak256("low-total");
        // guardian1 (30) + guardian2 (20) = 50 < 60, ascending order, last sig non-zero weight
        bytes memory sigs = abi.encodePacked(_sign(guardianKeys[1], hash), _sign(guardianKeys[2], hash));
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, sigs), ERC1271_INVALID, "50 < 60 -> invalid");
    }

    // ============ EC-01 regression ============

    /// @notice A single guardian's signature duplicated must NOT reach threshold by being counted
    ///         twice. The ordering guard (signer <= lastSigner) runs BEFORE weight is added, so the
    ///         second occurrence of the same signer is rejected. This is where EC-01 lived.
    function test_EC01_isValidSignatureWithSender_DuplicateSingleGuardianSig_ReturnsInvalid_NotMagicValue() public {
        _install();
        bytes32 hash = keccak256("EC01-dup");
        bytes memory sig = _sign(guardianKeys[0], hash); // W1=50, alone < 60
        bytes memory sigs = abi.encodePacked(sig, sig); // same guardian twice -> 100 if double-counted

        vm.prank(WALLET);
        bytes4 result = validator.isValidSignatureWithSender(address(0), hash, sigs);
        assertEq(result, ERC1271_INVALID, "EC-01: duplicate single-guardian sig rejected");
        assertTrue(result != ERC1271_MAGICVALUE, "EC-01: must never return MAGICVALUE for a duplicate");
    }
}

/// @title WeightedECDSAValidatorV09Test
/// @notice Reuses the full suite but for the ep0.9 variant: the final signature signs the RAW
///         userOpHash. The wrong-convention test flips to the eth-signed hash.
contract WeightedECDSAValidatorV09Test is WeightedECDSAValidatorTest {
    function setUp() public override {
        super.setUp();
        domainName = "WeightedECDSAValidator"; // V09 keeps the base domain name (one-method subclass)
    }

    function _deploy() internal override returns (WeightedECDSAValidator) {
        return new WeightedECDSAValidatorV09();
    }

    function _finalHash(bytes32 userOpHash) internal pure override returns (bytes32) {
        return userOpHash; // ep0.9: raw userOpHash
    }

    function _wrongFinalHash(bytes32 userOpHash) internal pure override returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(userOpHash);
    }
}
