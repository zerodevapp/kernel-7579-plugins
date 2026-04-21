// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

contract WeightedECDSADoubleCountTest is Test {
    WeightedECDSASigner public signer;
    IEntryPoint public entryPoint;

    address public wallet;

    // Guardians with known private keys - we'll sort them by address
    address public guardianLow;
    uint256 public guardianLowKey;
    address public guardianHigh;
    uint256 public guardianHighKey;
    address public guardianMid;
    uint256 public guardianMidKey;

    // Weights and threshold
    uint24 public constant WEIGHT_LOW = 40;
    uint24 public constant WEIGHT_HIGH = 40;
    uint24 public constant WEIGHT_MID = 30;
    uint24 public constant THRESHOLD = 70; // Requires at least 2 guardians

    bytes32 public constant SIGNER_ID = keccak256("TEST_SIGNER_ID");

    function setUp() public {
        signer = new WeightedECDSASigner();
        entryPoint = EntryPointLib.deploy();
        wallet = makeAddr("wallet");

        // Create guardians and sort them by address
        (address g1, uint256 k1) = makeAddrAndKey("guardian1");
        (address g2, uint256 k2) = makeAddrAndKey("guardian2");
        (address g3, uint256 k3) = makeAddrAndKey("guardian3");

        // Sort guardians by address (ascending)
        address[3] memory addrs = [g1, g2, g3];
        uint256[3] memory keys = [k1, k2, k3];

        // Simple bubble sort
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (addrs[i] > addrs[j]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }

        guardianLow = addrs[0];
        guardianLowKey = keys[0];
        guardianMid = addrs[1];
        guardianMidKey = keys[1];
        guardianHigh = addrs[2];
        guardianHighKey = keys[2];

        // Verify sorting
        assertTrue(guardianLow < guardianMid, "guardianLow should be less than guardianMid");
        assertTrue(guardianMid < guardianHigh, "guardianMid should be less than guardianHigh");

        // Install the signer module
        _installSigner();
    }

    function _installSigner() internal {
        address[] memory guardians = new address[](3);
        guardians[0] = guardianLow;
        guardians[1] = guardianMid;
        guardians[2] = guardianHigh;

        uint24[] memory weights = new uint24[](3);
        weights[0] = WEIGHT_LOW;
        weights[1] = WEIGHT_MID;
        weights[2] = WEIGHT_HIGH;

        bytes memory installData = abi.encode(guardians, weights, THRESHOLD);

        vm.prank(wallet);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));

        // Verify installation
        (uint24 totalWeight, uint24 threshold,) = signer.weightedStorage(SIGNER_ID, wallet);
        assertEq(totalWeight, WEIGHT_LOW + WEIGHT_MID + WEIGHT_HIGH, "Total weight should be sum of all weights");
        assertEq(threshold, THRESHOLD, "Threshold should match");
    }

    function _computeProposalHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSASigner"),
                keccak256("0.0.2"),
                block.chainid,
                address(signer)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                userOp.sender,
                SIGNER_ID,
                keccak256(userOp.callData),
                userOp.nonce
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _createUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: wallet,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _signWithKey(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    // ============================================================
    // Test: Same guardian signing both proposalHash and userOpHash
    // ============================================================
    function test_WhenSameGuardianSignsBothProposalHashAndUserOpHash() external {
        // it should return SIG_VALIDATION_FAILED
        // it should not count the guardian weight twice
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Use guardianLow to sign BOTH hashes
        // This simulates the double-counting attack
        bytes memory sig1 = _signWithKey(proposalHash, guardianLowKey);
        bytes memory sig2 = _signWithKey(userOpHash, guardianLowKey);

        // Concatenate signatures: first signs proposalHash, last signs userOpHash
        userOp.signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Should fail because same guardian signed both hashes
        // The fix enforces: lastSigner > previousSigner
        // Since same guardian signs both, recovered address would be <= lastSigner
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when same guardian signs both hashes");
    }

    // ============================================================
    // Test: Different guardians in sorted order succeeds
    // ============================================================
    function test_WhenDifferentGuardiansSignProposalHashAndUserOpHashInSortedOrder() external {
        // it should return SIG_VALIDATION_SUCCESS when threshold is met
        // it should count each guardian weight once
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // guardianLow signs proposalHash (weight 40)
        // guardianHigh signs userOpHash (weight 40)
        // Total: 80 >= threshold 70
        bytes memory sig1 = _signWithKey(proposalHash, guardianLowKey);
        bytes memory sig2 = _signWithKey(userOpHash, guardianHighKey);

        // guardianLow < guardianHigh, so sorted order is maintained
        userOp.signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed with different guardians in sorted order");
    }

    // ============================================================
    // Test: Guardians not in sorted order (proposal signers)
    // ============================================================
    function test_WhenGuardiansAreNotInSortedOrder() external {
        // it should revert with Signers not sorted
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Sign in WRONG order: high first, then low, then mid for userOpHash
        // guardianHigh signs proposalHash first
        // guardianLow signs proposalHash second (violates sorted order)
        // guardianMid signs userOpHash
        bytes memory sig1 = _signWithKey(proposalHash, guardianHighKey);
        bytes memory sig2 = _signWithKey(proposalHash, guardianLowKey);
        bytes memory sig3 = _signWithKey(userOpHash, guardianMidKey);

        userOp.signature = abi.encodePacked(sig1, sig2, sig3);

        vm.prank(wallet);
        vm.expectRevert("Signers not sorted");
        signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);
    }

    // ============================================================
    // Test: Last signer has lower address than previous signer
    // NOTE: The last signer (userOpHash signer) is NOT required to maintain sorted order
    // relative to proposalHash signers. Only proposalHash signers must be sorted among themselves.
    // ============================================================
    function test_WhenLastSignerHasLowerAddressThanPreviousSigner() external {
        // it should return SIG_VALIDATION_SUCCESS (last signer ordering is not enforced)
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // guardianHigh signs proposalHash (higher address, weight 40)
        // guardianLow signs userOpHash (lower address, weight 40)
        // Total weight = 80 >= threshold 70
        bytes memory sig1 = _signWithKey(proposalHash, guardianHighKey);
        bytes memory sig2 = _signWithKey(userOpHash, guardianLowKey);

        userOp.signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Last signer ordering is not enforced - only proposalHash signers must be sorted
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed - last signer ordering not enforced");
    }

    // ============================================================
    // Test: Last signer has equal address to previous signer
    // ============================================================
    function test_WhenLastSignerHasEqualAddressToPreviousSigner() external {
        // it should return SIG_VALIDATION_FAILED
        // This is essentially the same guardian signing both hashes
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Use guardianMid to sign both hashes
        bytes memory sig1 = _signWithKey(proposalHash, guardianMidKey);
        bytes memory sig2 = _signWithKey(userOpHash, guardianMidKey);

        userOp.signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Should fail because lastSigner == previousSigner (same guardian)
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when last signer equals previous signer");
    }

    // ============================================================
    // Test: Last signer has higher address than previous signer
    // ============================================================
    function test_WhenLastSignerHasHigherAddressThanPreviousSigner() external {
        // it should return SIG_VALIDATION_SUCCESS when threshold is met
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // guardianMid signs proposalHash (weight 30)
        // guardianHigh signs userOpHash (weight 40)
        // Total: 70 >= threshold 70
        bytes memory sig1 = _signWithKey(proposalHash, guardianMidKey);
        bytes memory sig2 = _signWithKey(userOpHash, guardianHighKey);

        // guardianMid < guardianHigh, sorted order maintained
        userOp.signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed when last signer has higher address");
    }

    // ============================================================
    // Test: Threshold met with unique signers only
    // ============================================================
    function test_WhenThresholdIsMetWithUniqueSignersOnly() external {
        // it should validate weight accumulation correctly
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Use all three guardians in sorted order
        // guardianLow (40) + guardianMid (30) signs proposalHash = 70
        // guardianHigh (40) signs userOpHash
        // Total would be 110 if all counted, but threshold met at 70
        bytes memory sig1 = _signWithKey(proposalHash, guardianLowKey);
        bytes memory sig2 = _signWithKey(proposalHash, guardianMidKey);
        bytes memory sig3 = _signWithKey(userOpHash, guardianHighKey);

        userOp.signature = abi.encodePacked(sig1, sig2, sig3);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Should succeed - threshold met with unique signers
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed with unique signers meeting threshold");
    }

    // ============================================================
    // Test: Same signer appears twice in ERC1271 signature array
    // ============================================================
    function test_WhenSameSignerAppearsTwiceInERC1271SignatureArray() external {
        // it should return ERC1271_INVALID
        bytes32 testHash = keccak256("test_hash");

        // Sign twice with the same guardian
        bytes memory sig1 = _signWithKey(testHash, guardianLowKey);
        bytes memory sig2 = _signWithKey(testHash, guardianLowKey);

        bytes memory signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signature);

        // Should fail because same signer appears twice (signer <= lastSigner)
        assertEq(result, ERC1271_INVALID, "Should return invalid when same signer appears twice");
    }

    // ============================================================
    // Test: ERC1271 signers in descending order
    // ============================================================
    function test_WhenERC1271SignersAreInDescendingOrder() external {
        // it should return ERC1271_INVALID
        bytes32 testHash = keccak256("test_hash");

        // Sign in descending order (high to low) - violates sorted order
        bytes memory sig1 = _signWithKey(testHash, guardianHighKey);
        bytes memory sig2 = _signWithKey(testHash, guardianLowKey);

        bytes memory signature = abi.encodePacked(sig1, sig2);

        vm.prank(wallet);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signature);

        // Should fail because signers are not in ascending order
        assertEq(result, ERC1271_INVALID, "Should return invalid when signers in descending order");
    }

    // ============================================================
    // Additional edge case: Single signature for userOp
    // ============================================================
    function test_WhenSingleSignatureProvided() external {
        // When only one signature is provided, it signs the userOpHash
        // This tests the edge case where sigCount == 1
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Only guardianHigh signs userOpHash (weight 40)
        bytes memory sig = _signWithKey(userOpHash, guardianHighKey);

        userOp.signature = sig;

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Should fail because weight 40 < threshold 70
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when single signer weight below threshold");
    }

    // ============================================================
    // Additional edge case: Early threshold satisfaction
    // ============================================================
    function test_WhenThresholdMetBeforeLastSignature() external {
        // Test that threshold can be met by proposal signers alone
        // This means the function returns early before checking last signature
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // guardianLow (40) + guardianMid (30) = 70 >= threshold 70
        // guardianHigh signs userOpHash but threshold already met
        bytes memory sig1 = _signWithKey(proposalHash, guardianLowKey);
        bytes memory sig2 = _signWithKey(proposalHash, guardianMidKey);
        bytes memory sig3 = _signWithKey(userOpHash, guardianHighKey);

        userOp.signature = abi.encodePacked(sig1, sig2, sig3);

        vm.prank(wallet);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // Should succeed - threshold met by proposal signers
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed when threshold met by proposal signers");
    }
}
