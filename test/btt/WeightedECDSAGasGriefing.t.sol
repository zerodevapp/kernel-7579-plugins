// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

/**
 * @title WeightedECDSAGasGriefingTest
 * @notice BTT tests for gas griefing protection in WeightedECDSASigner
 * @dev Tests the fix for TOB-KERNEL-15: Gas griefing through zero-weight signers
 *      - Non-last signers with zero weight cause a revert (prevents gas griefing)
 *      - Last signer with zero weight returns validation failed (allows proper UX)
 */
contract WeightedECDSAGasGriefingTest is Test {
    WeightedECDSASigner signer;
    IEntryPoint entrypoint;

    address constant WALLET = address(0x1234);
    bytes32 constant SIGNER_ID = keccak256("TEST_SIGNER_ID");

    // Guardians for testing
    address[] guardians;
    uint256[] guardianKeys;

    uint24 constant WEIGHT_PER_GUARDIAN = 10;
    uint24 constant THRESHOLD = 50; // Need 5 guardians to meet threshold

    function setUp() public {
        signer = new WeightedECDSASigner();
        entrypoint = EntryPointLib.deploy();

        // Create 15 guardians for testing (more than old MAX_SIGNATURES of 10)
        for (uint256 i = 0; i < 15; i++) {
            (address guardian, uint256 key) = makeAddrAndKey(string(abi.encodePacked("guardian", i)));
            guardians.push(guardian);
            guardianKeys.push(key);
        }

        // Sort guardians by address (ascending order) - bubble sort
        for (uint256 i = 0; i < guardians.length; i++) {
            for (uint256 j = i + 1; j < guardians.length; j++) {
                if (guardians[i] > guardians[j]) {
                    (guardians[i], guardians[j]) = (guardians[j], guardians[i]);
                    (guardianKeys[i], guardianKeys[j]) = (guardianKeys[j], guardianKeys[i]);
                }
            }
        }
    }

    function _installSigner(uint256 numGuardians) internal {
        address[] memory guardiansToInstall = new address[](numGuardians);
        uint24[] memory weights = new uint24[](numGuardians);

        for (uint256 i = 0; i < numGuardians; i++) {
            guardiansToInstall[i] = guardians[i];
            weights[i] = WEIGHT_PER_GUARDIAN;
        }

        bytes memory installData = abi.encode(guardiansToInstall, weights, THRESHOLD);

        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function _signHash(bytes32 hash, uint256 numSigners) internal view returns (bytes memory) {
        bytes memory signatures;

        for (uint256 i = 0; i < numSigners; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeys[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        return signatures;
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

        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                        userOp.sender,
                        SIGNER_ID,
                        keccak256(userOp.callData),
                        userOp.nonce
                    )
                )
            )
        );
    }

    function _createUserOp() internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSignature("execute()"),
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _signUserOp(PackedUserOperation memory userOp, uint256 numSigners)
        internal
        view
        returns (bytes memory)
    {
        bytes32 proposalHash = _computeProposalHash(userOp);
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        bytes memory signatures;

        // Sign proposalHash for all except last signer
        for (uint256 i = 0; i < numSigners - 1; i++) {
            (uint8 vi, bytes32 ri, bytes32 si) = vm.sign(guardianKeys[i], proposalHash);
            signatures = abi.encodePacked(signatures, ri, si, vi);
        }

        // Last signer signs userOpHash
        (uint8 vLast, bytes32 rLast, bytes32 sLast) = vm.sign(guardianKeys[numSigners - 1], userOpHash);
        signatures = abi.encodePacked(signatures, rLast, sLast, vLast);

        return signatures;
    }

    // ============ ERC1271 Signature Validation Tests ============

    modifier whenValidatingERC1271Signature() {
        _;
    }

    function test_WhenNon_lastSignerHasZeroWeight() external whenValidatingERC1271Signature {
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create a non-guardian with a specific private key that gives a low address
        // We need an address lower than guardians[4] (the highest guardian we use)
        uint256 nonGuardianKey = 0x1234567890abcdef;
        address nonGuardian = vm.addr(nonGuardianKey);

        // If nonGuardian happens to be higher than all guardians, keep trying different keys
        while (nonGuardian > guardians[4]) {
            nonGuardianKey += 1;
            nonGuardian = vm.addr(nonGuardianKey);
        }

        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        mixedSigners[0] = nonGuardian;
        mixedKeys[0] = nonGuardianKey;
        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i + 1] = guardians[i];
            mixedKeys[i + 1] = guardianKeys[i];
        }

        // Sort
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        // Ensure nonGuardian is not last
        require(mixedSigners[4] != nonGuardian, "Test setup: nonGuardian should not be last");

        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        // it should revert with ZeroWeightSigner
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);
    }

    function test_WhenLastSignerHasZeroWeight() external whenValidatingERC1271Signature {
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create a non-guardian that will be last after sorting (high address)
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zzz_lastNonGuardian");

        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i] = guardians[i];
            mixedKeys[i] = guardianKeys[i];
        }
        mixedSigners[4] = nonGuardian;
        mixedKeys[4] = nonGuardianKey;

        // Sort
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        require(mixedSigners[4] == nonGuardian, "Test setup: nonGuardian should be last");

        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        // it should return ERC1271_INVALID
        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);
        assertEq(result, ERC1271_INVALID);
    }

    function test_WhenAllSignersAreValidGuardians() external whenValidatingERC1271Signature {
        _installSigner(5);

        bytes32 testHash = keccak256("test");
        bytes memory signatures = _signHash(testHash, 5);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_MAGICVALUE
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_WhenSignatureCountIsZero() external whenValidatingERC1271Signature {
        _installSigner(5);

        bytes32 testHash = keccak256("test");
        bytes memory signatures = "";

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID);
    }

    function test_WhenSignatureLengthIsNotAMultipleOf65() external whenValidatingERC1271Signature {
        _installSigner(5);

        bytes32 testHash = keccak256("test");
        bytes memory signatures = new bytes(100); // Not a multiple of 65

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID);
    }

    function test_WhenMoreThan10ValidGuardiansSign() external whenValidatingERC1271Signature {
        _installSigner(12);

        bytes32 testHash = keccak256("test");
        bytes memory signatures = _signHash(testHash, 12);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should succeed with no arbitrary limit
        assertEq(result, ERC1271_MAGICVALUE);
    }

    // ============ ERC4337 UserOp Validation Tests ============

    modifier whenValidatingERC4337UserOp() {
        _;
    }

    function test_WhenNon_lastSignerHasZeroWeight_WhenValidatingERC4337UserOp() external whenValidatingERC4337UserOp {
        _installSigner(5);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 proposalHash = _computeProposalHash(userOp);
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        // Create a non-guardian with a specific private key that gives a low address
        uint256 nonGuardianKey = 0x1234567890abcdef;
        address nonGuardian = vm.addr(nonGuardianKey);

        // If nonGuardian happens to be higher than all guardians, keep trying different keys
        while (nonGuardian > guardians[4]) {
            nonGuardianKey += 1;
            nonGuardian = vm.addr(nonGuardianKey);
        }

        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        mixedSigners[0] = nonGuardian;
        mixedKeys[0] = nonGuardianKey;
        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i + 1] = guardians[i];
            mixedKeys[i + 1] = guardianKeys[i];
        }

        // Sort
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        require(mixedSigners[4] != nonGuardian, "Test setup: nonGuardian should not be last");

        // Sign: first 4 sign proposalHash, last signs userOpHash
        bytes memory signatures;
        for (uint256 i = 0; i < 4; i++) {
            (uint8 vi, bytes32 ri, bytes32 si) = vm.sign(mixedKeys[i], proposalHash);
            signatures = abi.encodePacked(signatures, ri, si, vi);
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[4], userOpHash);
        signatures = abi.encodePacked(signatures, r, s, v);

        userOp.signature = signatures;

        // it should revert with ZeroWeightSigner
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);
    }

    function test_WhenLastSignerHasZeroWeight_WhenValidatingERC4337UserOp() external whenValidatingERC4337UserOp {
        _installSigner(5);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 proposalHash = _computeProposalHash(userOp);
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        // Create a non-guardian that will be last after sorting
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zzz_lastNonGuardian");

        // Use 4 guardians + nonGuardian, ensure nonGuardian is last
        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i] = guardians[i];
            mixedKeys[i] = guardianKeys[i];
        }
        mixedSigners[4] = nonGuardian;
        mixedKeys[4] = nonGuardianKey;

        // Sort
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        require(mixedSigners[4] == nonGuardian, "Test setup: nonGuardian should be last");

        // Sign: first 4 sign proposalHash, last (nonGuardian) signs userOpHash
        bytes memory signatures;
        for (uint256 i = 0; i < 4; i++) {
            (uint8 vi, bytes32 ri, bytes32 si) = vm.sign(mixedKeys[i], proposalHash);
            signatures = abi.encodePacked(signatures, ri, si, vi);
        }
        (uint8 vLast, bytes32 rLast, bytes32 sLast) = vm.sign(nonGuardianKey, userOpHash);
        signatures = abi.encodePacked(signatures, rLast, sLast, vLast);

        userOp.signature = signatures;

        // it should return SIG_VALIDATION_FAILED
        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_WhenAllSignersAreValidGuardians_WhenValidatingERC4337UserOp() external whenValidatingERC4337UserOp {
        _installSigner(5);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        userOp.signature = _signUserOp(userOp, 5);

        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // it should return SIG_VALIDATION_SUCCESS
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_WhenSignatureCountIsZero_WhenValidatingERC4337UserOp() external whenValidatingERC4337UserOp {
        _installSigner(5);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        userOp.signature = "";

        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // it should return SIG_VALIDATION_FAILED
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_WhenSignatureLengthIsNotAMultipleOf65_WhenValidatingERC4337UserOp()
        external
        whenValidatingERC4337UserOp
    {
        _installSigner(5);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        userOp.signature = new bytes(100); // Not a multiple of 65

        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // it should return SIG_VALIDATION_FAILED
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_WhenMoreThan10ValidGuardiansSign_WhenValidatingERC4337UserOp() external whenValidatingERC4337UserOp {
        _installSigner(12);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        userOp.signature = _signUserOp(userOp, 12);

        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        // it should succeed with no arbitrary limit
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
    }
}
