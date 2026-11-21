pragma solidity ^0.8.20;

import {SignerTestBase} from "./base/SignerTestBase.sol";
import {StatelessValidatorTestBase} from "./base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "./base/StatelessValidatorWithSenderTestBase.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import "forge-std/console.sol";

contract WeightedECDSASignerTest is SignerTestBase, StatelessValidatorTestBase, StatelessValidatorWithSenderTestBase {
    address guardian1;
    uint256 guardian1Key;
    address guardian2;
    uint256 guardian2Key;
    address guardian3;
    uint256 guardian3Key;

    uint24 weight1 = 50;
    uint24 weight2 = 30;
    uint24 weight3 = 20;
    uint24 threshold = 60; // Need at least 60 weight (e.g., guardian1 + guardian2)

    function deployModule() internal virtual override returns (IModule) {
        return new WeightedECDSASigner();
    }

    function _initializeTest() internal override {
        (guardian1, guardian1Key) = makeAddrAndKey("guardian1");
        (guardian2, guardian2Key) = makeAddrAndKey("guardian2");
        (guardian3, guardian3Key) = makeAddrAndKey("guardian3");
    }

    function installData() internal view override returns (bytes memory) {
        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        uint24[] memory weights = new uint24[](3);
        weights[0] = weight1;
        weights[1] = weight2;
        weights[2] = weight3;

        return abi.encode(guardians, weights, threshold);
    }

    function _domainSeparator(bool replayable) internal view returns (bytes32) {
        if (replayable) {
            return keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                    keccak256("WeightedECDSASigner"),
                    keccak256("0.0.3"),
                    address(module)
                )
            );
        }
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSASigner"),
                keccak256("0.0.3"),
                block.chainid,
                address(module)
            )
        );
    }

    function _proposalHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        bool replayable = userOp.nonce & (uint256(0x40) << 248) != 0;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Proposal(address account,bytes32 id,bytes callData,uint256 nonce,uint256 configurationEpoch)"
                ),
                userOp.sender,
                signerId(),
                keccak256(userOp.callData),
                userOp.nonce,
                WeightedECDSASigner(address(module)).configurationEpoch(signerId(), WALLET)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(replayable), structHash));
    }

    function _finalHash(PackedUserOperation memory userOp, bytes32 userOpHash) internal view returns (bytes32) {
        bool replayable = userOp.nonce & (uint256(0x40) << 248) != 0;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WeightedUserOperation(bytes32 userOpHash,uint256 configurationEpoch)"),
                userOpHash,
                WeightedECDSASigner(address(module)).configurationEpoch(signerId(), WALLET)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(replayable), structHash));
    }

    function userOpSignature(PackedUserOperation memory userOp, bool valid)
        internal
        view
        virtual
        override
        returns (bytes memory)
    {
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        if (!valid) {
            // For invalid, use wrong hash
            userOpHash = keccak256(abi.encodePacked("invalid", userOpHash));
        }

        // For WeightedECDSASigner userOp validation:
        // - All signatures except the last one sign the EIP712 proposalHash
        // - The last signature signs the userOpHash
        // We'll use guardian1 to sign proposalHash and guardian2 to sign userOpHash

        bytes32 proposalHash = _proposalHash(userOp);

        // Sign proposalHash with guardian1 (first signature, sorted order)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);
        // Sign userOpHash with guardian2 (last signature)
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, _finalHash(userOp, userOpHash));

        // Guardian1 has lower address, must come first (sorted order)
        if (guardian1 < guardian2) {
            return abi.encodePacked(r1, s1, v1, r2, s2, v2);
        } else {
            return abi.encodePacked(r2, s2, v2, r1, s1, v1);
        }
    }

    function erc1271Signature(bytes32 hash, bool valid) internal view virtual override returns (address, bytes memory) {
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }

        // Sign with guardian1 and guardian2 (total weight = 80 >= threshold 60)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, hash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, hash);

        // Guardians must be in sorted order
        if (guardian1 < guardian2) {
            return (address(0), abi.encodePacked(r1, s1, v1, r2, s2, v2));
        } else {
            return (address(0), abi.encodePacked(r2, s2, v2, r1, s1, v1));
        }
    }

    function statelessValidationSignature(bytes32 hash, bool valid)
        internal
        view
        virtual
        override
        returns (address, bytes memory)
    {
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }

        // Sign with guardian1 and guardian2
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, hash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, hash);

        // Guardians must be in sorted order
        bytes memory signatures;
        if (guardian1 < guardian2) {
            signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        } else {
            signatures = abi.encodePacked(r2, s2, v2, r1, s1, v1);
        }

        return (address(0), signatures);
    }

    function statelessValidationSignatureWithSender(bytes32 hash, bool valid)
        internal
        view
        virtual
        override
        returns (address, bytes memory)
    {
        return statelessValidationSignature(hash, valid);
    }

    // Override the install/uninstall check hooks because WeightedECDSASigner uses per-ID initialization
    // but the base isInitialized() checks with hardcoded bytes32(0)
    function _afterInstallCheck(bytes32 id) internal override {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        // Check that the signer was installed by checking totalWeight for this ID
        (uint24 totalWeight,,) = signerModule.weightedStorage(id, WALLET);
        assertTrue(totalWeight > 0);
    }

    function _afterUninstallCheck(bytes32 id) internal override {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        // Check that the signer was uninstalled by checking totalWeight is 0 for this ID
        (uint24 totalWeight,,) = signerModule.weightedStorage(id, WALLET);
        assertEq(totalWeight, 0);
    }

    // Override base tests - with zero-weight signers that are not last, we now revert
    function testSignerIsValidSignatureWithSenderFail() public payable override {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (, bytes memory signature) = erc1271Signature(testHash, false);

        // With invalid signatures, recovered addresses are non-guardians with zero weight
        // Since first signer is not last and has zero weight, it should revert
        vm.startPrank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        signerModule.checkSignature(signerId(), address(0), testHash, signature);
        vm.stopPrank();
    }

    function testStatlessValidatorFail() external override {
        WeightedECDSASigner validatorModule = WeightedECDSASigner(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (, bytes memory sig) = statelessValidationSignature(message, false);

        // With invalid signatures, recovered addresses are non-guardians with zero weight
        // Since first signer is not last and has zero weight, it should revert
        vm.startPrank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        validatorModule.validateSignatureWithData(message, sig, installData());
        vm.stopPrank();
    }

    function testStatelessValidatorWithSenderFail() external override {
        WeightedECDSASigner validatorModule = WeightedECDSASigner(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (, bytes memory sig) = statelessValidationSignatureWithSender(message, false);

        // With invalid signatures, recovered addresses are non-guardians with zero weight
        // Since first signer is not last and has zero weight, it should revert
        vm.startPrank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        validatorModule.validateSignatureWithDataWithSender(address(0), message, sig, installData());
        vm.stopPrank();
    }

    // Additional tests specific to WeightedECDSASigner

    function testWeightedSignatureWithSingleGuardian() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Sign with only guardian1 (weight 50, less than threshold 60)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardian1Key, testHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(WALLET);
        bytes4 result = signerModule.checkSignature(signerId(), address(0), testHash, signature);
        vm.stopPrank();

        // Should fail because weight 50 < threshold 60
        assertFalse(result == 0x1626ba7e);
    }

    function testWeightedSignatureWithAllGuardians() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Sign with all guardians (total weight 100 >= threshold 60)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, testHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, testHash);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(guardian3Key, testHash);

        // Sort guardians by address
        bytes memory signature;
        if (guardian1 < guardian2 && guardian2 < guardian3) {
            signature = abi.encodePacked(r1, s1, v1, r2, s2, v2, r3, s3, v3);
        } else if (guardian1 < guardian3 && guardian3 < guardian2) {
            signature = abi.encodePacked(r1, s1, v1, r3, s3, v3, r2, s2, v2);
        } else if (guardian2 < guardian1 && guardian1 < guardian3) {
            signature = abi.encodePacked(r2, s2, v2, r1, s1, v1, r3, s3, v3);
        } else if (guardian2 < guardian3 && guardian3 < guardian1) {
            signature = abi.encodePacked(r2, s2, v2, r3, s3, v3, r1, s1, v1);
        } else if (guardian3 < guardian1 && guardian1 < guardian2) {
            signature = abi.encodePacked(r3, s3, v3, r1, s1, v1, r2, s2, v2);
        } else {
            signature = abi.encodePacked(r3, s3, v3, r2, s2, v2, r1, s1, v1);
        }

        vm.startPrank(WALLET);
        bytes4 result = signerModule.checkSignature(signerId(), address(0), testHash, signature);
        vm.stopPrank();

        assertTrue(result == 0x1626ba7e);
    }

    // Test for TOB-KERNEL-16: Verify userOpHash must always be validated
    // Even if proposalHash signatures reach threshold, validation must fail
    // if the last signature (userOpHash) is not from a valid guardian
    function testUserOpHashMustBeValidated() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        // Create a userOp
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 1,
            initCode: "",
            callData: hex"1234",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        bytes32 proposalHash = _proposalHash(userOp);

        // Create a non-guardian account to sign userOpHash
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("nonGuardian");

        // Have guardian1 (weight 50) and guardian2 (weight 30) sign proposalHash
        // Total = 80 >= threshold 60, so old code would return success early
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, proposalHash);
        // Have non-guardian sign userOpHash (this should fail validation)
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(nonGuardianKey, _finalHash(userOp, userOpHash));

        // Sort first two signatures, last one is userOpHash signature
        bytes memory signature;
        if (guardian1 < guardian2) {
            signature = abi.encodePacked(r1, s1, v1, r2, s2, v2, r3, s3, v3);
        } else {
            signature = abi.encodePacked(r2, s2, v2, r1, s1, v1, r3, s3, v3);
        }

        userOp.signature = signature;

        vm.startPrank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(signerId(), userOp, userOpHash);
        vm.stopPrank();

        // Should FAIL because last signer (userOpHash) is not a valid guardian
        // This tests the fix for TOB-KERNEL-16
        assertEq(result, 1); // SIG_VALIDATION_FAILED_UINT
    }

    // Test that same guardian signing both proposalHash and userOpHash doesn't double-count weight
    function testNoDoubleCountingWeight() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        // Create a userOp
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 1,
            initCode: "",
            callData: hex"1234",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        bytes32 proposalHash = _proposalHash(userOp);

        // Guardian1 (weight 50) signs proposalHash
        // Guardian1 also signs userOpHash (should not add weight twice)
        // Total weight should be 50, not 100
        // Threshold is 60, so this should FAIL
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1Key, _finalHash(userOp, userOpHash));

        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        userOp.signature = signature;

        vm.startPrank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(signerId(), userOp, userOpHash);
        vm.stopPrank();

        // Should FAIL because guardian1's weight (50) is only counted once, not twice
        // 50 < threshold (60)
        assertEq(result, 1); // SIG_VALIDATION_FAILED_UINT
    }

    function testReplayableUserOpSignatureSurvivesChainChange() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.prank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: (uint256(0x40) << 248) | 1,
            initCode: "",
            callData: hex"1234",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 chainAgnosticUserOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = userOpSignature(userOp, true);

        vm.chainId(block.chainid + 1);
        vm.prank(WALLET);
        assertEq(
            signerModule.checkUserOpSignature(signerId(), userOp, chainAgnosticUserOpHash),
            0,
            "replayable signature must use the chain-agnostic domain"
        );
    }

    function testFuzzReplayableAndChainBoundDomainsRemainSeparated(
        uint64 rawSourceChainId,
        uint64 rawDestinationChainId,
        uint64 lowNonce,
        bytes32 callDataSalt
    ) public {
        uint256 sourceChainId = uint256(rawSourceChainId);
        uint256 destinationChainId = uint256(rawDestinationChainId);
        if (destinationChainId == sourceChainId) {
            destinationChainId = sourceChainId == type(uint64).max ? 0 : sourceChainId + 1;
        }
        vm.chainId(sourceChainId);

        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.prank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));

        PackedUserOperation memory replayableOp = _auditUserOp((uint256(0x40) << 248) | lowNonce, callDataSalt);
        bytes32 replayableHash = ENTRYPOINT.getUserOpHash(replayableOp);
        replayableOp.signature = userOpSignature(replayableOp, true);

        PackedUserOperation memory chainBoundOp = _auditUserOp(uint256(lowNonce), callDataSalt);
        bytes32 chainBoundHash = ENTRYPOINT.getUserOpHash(chainBoundOp);
        chainBoundOp.signature = userOpSignature(chainBoundOp, true);

        vm.chainId(destinationChainId);
        vm.prank(WALLET);
        assertEq(
            signerModule.checkUserOpSignature(signerId(), replayableOp, replayableHash),
            0,
            "replayable approval changed across chains"
        );

        vm.prank(WALLET);
        (bool success, bytes memory result) = address(signerModule)
            .call(abi.encodeCall(signerModule.checkUserOpSignature, (signerId(), chainBoundOp, chainBoundHash)));
        assertTrue(!success || abi.decode(result, (uint256)) != 0, "chain-bound approval crossed chains");
    }

    function testOldUserOpApprovalFailsAfterReinstall() public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.prank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 1,
            initCode: "",
            callData: hex"1234",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = userOpSignature(userOp, true);
        assertEq(signerModule.configurationEpoch(signerId(), WALLET), 1);

        vm.startPrank(WALLET);
        signerModule.onUninstall(abi.encodePacked(signerId()));
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();
        assertEq(signerModule.configurationEpoch(signerId(), WALLET), 2);

        vm.prank(WALLET);
        (bool success, bytes memory result) = address(signerModule)
            .call(abi.encodeCall(signerModule.checkUserOpSignature, (signerId(), userOp, userOpHash)));
        assertTrue(!success || abi.decode(result, (uint256)) != 0, "old approval must not survive configuration change");
    }

    function testFuzzOldUserOpApprovalFailsAfterEveryReinstallCycle(uint8 rawCycles, bytes32 callDataSalt) public {
        WeightedECDSASigner signerModule = WeightedECDSASigner(address(module));
        vm.prank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));

        PackedUserOperation memory userOp = _auditUserOp(1, callDataSalt);
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = userOpSignature(userOp, true);

        uint256 cycles = bound(uint256(rawCycles), 1, 8);
        vm.startPrank(WALLET);
        for (uint256 i; i < cycles; ++i) {
            signerModule.onUninstall(abi.encodePacked(signerId()));
            signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        }
        vm.stopPrank();
        assertEq(signerModule.configurationEpoch(signerId(), WALLET), cycles + 1);

        vm.prank(WALLET);
        (bool success, bytes memory result) = address(signerModule)
            .call(abi.encodeCall(signerModule.checkUserOpSignature, (signerId(), userOp, userOpHash)));
        assertTrue(!success || abi.decode(result, (uint256)) != 0, "old approval survived a later epoch");
    }

    function _auditUserOp(uint256 nonce, bytes32 callDataSalt)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: WALLET,
            nonce: nonce,
            initCode: "",
            callData: abi.encodePacked(callDataSalt),
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }
}
