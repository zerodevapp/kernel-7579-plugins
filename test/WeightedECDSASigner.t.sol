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

        // Manually compute EIP712 hash
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSASigner"),
                keccak256("0.0.2"),
                block.chainid,
                address(module)
            )
        );

        bytes32 proposalHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                        userOp.sender,
                        signerId(),
                        keccak256(userOp.callData),
                        userOp.nonce
                    )
                )
            )
        );

        // Sign proposalHash with guardian1 (first signature, sorted order)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);
        // Sign userOpHash with guardian2 (last signature)
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, userOpHash);

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
}
