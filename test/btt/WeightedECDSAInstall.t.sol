// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

/**
 * @title WeightedECDSAInstallTest
 * @notice BTT tests for installation, uninstallation, and threshold zero checks
 */
contract WeightedECDSAInstallTest is Test {
    WeightedECDSASigner signer;
    IEntryPoint entrypoint;

    address constant WALLET = address(0x1234);
    bytes32 constant SIGNER_ID = keccak256("TEST_SIGNER_ID");

    address guardian1;
    uint256 guardian1Key;
    address guardian2;
    uint256 guardian2Key;

    function setUp() public {
        signer = new WeightedECDSASigner();
        entrypoint = EntryPointLib.deploy();

        (guardian1, guardian1Key) = makeAddrAndKey("guardian1");
        (guardian2, guardian2Key) = makeAddrAndKey("guardian2");
    }

    // ============ Installation Tests ============

    modifier whenInstallingSigner() {
        _;
    }

    function test_RevertWhen_GuardiansAndWeightsLengthMismatch() external whenInstallingSigner {
        address[] memory guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;

        uint24[] memory weights = new uint24[](1); // Mismatch: 1 weight for 2 guardians
        weights[0] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        // it should revert
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.LengthMismatch.selector);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function test_RevertWhen_GuardianIsSelf() external whenInstallingSigner {
        address[] memory guardians = new address[](1);
        guardians[0] = WALLET; // Guardian is msg.sender

        uint24[] memory weights = new uint24[](1);
        weights[0] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        // it should revert
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.GuardianCannotBeSelf.selector);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function test_RevertWhen_GuardianIsAddressZero() external whenInstallingSigner {
        address[] memory guardians = new address[](1);
        guardians[0] = address(0);

        uint24[] memory weights = new uint24[](1);
        weights[0] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        // it should revert
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroAddressGuardian.selector);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function test_RevertWhen_WeightIsZero() external whenInstallingSigner {
        address[] memory guardians = new address[](1);
        guardians[0] = guardian1;

        uint24[] memory weights = new uint24[](1);
        weights[0] = 0; // Zero weight

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        // it should revert
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeight.selector);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function test_RevertWhen_GuardianIsAlreadyEnabled() external whenInstallingSigner {
        address[] memory guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian1; // Duplicate guardian

        uint24[] memory weights = new uint24[](2);
        weights[0] = 50;
        weights[1] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        // it should revert
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.GuardianAlreadyEnabled.selector);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function test_WhenAllParametersAreValid() external whenInstallingSigner {
        address[] memory guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;

        uint24[] memory weights = new uint24[](2);
        weights[0] = 50;
        weights[1] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(60));

        // it should install successfully
        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));

        (uint24 totalWeight, uint24 threshold,) = signer.weightedStorage(SIGNER_ID, WALLET);
        assertEq(totalWeight, 100);
        assertEq(threshold, 60);
    }

    // ============ Uninstallation Tests ============

    modifier whenUninstallingSigner() {
        _;
    }

    function test_WhenSignerIsNotInitialized() external whenUninstallingSigner {
        // it should revert with NotInitialized
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        signer.onUninstall(abi.encodePacked(SIGNER_ID));
    }

    function test_WhenSignerIsInitialized() external whenUninstallingSigner {
        // First install
        address[] memory guardians = new address[](1);
        guardians[0] = guardian1;

        uint24[] memory weights = new uint24[](1);
        weights[0] = 50;

        bytes memory installData = abi.encode(guardians, weights, uint24(50));

        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));

        // Verify installed
        (uint24 totalWeight,,) = signer.weightedStorage(SIGNER_ID, WALLET);
        assertEq(totalWeight, 50);

        // it should uninstall successfully
        vm.prank(WALLET);
        signer.onUninstall(abi.encodePacked(SIGNER_ID));

        // Verify uninstalled
        (totalWeight,,) = signer.weightedStorage(SIGNER_ID, WALLET);
        assertEq(totalWeight, 0);
    }

    function test_WhenUninstallingWithMultipleGuardians() external whenUninstallingSigner {
        // Install with 3 guardians
        address guardian3;
        (guardian3,) = makeAddrAndKey("guardian3");

        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        uint24[] memory weights = new uint24[](3);
        weights[0] = 30;
        weights[1] = 30;
        weights[2] = 40;

        bytes memory installData = abi.encode(guardians, weights, uint24(60));

        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));

        // Verify installed
        (uint24 totalWeight,,) = signer.weightedStorage(SIGNER_ID, WALLET);
        assertEq(totalWeight, 100);

        // Uninstall
        vm.prank(WALLET);
        signer.onUninstall(abi.encodePacked(SIGNER_ID));

        // Verify uninstalled
        (totalWeight,,) = signer.weightedStorage(SIGNER_ID, WALLET);
        assertEq(totalWeight, 0);

        // Verify guardians are cleared
        (uint24 g1Weight,) = signer.guardian(guardian1, SIGNER_ID, WALLET);
        (uint24 g2Weight,) = signer.guardian(guardian2, SIGNER_ID, WALLET);
        (uint24 g3Weight,) = signer.guardian(guardian3, SIGNER_ID, WALLET);
        assertEq(g1Weight, 0);
        assertEq(g2Weight, 0);
        assertEq(g3Weight, 0);
    }

    // ============ Threshold Zero Tests ============

    modifier whenCheckingThresholdZero() {
        _;
    }

    function test_WhenValidatingUserOpWithThresholdZero() external whenCheckingThresholdZero {
        // Don't install the signer - threshold will be 0

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: hex"1234",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: hex"00" // Some signature data
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);

        // it should return SIG_VALIDATION_FAILED
        vm.prank(WALLET);
        uint256 result = signer.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_WhenValidatingERC1271WithThresholdZero() external whenCheckingThresholdZero {
        // Don't install the signer - threshold will be 0

        bytes32 testHash = keccak256("test");
        bytes memory signature = new bytes(65);

        // it should return ERC1271_INVALID
        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signature);
        assertEq(result, ERC1271_INVALID);
    }

    // ============ Module Type Tests ============

    modifier whenCheckingModuleType() {
        _;
    }

    function test_WhenTypeIsSigner() external whenCheckingModuleType {
        assertTrue(signer.isModuleType(6)); // MODULE_TYPE_SIGNER
    }

    function test_WhenTypeIsStatelessValidator() external whenCheckingModuleType {
        assertTrue(signer.isModuleType(7)); // MODULE_TYPE_STATELESS_VALIDATOR
    }

    function test_WhenTypeIsStatelessValidatorWithSender() external whenCheckingModuleType {
        assertTrue(signer.isModuleType(10)); // MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
    }

    function test_WhenTypeIsValidator() external whenCheckingModuleType {
        assertFalse(signer.isModuleType(1)); // MODULE_TYPE_VALIDATOR - not supported
    }

    // ============ Stateless Validator With Sender Tests ============

    function test_WhenValidatingSignatureWithDataWithSender() external {
        bytes32 hash = keccak256("test");

        // Create sorted guardians
        address[] memory guardians = new address[](2);
        uint256[] memory keys = new uint256[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        keys[0] = guardian1Key;
        keys[1] = guardian2Key;

        // Sort
        if (guardian1 > guardian2) {
            (guardians[0], guardians[1]) = (guardians[1], guardians[0]);
            (keys[0], keys[1]) = (keys[1], keys[0]);
        }

        uint24[] memory weights = new uint24[](2);
        weights[0] = 50;
        weights[1] = 50;

        bytes memory data = abi.encode(guardians, weights, uint24(50));

        // Sign with both guardians
        bytes memory signatures;
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(keys[0], hash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(keys[1], hash);
        signatures = abi.encodePacked(signatures, r2, s2, v2);

        bool result = signer.validateSignatureWithDataWithSender(address(0), hash, signatures, data);
        assertTrue(result);
    }
}
