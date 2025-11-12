pragma solidity ^0.8.20;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {StatelessValidatorTestBase} from "./base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "./base/StatelessValidatorWithSenderTestBase.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import "forge-std/console.sol";

contract TimelockPolicyTest is PolicyTestBase, StatelessValidatorTestBase, StatelessValidatorWithSenderTestBase {
    uint48 delay = 1 days;
    uint48 expirationPeriod = 1 days;

    function deployModule() internal virtual override returns (IModule) {
        return new TimelockPolicy();
    }

    function _initializeTest() internal override {}

    function installData() internal view override returns (bytes memory) {
        return abi.encode(delay, expirationPeriod);
    }

    function validUserOp() internal view virtual override returns (PackedUserOperation memory) {
        // For a valid userOp execution, we need a proposal that has been created and timelock has passed
        return PackedUserOperation({
            sender: WALLET,
            nonce: 1,
            initCode: "",
            callData: hex"1234", // Some calldata for the proposal
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function invalidUserOp() internal view virtual override returns (PackedUserOperation memory) {
        // An invalid userOp would be one without a proposal
        return PackedUserOperation({
            sender: WALLET,
            nonce: 999, // No proposal created for this nonce
            initCode: "",
            callData: hex"abcd",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function validSignatureData(
        bytes32 /* hash */
    )
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        // For TimelockPolicy, signature validation always passes if the policy is installed
        return (address(0), "");
    }

    function invalidSignatureData(
        bytes32 /* hash */
    )
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        // This will be called from a non-installed account
        return (address(0), "");
    }

    function statelessValidationSignature(
        bytes32,
        /* hash */
        bool valid
    )
        internal
        view
        virtual
        override
        returns (address, bytes memory signature)
    {
        // Signature doesn't matter for TimelockPolicy
        return (address(0), "");
    }

    function statelessValidationSignatureWithSender(
        bytes32,
        /* hash */
        bool valid
    )
        internal
        view
        virtual
        override
        returns (address, bytes memory)
    {
        return statelessValidationSignature(bytes32(0), valid);
    }

    // Override stateless validator tests to use proper data parameter
    function testStatlessValidatorFail() external override {
        IStatelessValidator validatorModule = IStatelessValidator(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (, bytes memory sig) = statelessValidationSignature(message, false);

        // For TimelockPolicy, validation fails if delay or expirationPeriod is 0
        bytes memory invalidData = abi.encode(uint48(0), uint48(0));

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithData(message, sig, invalidData);
        vm.stopPrank();

        assertFalse(result);
    }

    function testStatelessValidatorWithSenderFail() external override {
        IStatelessValidatorWithSender validatorModule = IStatelessValidatorWithSender(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (address caller, bytes memory sig) = statelessValidationSignatureWithSender(message, false);

        // For TimelockPolicy, validation fails if delay or expirationPeriod is 0
        bytes memory invalidData = abi.encode(uint48(0), uint48(0));

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithDataWithSender(caller, message, sig, invalidData);
        vm.stopPrank();

        assertFalse(result);
    }

    // Override the checkUserOpPolicy tests because TimelockPolicy has special behavior
    function testPolicyAfterInstallCheckUserOpPolicySuccess() public payable override {
        TimelockPolicy policyModule = TimelockPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        PackedUserOperation memory userOp = validUserOp();

        // First create a proposal
        vm.startPrank(WALLET);
        policyModule.createProposal(policyId(), WALLET, userOp.callData, userOp.nonce);
        vm.stopPrank();

        // Fast forward past the delay
        vm.warp(block.timestamp + delay + 1);

        // Now execute the proposal
        vm.startPrank(WALLET);
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();

        // For TimelockPolicy, successful execution returns packed validation data with timelock info
        // It should not be SIG_VALIDATION_FAILED_UINT (1)
        assertFalse(validationResult == 1);
    }

    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable override {
        TimelockPolicy policyModule = TimelockPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        PackedUserOperation memory userOp = invalidUserOp();

        // Try to execute without creating a proposal first
        vm.startPrank(WALLET);
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();

        // Should fail (return 1 = SIG_VALIDATION_FAILED_UINT)
        assertEq(validationResult, 1);
    }

    // Override signature policy test because TimelockPolicy always passes for installed accounts
    function testPolicyCheckSignaturePolicyFail() public payable override {
        TimelockPolicy policyModule = TimelockPolicy(address(module));

        // Don't install for this wallet
        address nonInstalledWallet = address(0xBEEF);

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = invalidSignatureData(testHash);

        vm.startPrank(nonInstalledWallet);
        uint256 result = policyModule.checkSignaturePolicy(policyId(), sender, testHash, sigData);
        vm.stopPrank();

        // Should fail for non-installed account
        assertFalse(result == 0);
    }

    // Additional TimelockPolicy-specific tests

    function testCreateProposal() public {
        TimelockPolicy policyModule = TimelockPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        vm.startPrank(WALLET);
        policyModule.createProposal(policyId(), WALLET, callData, nonce);
        vm.stopPrank();

        // Verify proposal was created
        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            policyModule.getProposal(WALLET, callData, nonce, policyId(), WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(validAfter, block.timestamp + delay);
        assertEq(validUntil, block.timestamp + delay + expirationPeriod);
    }

    function testCancelProposal() public {
        TimelockPolicy policyModule = TimelockPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        // Create proposal
        vm.startPrank(WALLET);
        policyModule.createProposal(policyId(), WALLET, callData, nonce);
        vm.stopPrank();

        // Cancel proposal
        vm.startPrank(WALLET);
        policyModule.cancelProposal(policyId(), WALLET, callData, nonce);
        vm.stopPrank();

        // Verify proposal was cancelled
        (TimelockPolicy.ProposalStatus status,,) = policyModule.getProposal(WALLET, callData, nonce, policyId(), WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled));
    }

    function testCreateProposalViaNoOpUserOp() public {
        TimelockPolicy policyModule = TimelockPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        // Create a proposal via checkUserOpPolicy with no-op calldata
        bytes memory proposalCallData = hex"1234";
        uint256 proposalNonce = 1;

        // Encode proposal data in signature
        bytes memory signature = abi.encodePacked(
            uint256(proposalCallData.length), // callDataLength
            proposalCallData, // callData
            proposalNonce // nonce
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "", // Empty calldata = no-op
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: signature
        });

        vm.startPrank(WALLET);
        uint256 result = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();

        // Should return failure (1) because this was proposal creation, not execution
        assertEq(result, 1);

        // Verify proposal was created
        (TimelockPolicy.ProposalStatus status,,) =
            policyModule.getProposal(WALLET, proposalCallData, proposalNonce, policyId(), WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }
}
