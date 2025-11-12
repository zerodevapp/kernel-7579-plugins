pragma solidity ^0.8.20;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {StatelessValidatorTestBase} from "./base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "./base/StatelessValidatorWithSenderTestBase.sol";
import {SignaturePolicy} from "src/policies/SignaturePolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import "forge-std/console.sol";

contract SignaturePolicyTest is PolicyTestBase, StatelessValidatorWithSenderTestBase {
    address allowedCaller;
    address disallowedCaller;

    function deployModule() internal virtual override returns (IModule) {
        return new SignaturePolicy();
    }

    function _initializeTest() internal override {
        allowedCaller = address(0x5678);
        disallowedCaller = address(0x9ABC);
    }

    function installData() internal view override returns (bytes memory) {
        address[] memory callers = new address[](1);
        callers[0] = allowedCaller;
        return abi.encode(callers);
    }

    function validUserOp() internal view virtual override returns (PackedUserOperation memory) {
        // SignaturePolicy always passes for live policies in checkUserOpPolicy
        return PackedUserOperation({
            sender: WALLET,
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

    function invalidUserOp() internal view virtual override returns (PackedUserOperation memory) {
        // For SignaturePolicy, userOp validation always passes if policy is live
        // To make it fail, we would need to use a non-live policy, but that's tested separately
        // For this test, we'll just return a userOp (the fail case is tested by not installing)
        return PackedUserOperation({
            sender: address(0xDEAD), // Different sender to simulate non-installed policy
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

    function validSignatureData(bytes32 hash)
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        // Return allowed caller and any signature (signature content doesn't matter for SignaturePolicy)
        return (allowedCaller, "");
    }

    function invalidSignatureData(bytes32 hash)
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        // Return disallowed caller and any signature
        return (disallowedCaller, "");
    }

    // Override the fail test because SignaturePolicy's checkUserOpPolicy doesn't validate based on userOp content
    // It only checks if the policy is live for the calling account
    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable override {
        SignaturePolicy policyModule = SignaturePolicy(address(module));

        // Don't install for this account
        address nonInstalledAccount = address(0xBEEF);

        PackedUserOperation memory userOp = validUserOp();

        vm.startPrank(nonInstalledAccount);
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();
        assertFalse(validationResult == 0);
    }

    function statelessValidationSignatureWithSender(bytes32 hash, bool valid)
        internal
        view
        virtual
        override
        returns (address, bytes memory)
    {
        return valid ? validSignatureData(hash) : invalidSignatureData(hash);
    }
}
