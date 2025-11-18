pragma solidity ^0.8.20;

import {ValidatorTestBase} from "./base/ValidatorTestBase.sol";
import {StatelessValidatorTestBase} from "./base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "./base/StatelessValidatorWithSenderTestBase.sol";
import {ECDSAValidator} from "src/validators/ECDSAValidator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule, IHook} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "src/types/Constants.sol";
import "forge-std/console.sol";

contract ECDSAValidatorTest is ValidatorTestBase, StatelessValidatorTestBase, StatelessValidatorWithSenderTestBase {
    address owner;
    uint256 ownerKey;

    function deployModule() internal virtual override returns (IModule) {
        return new ECDSAValidator();
    }

    function _initializeTest() internal override {
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    function installData() internal view override returns (bytes memory) {
        return abi.encodePacked(owner);
    }

    function userOpSignature(PackedUserOperation memory userOp, bool valid)
        internal
        view
        virtual
        override
        returns (bytes memory)
    {
        bytes32 hash = ENTRYPOINT.getUserOpHash(userOp);
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function erc1271Signature(bytes32 hash, bool valid)
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return (address(0), abi.encodePacked(r, s, v));
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return (address(0), abi.encodePacked(r, s, v));
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

    // Test Hook functionality
    function testModuleTypeHook() public view {
        ECDSAValidator validatorModule = ECDSAValidator(address(module));
        bool result = validatorModule.isModuleType(MODULE_TYPE_HOOK);
        assertTrue(result);
    }

    // Test with ethSignedMessage hash
    function testStatelessValidationWithDifferentOwner() public {
        ECDSAValidator validatorModule = ECDSAValidator(address(module));

        // Create a different owner
        (address otherOwner, uint256 otherOwnerKey) = makeAddrAndKey("otherOwner");

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherOwnerKey, message);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Use otherOwner as the data parameter
        bytes memory data = abi.encodePacked(otherOwner);

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithData(message, sig, data);
        vm.stopPrank();

        assertTrue(result);
    }

    function testStatelessValidationWithSenderWithDifferentOwner() public {
        ECDSAValidator validatorModule = ECDSAValidator(address(module));

        // Create a different owner
        (address otherOwner, uint256 otherOwnerKey) = makeAddrAndKey("otherOwner");

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherOwnerKey, message);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Use otherOwner as the data parameter
        bytes memory data = abi.encodePacked(otherOwner);

        address sender = address(0x5678);
        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithDataWithSender(sender, message, sig, data);
        vm.stopPrank();

        assertTrue(result);
    }
}
