pragma solidity ^0.8.20;

import {SignerTestBase} from "./base/SignerTestBase.sol";
import {StatelessValidatorTestBase} from "./base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "./base/StatelessValidatorWithSenderTestBase.sol";
import {ECDSASigner} from "src/signers/ECDSASigner.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import "forge-std/console.sol";

contract ECDSASignerTest is
    SignerTestBase,
    StatelessValidatorTestBase,
    StatelessValidatorWithSenderTestBase
{
    address owner;
    uint256 ownerKey;
    function deployModule() internal virtual override returns (IModule) {
        return new ECDSASigner();
    }

    function _initializeTest() internal override {
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    function installData() internal view override returns (bytes memory) {
        return abi.encodePacked(owner);
    }

    function userOpSignature(
        PackedUserOperation memory userOp,
        bool valid
    ) internal view virtual override returns (bytes memory) {
        console.log("owner:", owner);
        bytes32 hash = ENTRYPOINT.getUserOpHash(userOp);
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function erc1271Signature(
        bytes32 hash,
        bool valid
    ) internal view virtual override returns (address,bytes memory) {
        if (!valid) {
            hash = keccak256(abi.encodePacked("invalid", hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return (address(0), abi.encodePacked(r, s, v));
    }

    function statelessValidationSignature(
        bytes32 hash,
        bool valid
    ) internal view virtual override returns (address, bytes memory) {
        return erc1271Signature(hash, valid);
    }

    function statelessValidationSignatureWithSender(
        bytes32 hash,
        bool valid
    ) internal view virtual override returns (address, bytes memory) {
        return erc1271Signature(hash, valid);
    }
}
