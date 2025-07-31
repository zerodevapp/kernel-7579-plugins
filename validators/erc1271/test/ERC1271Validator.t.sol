pragma solidity ^0.8.0;

import {ERC1271Validator} from "../src/ERC1271Validator.sol";
import {MockCallee, KernelTestBase} from "kernel/test/base/KernelTestBase.sol";
import {PackedUserOperation} from "kernel/test/base/KernelTestBase.sol";
import {ValidatorLib} from "kernel/test/base/KernelTestBase.sol";
import {IHook, IValidator} from "kernel/test/base/KernelTestBase.sol";
import {ValidatorLib, ValidationId, ValidationMode, ValidationType} from "kernel/test/base/KernelTestBase.sol";
import {VALIDATION_MODE_ENABLE, VALIDATION_TYPE_VALIDATOR} from "kernel/test/base/KernelTestBase.sol";

import {SafeProxyFactory} from "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {CompatibilityFallbackHandler} from "safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";

contract WebAuthnValidatorTest is KernelTestBase {
    ERC1271Validator erc1271Validator;
    SafeProxyFactory proxyFactory;
    Safe safeSingleton;
    CompatibilityFallbackHandler handler;

    Safe ownerSafe;
    address owner;
    uint256 ownerKey;

    function _setRootValidationConfig() internal override {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        erc1271Validator = new ERC1271Validator();
        proxyFactory = new SafeProxyFactory();
        safeSingleton = new Safe();
        handler = new CompatibilityFallbackHandler();

        address[] memory owners = new address[](1);
        owners[0] = owner;

        ownerSafe = Safe(payable(address(proxyFactory.createProxyWithNonce(
            address(safeSingleton),
            abi.encodeWithSelector(
                Safe.setup.selector, owners, 1, address(0), hex"", address(handler), address(0), 0, address(0)
            ),
            0
        ))));
        rootValidation = ValidatorLib.validatorToIdentifier(IValidator(address(erc1271Validator)));
        rootValidationConfig =
            RootValidationConfig({hook: IHook(address(0)), hookData: hex"", validatorData: abi.encodePacked(ownerSafe)});
    }

    function _rootSignDigest(bytes32 digest, bool success) internal override returns (bytes memory data) {
        if (success) {
            bytes memory encoded = handler.encodeMessageDataForSafe(ownerSafe, abi.encode(digest));
            bytes32 messageHash = keccak256(encoded);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, messageHash);
            return abi.encodePacked(r, s, v);
        } else {
            digest = keccak256(abi.encodePacked(digest));
            bytes memory encoded = handler.encodeMessageDataForSafe(ownerSafe, abi.encode(digest));
            bytes32 messageHash = keccak256(encoded);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, messageHash);
            return abi.encodePacked(r, s, v);
        }
    }

    function _rootSignUserOp(PackedUserOperation memory op, bytes32 userOpHash, bool success)
        internal
        override
        returns (bytes memory)
    {
        return _rootSignDigest(userOpHash, success);
    }
}
