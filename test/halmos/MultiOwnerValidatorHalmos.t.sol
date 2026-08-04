// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_STATELESS_VALIDATOR,
    SIG_VALIDATION_FAILED_UINT
} from "src/types/Constants.sol";
import {MultiOwnerValidator} from "src/validators/MultiOwnerValidator.sol";

interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @notice Deterministic stateless-validator boundary for the registry proofs.
/// @dev A signature is accepted exactly when it equals the supplied validation data.
contract MultiOwnerStatelessSignerHalmosStub is IStatelessValidator {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function validateSignatureWithData(bytes32, bytes calldata signature, bytes calldata data)
        external
        pure
        returns (bool)
    {
        return keccak256(signature) == keccak256(data);
    }
}

/// @title MultiOwnerValidatorHalmos
/// @author taek <leekt216@gmail.com>
/// @notice Symbolic storage, lifecycle, dispatch, selection, and account-isolation properties for
///         the stateless-signer multi-owner root validator.
/// @dev TCB / MODELING: the registry and external dispatch execute unchanged. The selected
///      `IStatelessValidator` is modeled as a deterministic oracle that accepts exactly when the
///      owner signature equals its supplied validation data. The properties prove registry and
///      dispatch correctness, not the soundness of an arbitrary child signer.
contract MultiOwnerValidatorHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant ACCOUNT = address(0xA11);
    address internal constant OTHER_ACCOUNT = address(0xB22);
    bytes32 internal constant FIXED_ID = bytes32(uint256(0x1111));
    bytes32 internal constant SECOND_ID = bytes32(uint256(0x2222));

    MultiOwnerValidator internal validator;
    address internal statelessSigner;

    function setUp() external {
        validator = MultiOwnerValidator(address(uint160(uint256(keccak256("MultiOwnerValidator")))));
        statelessSigner = address(uint160(uint256(keccak256("MultiOwnerStatelessSigner"))));
        vm.etch(address(validator), type(MultiOwnerValidator).runtimeCode);
        vm.etch(statelessSigner, type(MultiOwnerStatelessSignerHalmosStub).runtimeCode);
    }

    function check_InstallStoresExactlyTheScopedRegistry(
        bytes32 firstId,
        bytes32 secondId,
        address firstOwner,
        address secondOwner
    ) external {
        vm.assume(firstId != bytes32(0) && secondId != bytes32(0));
        vm.assume(firstId != secondId);
        vm.assume(firstOwner != address(0) && secondOwner != address(0));

        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _config(firstId, firstOwner);
        configs[1] = _config(secondId, secondOwner);

        vm.prank(ACCOUNT);
        validator.onInstall(abi.encode(configs));

        assert(validator.isInitialized(ACCOUNT));
        assert(validator.ownerCount(ACCOUNT) == 2);
        assert(validator.ownerIdAt(ACCOUNT, 0) == firstId);
        assert(validator.ownerIdAt(ACCOUNT, 1) == secondId);
        (address firstSigner, bytes memory firstData) = validator.owners(ACCOUNT, firstId);
        (address secondSigner, bytes memory secondData) = validator.owners(ACCOUNT, secondId);
        assert(firstSigner == statelessSigner && keccak256(firstData) == keccak256(abi.encode(firstOwner)));
        assert(secondSigner == statelessSigner && keccak256(secondData) == keccak256(abi.encode(secondOwner)));

        assert(!validator.isInitialized(OTHER_ACCOUNT));
        assert(validator.ownerCount(OTHER_ACCOUNT) == 0);
        (address otherSigner, bytes memory otherData) = validator.owners(OTHER_ACCOUNT, firstId);
        assert(otherSigner == address(0) && otherData.length == 0);
    }

    function check_AddUpdateRemovePreservesCountAndEnumeration(
        address firstOwner,
        address secondOwner,
        address rotatedOwner
    ) external {
        vm.assume(firstOwner != address(0) && secondOwner != address(0) && rotatedOwner != address(0));

        _installOne(ACCOUNT, FIXED_ID, firstOwner);

        vm.prank(ACCOUNT);
        validator.addOwner(_config(SECOND_ID, secondOwner));
        assert(validator.ownerCount(ACCOUNT) == 2);

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(SECOND_ID, rotatedOwner));
        assert(validator.ownerCount(ACCOUNT) == 2);
        (address rotatedSigner, bytes memory rotatedData) = validator.owners(ACCOUNT, SECOND_ID);
        assert(rotatedSigner == statelessSigner && keccak256(rotatedData) == keccak256(abi.encode(rotatedOwner)));

        vm.prank(ACCOUNT);
        validator.removeOwner(FIXED_ID);
        assert(validator.ownerCount(ACCOUNT) == 1);
        assert(validator.ownerIdAt(ACCOUNT, 0) == SECOND_ID);
        (address removedSigner, bytes memory removedData) = validator.owners(ACCOUNT, FIXED_ID);
        assert(removedSigner == address(0) && removedData.length == 0);
    }

    function check_LastOwnerCannotBeRemoved(address owner) external {
        vm.assume(owner != address(0));
        _installOne(ACCOUNT, FIXED_ID, owner);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory returndata) = address(validator).call(abi.encodeCall(validator.removeOwner, (FIXED_ID)));

        assert(!ok);
        assert(_selector(returndata) == MultiOwnerValidator.CannotRemoveLastOwner.selector);
        assert(validator.ownerCount(ACCOUNT) == 1);
        assert(validator.isInitialized(ACCOUNT));
    }

    function check_UninstallClearsEveryOwner(address firstOwner, address secondOwner) external {
        vm.assume(firstOwner != address(0) && secondOwner != address(0));

        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _config(FIXED_ID, firstOwner);
        configs[1] = _config(SECOND_ID, secondOwner);
        vm.prank(ACCOUNT);
        validator.onInstall(abi.encode(configs));

        vm.prank(ACCOUNT);
        validator.onUninstall("");

        assert(!validator.isInitialized(ACCOUNT));
        assert(validator.ownerCount(ACCOUNT) == 0);
        (address firstSigner, bytes memory firstData) = validator.owners(ACCOUNT, FIXED_ID);
        (address secondSigner, bytes memory secondData) = validator.owners(ACCOUNT, SECOND_ID);
        assert(firstSigner == address(0) && firstData.length == 0);
        assert(secondSigner == address(0) && secondData.length == 0);
    }

    function check_SameOwnerIdIsSeparatedAcrossAccounts(address firstOwner, address secondOwner) external {
        vm.assume(firstOwner != address(0) && secondOwner != address(0));

        _installOne(ACCOUNT, FIXED_ID, firstOwner);
        _installOne(OTHER_ACCOUNT, FIXED_ID, secondOwner);

        (, bytes memory firstData) = validator.owners(ACCOUNT, FIXED_ID);
        (, bytes memory secondData) = validator.owners(OTHER_ACCOUNT, FIXED_ID);
        assert(keccak256(firstData) == keccak256(abi.encode(firstOwner)));
        assert(keccak256(secondData) == keccak256(abi.encode(secondOwner)));
    }

    function check_SelectedOwnerRoutesItsExactValidationData(bytes32 hash, address owner, address otherOwner) external {
        vm.assume(owner != address(0) && otherOwner != address(0));
        vm.assume(owner != otherOwner);
        _installOne(ACCOUNT, FIXED_ID, owner);

        vm.prank(ACCOUNT);
        bytes4 accepted =
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(FIXED_ID, abi.encode(owner)));
        vm.prank(ACCOUNT);
        bytes4 rejected =
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(FIXED_ID, abi.encode(otherOwner)));

        assert(accepted == ERC1271_MAGICVALUE);
        assert(rejected == ERC1271_INVALID);
    }

    function check_UnknownOwnerCanNeverValidate(bytes32 unknownId, bytes32 hash, address owner) external {
        vm.assume(owner != address(0));
        vm.assume(unknownId != FIXED_ID);
        _installOne(ACCOUNT, FIXED_ID, owner);

        bytes memory signature = abi.encodePacked(unknownId, abi.encode(owner));
        vm.prank(ACCOUNT);
        bytes4 result = validator.isValidSignatureWithSender(address(0), hash, signature);
        assert(result == ERC1271_INVALID);
    }

    function check_UserOpSenderMustEqualCallingAccount(bytes32 hash, bytes32 selectedId, address owner) external {
        vm.assume(owner != address(0));
        _installOne(ACCOUNT, FIXED_ID, owner);

        PackedUserOperation memory userOp;
        userOp.sender = OTHER_ACCOUNT;
        userOp.signature = abi.encodePacked(selectedId, abi.encode(owner));

        vm.prank(ACCOUNT);
        uint256 result = validator.validateUserOp(userOp, hash);
        assert(result == SIG_VALIDATION_FAILED_UINT);
    }

    function _installOne(address account, bytes32 ownerId, address owner) internal {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = _config(ownerId, owner);
        vm.prank(account);
        validator.onInstall(abi.encode(configs));
    }

    function _config(bytes32 ownerId, address owner) internal view returns (MultiOwnerValidator.OwnerConfig memory) {
        return MultiOwnerValidator.OwnerConfig(ownerId, statelessSigner, abi.encode(owner));
    }

    function _selector(bytes memory returndata) internal pure returns (bytes4 result) {
        if (returndata.length >= 4) {
            assembly ("memory-safe") {
                result := mload(add(returndata, 0x20))
            }
        }
    }
}
