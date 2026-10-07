// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule, IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_STATELESS_VALIDATOR,
    SIG_VALIDATION_FAILED_UINT
} from "src/types/Constants.sol";
import {MultiOwnerValidator} from "src/validators/MultiOwnerValidator.sol";

contract BehaviorStatelessSigner is IStatelessValidator {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        pure
        returns (bool)
    {
        return keccak256(signature) == keccak256(abi.encodePacked(hash, data));
    }
}

contract BehaviorRevertingSigner is IStatelessValidator {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function validateSignatureWithData(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        revert("reverting signer");
    }
}

contract MultiOwnerValidatorBehaviorTreeTest is Test {
    address internal constant ACCOUNT = address(0xA11);
    address internal constant OTHER_ACCOUNT = address(0xB22);

    bytes32 internal constant OWNER_ID = keccak256("owner");
    bytes32 internal constant OTHER_OWNER_ID = keccak256("other-owner");
    bytes32 internal constant THIRD_OWNER_ID = keccak256("third-owner");

    MultiOwnerValidator internal validator;
    BehaviorStatelessSigner internal firstSigner;
    BehaviorStatelessSigner internal secondSigner;
    BehaviorRevertingSigner internal revertingSigner;

    function setUp() public {
        validator = new MultiOwnerValidator();
        firstSigner = new BehaviorStatelessSigner();
        secondSigner = new BehaviorStatelessSigner();
        revertingSigner = new BehaviorRevertingSigner();
    }

    modifier whenAccountIsInitialized() {
        _install(ACCOUNT, _single(_config(OWNER_ID, address(firstSigner), hex"a1")));
        _;
    }

    function test_RevertWhen_InstallingAnEmptyRegistry() external {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](0);
        vm.prank(ACCOUNT);
        vm.expectRevert(MultiOwnerValidator.EmptyOwners.selector);
        validator.onInstall(abi.encode(configs));
    }

    function test_RevertWhen_InstallingDuplicateOwnerIds() external {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _config(OWNER_ID, address(firstSigner), hex"a1");
        configs[1] = _config(OWNER_ID, address(secondSigner), hex"b2");

        vm.prank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnerValidator.OwnerAlreadyExists.selector, OWNER_ID));
        validator.onInstall(abi.encode(configs));
    }

    function test_WhenInstallingDifferentStatelessSigners() external {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](3);
        configs[0] = _config(OWNER_ID, address(firstSigner), hex"a1");
        configs[1] = _config(OTHER_OWNER_ID, address(secondSigner), hex"b2");
        configs[2] = _config(THIRD_OWNER_ID, address(firstSigner), hex"c3");

        _install(ACCOUNT, configs);

        assertTrue(validator.isInitialized(ACCOUNT));
        assertEq(validator.ownerCount(ACCOUNT), 3);
        assertEq(validator.ownerIdAt(ACCOUNT, 0), OWNER_ID);
        assertEq(validator.ownerIdAt(ACCOUNT, 1), OTHER_OWNER_ID);
        assertEq(validator.ownerIdAt(ACCOUNT, 2), THIRD_OWNER_ID);
        (address selected, bytes memory data) = validator.owners(ACCOUNT, OTHER_OWNER_ID);
        assertEq(selected, address(secondSigner));
        assertEq(data, hex"b2");
    }

    function test_WhenAddingAnOwner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));

        assertEq(validator.ownerCount(ACCOUNT), 2);
        (address selected, bytes memory data) = validator.owners(ACCOUNT, OTHER_OWNER_ID);
        assertEq(selected, address(secondSigner));
        assertEq(data, hex"b2");
    }

    function test_RevertWhen_AddingAnExistingOwnerId() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnerValidator.OwnerAlreadyExists.selector, OWNER_ID));
        validator.addOwner(_config(OWNER_ID, address(secondSigner), hex"b2"));
    }

    function test_RevertWhen_AddingBeyondMaxOwners() external {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](validator.MAX_OWNERS());
        for (uint256 i; i < configs.length; ++i) {
            configs[i] = _config(bytes32(i + 1), address(firstSigner), abi.encode(i));
        }
        _install(ACCOUNT, configs);

        vm.prank(ACCOUNT);
        vm.expectRevert(MultiOwnerValidator.MaxOwnersExceeded.selector);
        validator.addOwner(_config(bytes32(configs.length + 1), address(secondSigner), hex"ff"));
    }

    function test_WhenUpdatingAnOwner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(secondSigner), hex"b2"));

        assertEq(validator.ownerCount(ACCOUNT), 1);
        (address selected, bytes memory data) = validator.owners(ACCOUNT, OWNER_ID);
        assertEq(selected, address(secondSigner));
        assertEq(data, hex"b2");

        bytes32 hash = keccak256("updated owner");
        vm.startPrank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OWNER_ID, hash, hex"a1")), ERC1271_INVALID
        );
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OWNER_ID, hash, hex"b2")),
            ERC1271_MAGICVALUE
        );
        vm.stopPrank();
    }

    function test_RevertWhen_UpdatingAnUnknownOwner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnerValidator.OwnerDoesNotExist.selector, OTHER_OWNER_ID));
        validator.updateOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));
    }

    function test_WhenRemovingAnOwner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));

        vm.prank(ACCOUNT);
        validator.removeOwner(OWNER_ID);

        assertEq(validator.ownerCount(ACCOUNT), 1);
        assertEq(validator.ownerIdAt(ACCOUNT, 0), OTHER_OWNER_ID);
        (address selected, bytes memory data) = validator.owners(ACCOUNT, OWNER_ID);
        assertEq(selected, address(0));
        assertEq(data.length, 0);
    }

    function test_RevertWhen_RemovingTheLastOwner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        vm.expectRevert(MultiOwnerValidator.CannotRemoveLastOwner.selector);
        validator.removeOwner(OWNER_ID);
    }

    function test_WhenUninstallingTheRegistry() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));

        vm.prank(ACCOUNT);
        validator.onUninstall("");

        assertFalse(validator.isInitialized(ACCOUNT));
        assertEq(validator.ownerCount(ACCOUNT), 0);
        (address first,) = validator.owners(ACCOUNT, OWNER_ID);
        (address second,) = validator.owners(ACCOUNT, OTHER_OWNER_ID);
        assertEq(first, address(0));
        assertEq(second, address(0));
    }

    function test_WhenValidatingWithAnyRegisteredStatelessSigner() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));

        bytes32 hash = keccak256("equal owner rights");
        vm.startPrank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OWNER_ID, hash, hex"a1")),
            ERC1271_MAGICVALUE
        );
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OTHER_OWNER_ID, hash, hex"b2")),
            ERC1271_MAGICVALUE
        );
        vm.stopPrank();
    }

    function test_WhenOwnerIdAndValidationDataDoNotMatch() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));

        bytes32 hash = keccak256("owner binding");
        vm.startPrank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OWNER_ID, hash, hex"b2")), ERC1271_INVALID
        );
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OTHER_OWNER_ID, hash, hex"a1")),
            ERC1271_INVALID
        );
        vm.stopPrank();
    }

    function test_WhenAnOwnerIsRevoked() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(secondSigner), hex"b2"));
        vm.prank(ACCOUNT);
        validator.removeOwner(OWNER_ID);

        bytes32 hash = keccak256("revoked owner");
        vm.prank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(OWNER_ID, hash, hex"a1")), ERC1271_INVALID
        );
    }

    function test_WhenSignatureEnvelopeIsMalformedUnknownOrChildReverts() external whenAccountIsInitialized {
        vm.prank(ACCOUNT);
        validator.addOwner(_config(OTHER_OWNER_ID, address(revertingSigner), ""));

        bytes32 hash = keccak256("malformed envelope");
        vm.startPrank(ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, hex"01"), ERC1271_INVALID);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, _signature(bytes32(uint256(0xBAD)), hash, hex"a1")),
            ERC1271_INVALID
        );
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(OTHER_OWNER_ID)), ERC1271_INVALID
        );
        vm.stopPrank();
    }

    function test_WhenUserOpSenderDoesNotMatchTheCallingAccount() external whenAccountIsInitialized {
        bytes32 hash = keccak256("sender binding");
        PackedUserOperation memory userOp;
        userOp.sender = OTHER_ACCOUNT;
        userOp.signature = _signature(OWNER_ID, hash, hex"a1");

        vm.prank(ACCOUNT);
        assertEq(validator.validateUserOp(userOp, hash), SIG_VALIDATION_FAILED_UINT);
    }

    function test_WhenTwoAccountsUseTheSameOwnerId() external {
        _install(ACCOUNT, _single(_config(OWNER_ID, address(firstSigner), hex"a1")));
        _install(OTHER_ACCOUNT, _single(_config(OWNER_ID, address(secondSigner), hex"b2")));

        bytes32 hash = keccak256("account separation");
        bytes memory firstSignature = _signature(OWNER_ID, hash, hex"a1");
        bytes memory secondSignature = _signature(OWNER_ID, hash, hex"b2");

        vm.prank(ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, firstSignature), ERC1271_MAGICVALUE);
        vm.prank(ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, secondSignature), ERC1271_INVALID);
        vm.prank(OTHER_ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, secondSignature), ERC1271_MAGICVALUE);
        vm.prank(OTHER_ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, firstSignature), ERC1271_INVALID);
    }

    function test_RevertWhen_MutatingFromAnUninitializedAccount() external {
        vm.startPrank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, ACCOUNT));
        validator.addOwner(_config(OWNER_ID, address(firstSigner), hex"a1"));
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, ACCOUNT));
        validator.updateOwner(_config(OWNER_ID, address(firstSigner), hex"a1"));
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, ACCOUNT));
        validator.removeOwner(OWNER_ID);
        vm.stopPrank();
    }

    function _install(address account, MultiOwnerValidator.OwnerConfig[] memory configs) internal {
        vm.prank(account);
        validator.onInstall(abi.encode(configs));
    }

    function _single(MultiOwnerValidator.OwnerConfig memory config)
        internal
        pure
        returns (MultiOwnerValidator.OwnerConfig[] memory configs)
    {
        configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = config;
    }

    function _config(bytes32 ownerId, address statelessValidator, bytes memory validationData)
        internal
        pure
        returns (MultiOwnerValidator.OwnerConfig memory)
    {
        return MultiOwnerValidator.OwnerConfig(ownerId, statelessValidator, validationData);
    }

    function _signature(bytes32 ownerId, bytes32 hash, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(ownerId, hash, validationData);
    }
}
