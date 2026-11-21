// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {RecoveryAction} from "src/actions/RecoveryAction.sol";
import {IModule, IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {ECDSASigner} from "src/signers/ECDSASigner.sol";
import {
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_STATELESS_VALIDATOR,
    SIG_VALIDATION_FAILED_UINT
} from "src/types/Constants.sol";
import {MultiOwnerValidator} from "src/validators/MultiOwnerValidator.sol";

contract AuditStatelessSigner is IStatelessValidator {
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

contract AuditRecoveryAccount {
    function callModule(address module, bytes calldata callData) external returns (bytes memory) {
        return _call(module, callData, false);
    }

    function recover(address action, address validator, bytes calldata newConfiguration)
        external
        returns (bytes memory)
    {
        return _call(action, abi.encodeCall(RecoveryAction.doRecovery, (validator, newConfiguration)), true);
    }

    function _call(address target, bytes memory callData, bool delegate) private returns (bytes memory returnData) {
        bool success;
        if (delegate) {
            (success, returnData) = target.delegatecall(callData);
        } else {
            (success, returnData) = target.call(callData);
        }
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }
}

contract MultiOwnerValidatorAuditTest is Test {
    address internal constant ACCOUNT = address(0xA11CE);
    bytes32 internal constant OWNER_ID = keccak256("audit-owner");
    bytes32 internal constant SECOND_OWNER_ID = keccak256("second-audit-owner");

    MultiOwnerValidator internal validator;
    AuditStatelessSigner internal signer;

    function setUp() external {
        validator = new MultiOwnerValidator();
        signer = new AuditStatelessSigner();
    }

    function testValidationReadsOnlyAccountAssociatedOwnerSlots() external {
        bytes memory validationData = _patternedBytes(97);
        _install(_single(_config(OWNER_ID, address(signer), validationData)));

        bytes32 hash = keccak256("associated validation storage");
        bytes memory ownerSignature = abi.encodePacked(hash, validationData);

        vm.record();
        vm.prank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(OWNER_ID, ownerSignature)),
            ERC1271_MAGICVALUE
        );

        (bytes32[] memory reads,) = vm.accesses(address(validator));
        uint256 base = uint256(_ownerBaseSlot(ACCOUNT, OWNER_ID));
        assertTrue(reads.length >= 5);
        assertTrue(_contains(reads, bytes32(base)));
        for (uint256 i = 1; i <= 4; ++i) {
            assertTrue(_contains(reads, bytes32(base + i)));
        }
        for (uint256 i; i < reads.length; ++i) {
            uint256 slot = uint256(reads[i]);
            assertGe(slot, base);
            assertLe(slot, base + 128);
        }
    }

    function testMaximumValidationDataReadsEveryWordFromAssociatedFixedSlots() external {
        bytes memory validationData = _patternedBytes(validator.MAX_TOTAL_VALIDATION_DATA());
        _install(_single(_config(OWNER_ID, address(signer), validationData)));

        bytes32 hash = keccak256("maximum associated validation storage");
        bytes memory ownerSignature = abi.encodePacked(hash, validationData);

        vm.record();
        vm.prank(ACCOUNT);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(OWNER_ID, ownerSignature)),
            ERC1271_MAGICVALUE
        );

        (bytes32[] memory reads,) = vm.accesses(address(validator));
        uint256 base = uint256(_ownerBaseSlot(ACCOUNT, OWNER_ID));
        assertTrue(reads.length >= 129);
        for (uint256 i; i <= 128; ++i) {
            assertTrue(_contains(reads, bytes32(base + i)));
        }
        for (uint256 i; i < reads.length; ++i) {
            uint256 slot = uint256(reads[i]);
            assertGe(slot, base);
            assertLe(slot, base + 128);
        }
    }

    function testAggregateValidationDataLimitAppliesAcrossInstallAddAndUpdate() external {
        uint256 maximum = validator.MAX_TOTAL_VALIDATION_DATA();
        bytes memory maxData = _patternedBytes(maximum);
        _install(_single(_config(OWNER_ID, address(signer), maxData)));
        assertEq(validator.totalValidationData(ACCOUNT), maximum);

        vm.prank(ACCOUNT);
        vm.expectRevert(
            abi.encodeWithSelector(MultiOwnerValidator.ValidationDataLimitExceeded.selector, maximum + 1, maximum)
        );
        validator.addOwner(_config(SECOND_OWNER_ID, address(signer), hex"01"));

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(signer), _patternedBytes(maximum - 1)));
        vm.prank(ACCOUNT);
        validator.addOwner(_config(SECOND_OWNER_ID, address(signer), hex"01"));
        assertEq(validator.totalValidationData(ACCOUNT), maximum);
    }

    function testInstallRejectsAggregateValidationDataAboveLimit() external {
        uint256 maximum = validator.MAX_TOTAL_VALIDATION_DATA();
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _config(OWNER_ID, address(signer), _patternedBytes(maximum));
        configs[1] = _config(SECOND_OWNER_ID, address(signer), hex"01");

        vm.prank(ACCOUNT);
        vm.expectRevert(
            abi.encodeWithSelector(MultiOwnerValidator.ValidationDataLimitExceeded.selector, maximum + 1, maximum)
        );
        validator.onInstall(abi.encode(configs));
        assertEq(validator.ownerCount(ACCOUNT), 0);
        assertEq(validator.totalValidationData(ACCOUNT), 0);
    }

    function testTotalValidationDataTracksUpdateRemoveAndUninstall() external {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _config(OWNER_ID, address(signer), _patternedBytes(70));
        configs[1] = _config(SECOND_OWNER_ID, address(signer), _patternedBytes(30));
        _install(configs);
        assertEq(validator.totalValidationData(ACCOUNT), 100);

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(signer), _patternedBytes(5)));
        assertEq(validator.totalValidationData(ACCOUNT), 35);

        vm.prank(ACCOUNT);
        validator.removeOwner(SECOND_OWNER_ID);
        assertEq(validator.totalValidationData(ACCOUNT), 5);

        vm.prank(ACCOUNT);
        validator.onUninstall("");
        assertEq(validator.totalValidationData(ACCOUNT), 0);
    }

    function testMaximumValidationDataRoundTripsAndUninstallsWithinBound() external {
        bytes memory validationData = _patternedBytes(validator.MAX_TOTAL_VALIDATION_DATA());
        _install(_single(_config(OWNER_ID, address(signer), validationData)));

        (, bytes memory storedData) = validator.owners(ACCOUNT, OWNER_ID);
        assertEq(storedData, validationData);

        uint256 gasBefore = gasleft();
        vm.prank(ACCOUNT);
        validator.onUninstall("");
        uint256 gasUsed = gasBefore - gasleft();
        assertLt(gasUsed, 5_000_000);
    }

    function testMaximumOwnerCountAndAggregateDataRecoverWithinBlockGasLimit() external {
        AuditRecoveryAccount account = new AuditRecoveryAccount();
        RecoveryAction action = new RecoveryAction();
        uint256 ownerCount = validator.MAX_OWNERS();
        uint256 bytesPerOwner = validator.MAX_TOTAL_VALIDATION_DATA() / ownerCount;
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](ownerCount);
        for (uint256 i; i < ownerCount; ++i) {
            configs[i] = _config(bytes32(i + 1), address(signer), _patternedBytes(bytesPerOwner));
        }

        account.callModule(address(validator), abi.encodeCall(validator.onInstall, (abi.encode(configs))));
        assertEq(validator.ownerCount(address(account)), ownerCount);
        assertEq(validator.totalValidationData(address(account)), validator.MAX_TOTAL_VALIDATION_DATA());

        MultiOwnerValidator.OwnerConfig[] memory replacement =
            _single(_config(keccak256("replacement owner"), address(signer), _patternedBytes(20)));
        uint256 gasBefore = gasleft();
        account.recover(address(action), address(validator), abi.encode(replacement));
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 30_000_000);
        assertEq(validator.ownerCount(address(account)), 1);
        assertEq(validator.totalValidationData(address(account)), 20);
        assertEq(validator.ownerIdAt(address(account), 0), keccak256("replacement owner"));
    }

    function testFuzzValidationDataRoundTripsAcrossWordBoundaries(uint16 initialRaw, uint16 replacementRaw) external {
        uint256 initialLength = bound(initialRaw, 0, 512);
        uint256 replacementLength = bound(replacementRaw, 0, 512);
        bytes memory initialData = _patternedBytes(initialLength);
        bytes memory replacementData = _patternedBytes(replacementLength);

        _install(_single(_config(OWNER_ID, address(signer), initialData)));
        (, bytes memory storedInitial) = validator.owners(ACCOUNT, OWNER_ID);
        assertEq(storedInitial, initialData);

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(signer), replacementData));
        (, bytes memory storedReplacement) = validator.owners(ACCOUNT, OWNER_ID);
        assertEq(storedReplacement, replacementData);
        assertEq(validator.totalValidationData(ACCOUNT), replacementLength);
    }

    function testMalformedAndZeroECDSAConfigurationsFailBothValidationPaths() external {
        ECDSASigner ecdsaSigner = new ECDSASigner();
        _install(_single(_config(OWNER_ID, address(ecdsaSigner), new bytes(20))));

        _assertBothValidationPathsFail(abi.encodePacked(OWNER_ID, new bytes(65)));

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(ecdsaSigner), bytes("")));
        _assertBothValidationPathsFail(abi.encodePacked(OWNER_ID, new bytes(65)));

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(ecdsaSigner), new bytes(19)));
        _assertBothValidationPathsFail(abi.encodePacked(OWNER_ID, new bytes(65)));

        vm.prank(ACCOUNT);
        validator.updateOwner(_config(OWNER_ID, address(ecdsaSigner), new bytes(21)));
        _assertBothValidationPathsFail(abi.encodePacked(OWNER_ID, new bytes(65)));
    }

    function _assertBothValidationPathsFail(bytes memory signature) internal {
        bytes32 hash = keccak256("failed recovery");

        vm.prank(ACCOUNT);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, signature), ERC1271_INVALID);

        PackedUserOperation memory userOp;
        userOp.sender = ACCOUNT;
        userOp.signature = signature;
        vm.prank(ACCOUNT);
        assertEq(validator.validateUserOp(userOp, hash), SIG_VALIDATION_FAILED_UINT);
    }

    function _ownerBaseSlot(address account, bytes32 ownerId) internal pure returns (bytes32) {
        // `_owners` is storage slot zero. Solidity hashes the outer owner ID first, then the account.
        bytes32 outerSlot = keccak256(abi.encode(ownerId, uint256(0)));
        return keccak256(abi.encode(account, outerSlot));
    }

    function _contains(bytes32[] memory values, bytes32 expected) internal pure returns (bool) {
        for (uint256 i; i < values.length; ++i) {
            if (values[i] == expected) return true;
        }
        return false;
    }

    function _patternedBytes(uint256 length) internal pure returns (bytes memory data) {
        data = new bytes(length);
        for (uint256 i; i < length; ++i) {
            // Intentional repeating byte pattern for values longer than 256 bytes.
            // forge-lint: disable-next-line(unsafe-typecast)
            data[i] = bytes1(uint8(i));
        }
    }

    function _install(MultiOwnerValidator.OwnerConfig[] memory configs) internal {
        vm.prank(ACCOUNT);
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
}
