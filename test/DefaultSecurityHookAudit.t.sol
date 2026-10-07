// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RecoveryAction} from "src/actions/RecoveryAction.sol";
import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {AtomicCallHarness} from "test/utils/AtomicCallHarness.sol";
import {MockTimelockEntryPoint} from "test/utils/MockTimelockEntryPoint.sol";
import {IModule, IPolicy, ISigner} from "src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {AccountERC7579Hooked} from "openzeppelin-contracts/contracts/account/extensions/draft-AccountERC7579Hooked.sol";
import {IERC7579Execution, IERC7579ModuleConfig} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";

contract DefaultSecurityHookAuditHarness is DefaultSecurityHook {
    function activeTargetCount(address account) external view returns (uint256) {
        return allowlistedTargets[account].length;
    }
}

contract HookedAccountAuditHarness is AccountERC7579Hooked {
    function installHook(address hookModule) external {
        _installModule(MODULE_TYPE_HOOK, hookModule, "");
    }
}

contract NonModuleTokenLikeTarget {}

contract EmptyReturnFallbackTarget {
    fallback() external payable {}
}

contract MalformedBoolFallbackTarget {
    fallback() external payable {
        assembly ("memory-safe") {
            mstore(0, 2)
            return(0, 32)
        }
    }
}

contract AuditPolicyModuleTarget is IPolicy {
    function onInstall(bytes calldata) external payable {}
    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable returns (uint256) {
        return 0;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure returns (uint256) {
        return 0;
    }
}

contract AuditSignerModuleTarget is ISigner {
    function onInstall(bytes calldata) external payable {}
    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_SIGNER;
    }

    function checkUserOpSignature(bytes32, PackedUserOperation calldata, bytes32) external payable returns (uint256) {
        return 0;
    }

    function checkSignature(bytes32, address, bytes32, bytes calldata) external pure returns (bytes4) {
        return bytes4(0x1626ba7e);
    }
}

contract DefaultSecurityHookAuditTest is Test {
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0xBEEF);
    bytes32 internal constant RESTRICTED_PERMISSION_ID = bytes32(bytes4(0x11111111));
    bytes32 internal constant VICTIM_PERMISSION_ID = bytes32(bytes4(0x22222222));
    uint48 internal constant TIMELOCK_DELAY = 1 days;
    uint48 internal constant TIMELOCK_EXPIRATION = 2 days;

    DefaultSecurityHookAuditHarness internal hook;

    function setUp() external {
        hook = new DefaultSecurityHookAuditHarness();
        AtomicCallHarness harness = new AtomicCallHarness();
        vm.etch(ACCOUNT, address(harness).code);
        vm.prank(ACCOUNT);
        hook.onInstall("");
    }

    function testPreCheckAllowsCanonicalSelfHookUninstallCallback() external {
        bytes memory callback = abi.encodeWithSelector(
            IERC7579ModuleConfig.uninstallModule.selector, MODULE_TYPE_HOOK, address(hook), bytes("")
        );

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testOpenZeppelinHostCanUninstallDefaultSecurityHook() external {
        DefaultSecurityHook installedHook = new DefaultSecurityHook();
        HookedAccountAuditHarness account = new HookedAccountAuditHarness();
        account.installHook(address(installedHook));

        assertEq(account.hook(), address(installedHook));
        assertTrue(installedHook.isInitialized(address(account)));

        vm.prank(address(account.entryPoint()));
        account.uninstallModule(MODULE_TYPE_HOOK, address(installedHook), "");

        assertEq(account.hook(), address(0));
        assertFalse(installedHook.isInitialized(address(account)));
    }

    function testPreCheckRejectsOtherModuleConfigurationCallbacks() external {
        bytes memory installCallback =
            abi.encodeWithSelector(IERC7579ModuleConfig.installModule.selector, uint256(1), TARGET, bytes(""));
        vm.prank(ACCOUNT);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.ModuleConfigurationNotAllowed.selector,
                IERC7579ModuleConfig.installModule.selector,
                uint256(1),
                TARGET
            )
        );
        hook.preCheck(ACCOUNT, 0, installCallback);

        bytes memory uninstallCallback =
            abi.encodeWithSelector(IERC7579ModuleConfig.uninstallModule.selector, uint256(1), TARGET, bytes(""));
        vm.prank(ACCOUNT);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.ModuleConfigurationNotAllowed.selector,
                IERC7579ModuleConfig.uninstallModule.selector,
                uint256(1),
                TARGET
            )
        );
        hook.preCheck(ACCOUNT, 0, uninstallCallback);
    }

    function testPreCheckRejectsUnknownAndShortCallbacks() external {
        bytes4 unknown = bytes4(keccak256("unknownCallback()"));
        vm.prank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(DefaultSecurityHook.UnsupportedCallback.selector, unknown));
        hook.preCheck(ACCOUNT, 0, abi.encodePacked(unknown));

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.InvalidCallbackData.selector);
        hook.preCheck(ACCOUNT, 0, hex"010203");
    }

    function testFuzzPreCheckRejectsEveryShortCallback(bytes3 prefix, uint8 rawLength) external {
        uint256 length = bound(rawLength, 0, 3);
        bytes memory callback = new bytes(length);
        for (uint256 i; i < length; ++i) {
            callback[i] = prefix[i];
        }

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.InvalidCallbackData.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testPreCheckRejectsNonCanonicalExecuteCalldata() external {
        bytes memory callback = _executionCallback(IERC7579Execution.execute.selector, TARGET, hex"12345678");

        // Replace the canonical bytes offset (0x40) with 0x60.
        assembly ("memory-safe") {
            mstore(add(callback, 0x44), 0x60)
        }

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.InvalidCallbackData.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testPreCheckRejectsTrailingExecuteCalldata() external {
        bytes memory callback =
            bytes.concat(_executionCallback(IERC7579Execution.execute.selector, TARGET, hex"12345678"), hex"00");

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.InvalidCallbackData.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testFuzzPreCheckRejectsNonCanonicalSelfUninstallOffset(uint256 badOffset) external {
        vm.assume(badOffset != 96);
        bytes memory callback = abi.encodeWithSelector(
            IERC7579ModuleConfig.uninstallModule.selector, MODULE_TYPE_HOOK, address(hook), bytes("deinit")
        );

        // The dynamic bytes offset is the third ABI head word.
        assembly ("memory-safe") {
            mstore(add(callback, 0x64), badOffset)
        }

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.InvalidCallbackData.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testFuzzPreCheckAllowsCanonicalSelfUninstallWithArbitraryData(bytes calldata deInitData) external {
        bytes memory callback = abi.encodeWithSelector(
            IERC7579ModuleConfig.uninstallModule.selector, MODULE_TYPE_HOOK, address(hook), deInitData
        );

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testPreCheckSupportsExecuteFromExecutor() external {
        bytes memory callback =
            _executionCallback(IERC7579Execution.executeFromExecutor.selector, address(this), hex"12345678");

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testEOAIsNotMisclassifiedAsModule() external {
        bytes memory callback =
            _executionCallback(IERC7579Execution.execute.selector, TARGET, abi.encodeWithSignature("safeCall()"));

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testEmptyReturnFallbackIsNotMisclassifiedAsModule() external {
        EmptyReturnFallbackTarget target = new EmptyReturnFallbackTarget();
        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector, address(target), abi.encodeWithSignature("safeCall()")
        );

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testMalformedBoolReturnIsNotAcceptedAsModuleInterface() external {
        MalformedBoolFallbackTarget target = new MalformedBoolFallbackTarget();
        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector, address(target), abi.encodeWithSignature("safeCall()")
        );

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testZeroTargetAliasIsNormalizedBeforeAllowlistLookup() external {
        bytes4[] memory allSelectors = new bytes4[](0);
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(0), allSelectors);

        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector, address(0), abi.encodeWithSignature("upgradeToAndCall(address,bytes)")
        );

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.SelfCallNotAllowed.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testFuzzZeroTargetAliasAlwaysHitsSelfCallCheck(bytes4 selector, bytes32 argument, uint96 value) external {
        bytes4[] memory allSelectors = new bytes4[](0);
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(0), allSelectors);

        bytes memory callback = _executionCallbackWithMode(
            IERC7579Execution.execute.selector,
            LibERC7579.CALLTYPE_SINGLE,
            address(0),
            value,
            abi.encodePacked(selector, argument)
        );

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.SelfCallNotAllowed.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testAllowlistCannotEnableMismatchedPermissionUninstallSelfCall() external {
        AuditSignerModuleTarget signerModule = new AuditSignerModuleTarget();
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IERC7579ModuleConfig.uninstallModule.selector;
        vm.prank(ACCOUNT);
        hook.setAllowlist(ACCOUNT, selectors);

        // Kernel decodes this as InstallModuleDataFormat(bytes installData, bytes internalData).
        // The callback payload selects the victim while Kernel's internal payload selects the
        // restricted permission: the mismatch described by TOB-KERNEL-15.
        bytes memory mismatchedDeInitData =
            abi.encode(abi.encodePacked(VICTIM_PERMISSION_ID), abi.encodePacked(RESTRICTED_PERMISSION_ID));
        bytes memory attack = abi.encodeCall(
            IERC7579ModuleConfig.uninstallModule, (MODULE_TYPE_SIGNER, address(signerModule), mismatchedDeInitData)
        );
        bytes memory callback = _executionCallback(IERC7579Execution.execute.selector, ACCOUNT, attack);

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.SelfCallNotAllowed.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testAllowlistCannotEnableCrossPermissionPolicyConsumption() external {
        AuditPolicyModuleTarget policyModule = new AuditPolicyModuleTarget();
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IPolicy.checkUserOpPolicy.selector;
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(policyModule), selectors);

        PackedUserOperation memory fakeVictimOp;
        fakeVictimOp.sender = ACCOUNT;
        bytes memory attack = abi.encodeCall(IPolicy.checkUserOpPolicy, (VICTIM_PERMISSION_ID, fakeVictimOp));
        bytes memory callback = _executionCallback(IERC7579Execution.execute.selector, address(policyModule), attack);

        vm.prank(ACCOUNT);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policyModule))
        );
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testAllowlistCannotEnableCrossPermissionSignerLifecycleCall() external {
        AuditSignerModuleTarget signerModule = new AuditSignerModuleTarget();
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = IModule.onUninstall.selector;
        selectors[1] = IModule.onInstall.selector;
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(signerModule), selectors);

        bytes[] memory attacks = new bytes[](2);
        attacks[0] = abi.encodeCall(IModule.onUninstall, (abi.encodePacked(VICTIM_PERMISSION_ID)));
        attacks[1] =
            abi.encodeCall(IModule.onInstall, (abi.encodePacked(VICTIM_PERMISSION_ID, address(0xBAD), bytes12(0))));

        for (uint256 i; i < attacks.length; ++i) {
            bytes memory callback =
                _executionCallback(IERC7579Execution.execute.selector, address(signerModule), attacks[i]);
            vm.prank(ACCOUNT);
            vm.expectRevert(
                abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(signerModule))
            );
            hook.preCheck(ACCOUNT, 0, callback);
        }
    }

    function testExactAllowlistAllowsCommittedTimelockProposalCreation() external {
        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        _allowTimelockProposalCreation(policy);

        bytes memory proposed = hex"abcdef01";
        uint256 proposalNonce = 7;
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, proposalNonce);
        bytes memory createCall =
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, proposalNonce));
        bytes memory callback = _executionCallback(IERC7579Execution.execute.selector, address(policy), createCall);

        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](3);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, callback))
        });
        afterValidation[1] = AtomicCallHarness.Call({target: address(policy), data: createCall});
        afterValidation[2] = afterValidation[0];
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);

        assertTrue(successes[2]);
        assertEq(abi.decode(results[2], (bytes)), bytes(""));
        assertTrue(successes[3]);
        assertFalse(successes[4]);
        assertEq(results[4], abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy)));
        (TimelockPolicy.ProposalStatus status,,) =
            policy.getProposal(ACCOUNT, proposed, proposalNonce, RESTRICTED_PERMISSION_ID, ACCOUNT);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));

        // Consumption clears the transient authorization, even while the EntryPoint still exposes
        // the same current UserOp hash.
        assertEq(
            entryPoint.getCurrentUserOpHash(),
            policy.getEntryPointUserOpHash(RESTRICTED_PERMISSION_ID, ACCOUNT, creation)
        );
    }

    function testTimelockWildcardAllowlistDoesNotAuthorizeModuleCall() external {
        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        bytes4[] memory allSelectors = new bytes4[](0);
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(policy), allSelectors);

        bytes memory proposed = hex"abcdef01";
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, 7);
        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, 7))
        );

        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](1);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, callback))
        });
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);
        assertFalse(successes[2]);
        assertEq(results[2], abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy)));
    }

    function testTimelockExactAllowlistRequiresLiveCommitment() external {
        (TimelockPolicy policy,) = _installTimelock();
        _allowTimelockProposalCreation(policy);

        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, hex"abcdef01", 7))
        );

        vm.prank(ACCOUNT);
        vm.expectRevert(abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy)));
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testTimelockCommitmentCannotAuthorizeAnotherPermissionOrValue() external {
        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        _allowTimelockProposalCreation(policy);

        bytes memory proposed = hex"abcdef01";
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, 7);

        bytes memory wrongIdCallback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (VICTIM_PERMISSION_ID, proposed, 7))
        );
        bytes memory valueCallback = _executionCallbackWithMode(
            IERC7579Execution.execute.selector,
            LibERC7579.CALLTYPE_SINGLE,
            address(policy),
            1,
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, 7))
        );

        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](2);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, wrongIdCallback))
        });
        afterValidation[1] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, valueCallback))
        });
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);
        bytes memory expected =
            abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy));
        assertFalse(successes[2]);
        assertEq(results[2], expected);
        assertFalse(successes[3]);
        assertEq(results[3], expected);
    }

    function testTimelockCommitmentRequiresExactNonceAndCurrentUserOpHash() external {
        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        _allowTimelockProposalCreation(policy);

        bytes memory proposed = hex"abcdef01";
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, 7);
        bytes memory wrongNonceCallback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, 8))
        );
        bytes memory exactCallback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, 7))
        );
        bytes32 exactHash = policy.getEntryPointUserOpHash(RESTRICTED_PERMISSION_ID, ACCOUNT, creation);

        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](5);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, wrongNonceCallback))
        });
        afterValidation[1] = AtomicCallHarness.Call({
            target: address(entryPoint),
            data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (keccak256("different current UserOp")))
        });
        afterValidation[2] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, exactCallback))
        });
        afterValidation[3] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (exactHash))
        });
        afterValidation[4] = afterValidation[2];
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);

        bytes memory expected =
            abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy));
        assertFalse(successes[2]);
        assertEq(results[2], expected);
        assertTrue(successes[3]);
        assertFalse(successes[4]);
        assertEq(results[4], expected);
        assertTrue(successes[5]);
        assertTrue(successes[6]);
        assertEq(abi.decode(results[6], (bytes)), bytes(""));
    }

    function testTimelockAuthorizationGasCapSupportsLargeProposalCalldata() external {
        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        _allowTimelockProposalCreation(policy);

        bytes memory proposed = new bytes(64 * 1024);
        proposed[0] = 0x01;
        proposed[proposed.length - 1] = 0xff;
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, 7);
        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, proposed, 7))
        );

        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](1);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, callback))
        });
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);
        assertTrue(successes[2]);
        assertEq(abi.decode(results[2], (bytes)), bytes(""));
    }

    function testFuzzTimelockCommitmentDoesNotAuthorizeTamperedProposal(
        bytes calldata proposed,
        uint256 proposalNonce,
        bytes32 suffix,
        uint256 tamperedNonce
    ) external {
        vm.assume(proposed.length <= 512);
        bytes memory tampered = abi.encodePacked(proposed, suffix);
        vm.assume(keccak256(tampered) != keccak256(proposed) || tamperedNonce != proposalNonce);

        (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) = _installTimelock();
        _allowTimelockProposalCreation(policy);
        PackedUserOperation memory creation = _timelockCreation(policy, proposed, proposalNonce);

        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(policy),
            abi.encodeCall(policy.createProposal, (RESTRICTED_PERMISSION_ID, tampered, tamperedNonce))
        );
        AtomicCallHarness.Call[] memory afterValidation = new AtomicCallHarness.Call[](1);
        afterValidation[0] = AtomicCallHarness.Call({
            target: address(hook), data: abi.encodeCall(hook.preCheck, (ACCOUNT, 0, callback))
        });
        (bool[] memory successes, bytes[] memory results) =
            _withTimelockCommitment(policy, entryPoint, creation, afterValidation);
        assertFalse(successes[2]);
        assertEq(results[2], abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(policy)));
    }

    function testFiniteDenylistDocumentsERC1363TransferAndCallAsUnblocked() external {
        NonModuleTokenLikeTarget target = new NonModuleTokenLikeTarget();
        bytes memory callback = _executionCallback(
            IERC7579Execution.execute.selector,
            address(target),
            abi.encodePacked(bytes4(0x4000aea0), address(0xCAFE), uint256(1))
        );

        vm.prank(ACCOUNT);
        assertEq(hook.preCheck(ACCOUNT, 0, callback), bytes(""));
    }

    function testAllowlistingRecoveryActionCannotBypassDelegatecallProhibition() external {
        RecoveryAction action = new RecoveryAction();
        bytes4[] memory allSelectors = new bytes4[](0);
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(action), allSelectors);

        bytes memory callback = _executionCallbackWithMode(
            IERC7579Execution.execute.selector,
            LibERC7579.CALLTYPE_DELEGATECALL,
            address(action),
            0,
            abi.encodeCall(action.doRecovery, (TARGET, bytes("configuration")))
        );

        vm.prank(ACCOUNT);
        vm.expectRevert(DefaultSecurityHook.DelegateCallNotAllowed.selector);
        hook.preCheck(ACCOUNT, 0, callback);
    }

    function testAllowlistTargetSetRemainsUniqueAcrossRemoveAndReadd() external {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("safeFunction()"));

        for (uint256 i; i < 20; ++i) {
            vm.prank(ACCOUNT);
            hook.setAllowlist(TARGET, selectors);
            assertEq(hook.activeTargetCount(ACCOUNT), 1);

            vm.prank(ACCOUNT);
            hook.removeAllowlist(TARGET);
            assertEq(hook.activeTargetCount(ACCOUNT), 0);
        }

        vm.prank(ACCOUNT);
        hook.setAllowlist(TARGET, selectors);
        assertEq(hook.activeTargetCount(ACCOUNT), 1);

        vm.prank(ACCOUNT);
        hook.onUninstall("");
        assertEq(hook.activeTargetCount(ACCOUNT), 0);
        assertFalse(hook.isAllowlisted(ACCOUNT, TARGET));
    }

    function testFuzzAllowlistTargetSetNeverContainsDuplicates(uint8 rawOperations, bytes4 selector) external {
        uint256 operations = bound(rawOperations, 1, 8);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = selector;

        for (uint256 i; i < operations; ++i) {
            vm.prank(ACCOUNT);
            hook.setAllowlist(TARGET, selectors);
            vm.prank(ACCOUNT);
            hook.setAllowlist(TARGET, selectors);
            assertEq(hook.activeTargetCount(ACCOUNT), 1);

            if (i & 1 == 0) {
                vm.prank(ACCOUNT);
                hook.removeAllowlist(TARGET);
                assertEq(hook.activeTargetCount(ACCOUNT), 0);
            }
        }

        vm.prank(ACCOUNT);
        hook.onUninstall("");
        assertEq(hook.activeTargetCount(ACCOUNT), 0);
        assertFalse(hook.isAllowlisted(ACCOUNT, TARGET));
    }

    function _installTimelock() internal returns (TimelockPolicy policy, MockTimelockEntryPoint entryPoint) {
        policy = new TimelockPolicy();
        entryPoint = new MockTimelockEntryPoint();
        vm.prank(ACCOUNT);
        policy.onInstall(
            abi.encode(RESTRICTED_PERMISSION_ID, TIMELOCK_DELAY, TIMELOCK_EXPIRATION, address(0), address(entryPoint))
        );
    }

    function _allowTimelockProposalCreation(TimelockPolicy policy) internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = policy.createProposal.selector;
        vm.prank(ACCOUNT);
        hook.setAllowlist(address(policy), selectors);
    }

    function _timelockCreation(TimelockPolicy policy, bytes memory proposed, uint256 proposalNonce)
        internal
        view
        returns (PackedUserOperation memory creation)
    {
        creation = PackedUserOperation({
            sender: ACCOUNT,
            nonce: 0,
            initCode: "",
            callData: policy.getProposalCreationCallData(RESTRICTED_PERMISSION_ID, proposed, proposalNonce),
            accountGasLimits: bytes32(abi.encodePacked(uint128(300_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: abi.encodePacked(address(0xCAFE), uint128(300_000), uint128(100_000)),
            signature: "signed-by-permission"
        });
    }

    function _withTimelockCommitment(
        TimelockPolicy policy,
        MockTimelockEntryPoint entryPoint,
        PackedUserOperation memory creation,
        AtomicCallHarness.Call[] memory afterValidation
    ) internal returns (bool[] memory successes, bytes[] memory results) {
        uint256 afterLength = afterValidation.length;
        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](afterLength + 2);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy),
            data: abi.encodeCall(policy.checkUserOpPolicy, (RESTRICTED_PERMISSION_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint),
            data: abi.encodeCall(
                entryPoint.setCurrentUserOpHash,
                (policy.getEntryPointUserOpHash(RESTRICTED_PERMISSION_ID, ACCOUNT, creation))
            )
        });
        for (uint256 i; i < afterLength; ++i) {
            calls[i + 2] = afterValidation[i];
        }

        (successes, results) = AtomicCallHarness(ACCOUNT).execute(calls);
        assertTrue(successes[0], "Timelock validation reverted");
        assertEq(
            abi.decode(results[0], (uint256)),
            SIG_VALIDATION_SUCCESS_UINT,
            "Timelock validation must create the transient commitment"
        );
        assertTrue(successes[1], "EntryPoint hash update reverted");
    }

    function _executionCallback(bytes4 callbackSelector, address target, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return _executionCallbackWithMode(callbackSelector, LibERC7579.CALLTYPE_SINGLE, target, 0, data);
    }

    function _executionCallbackWithMode(
        bytes4 callbackSelector,
        bytes1 callType,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory) {
        bytes32 mode = LibERC7579.encodeMode(callType, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        return abi.encodeWithSelector(callbackSelector, mode, abi.encodePacked(target, value, data));
    }
}
