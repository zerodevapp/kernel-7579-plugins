// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "src/types/Constants.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {IERC7579Execution, Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";

/// @dev Mock module that responds to isModuleType without reverting.
contract MockModule is IModule {
    function onInstall(bytes calldata) external payable override {}
    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256) external pure override returns (bool) {
        return true;
    }
}

/// @dev A contract that does NOT implement isModuleType (staticcall will revert).
contract NonModuleContract {
    function doSomething() external pure returns (uint256) {
        return 42;
    }
}

contract DefaultSecurityHookBTTTest is Test {
    DefaultSecurityHook public hook;
    MockModule public mockModule;
    NonModuleContract public nonModule;

    address public account;
    address public randomTarget;

    // Blocked selectors
    bytes4 internal constant TRANSFER = 0xa9059cbb;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant TRANSFER_FROM = 0x23b872dd;
    bytes4 internal constant INCREASE_ALLOWANCE = 0x39509351;
    bytes4 internal constant DECREASE_ALLOWANCE = 0xa457c2d7;
    bytes4 internal constant SAFE_TRANSFER_FROM = 0x42842e0e;
    bytes4 internal constant SAFE_TRANSFER_FROM_WITH_DATA = 0xb88d4fde;
    bytes4 internal constant SET_APPROVAL_FOR_ALL = 0xa22cb465;
    bytes4 internal constant SAFE_TRANSFER_FROM_1155 = 0xf242432a;
    bytes4 internal constant SAFE_BATCH_TRANSFER_FROM = 0x2eb2c2d6;

    // An unblocked selector
    bytes4 internal constant BALANCE_OF = 0x70a08231;

    event AllowlistSet(address indexed account, address indexed target, bytes4[] selectors);
    event AllowlistRemoved(address indexed account, address indexed target);
    event Initialized(address indexed account);
    event Uninitialized(address indexed account);

    function setUp() public {
        hook = new DefaultSecurityHook();
        mockModule = new MockModule();
        nonModule = new NonModuleContract();
        account = address(0xACC0);
        randomTarget = address(nonModule);
    }

    // ==================== Helper Functions ====================

    function _install() internal {
        vm.prank(account);
        hook.onInstall("");
    }

    function _installWithConfig(DefaultSecurityHook.AllowlistConfig[] memory configs) internal {
        vm.prank(account);
        hook.onInstall(abi.encode(configs));
    }

    /// @dev Build msgData for a single-mode preCheck call.
    function _singleMsgData(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory executionData = abi.encodePacked(target, value, data);
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionData);
    }

    /// @dev Build msgData for a batch-mode preCheck call.
    function _batchMsgData(Execution[] memory executions) internal pure returns (bytes memory) {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory executionData = abi.encode(executions);
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionData);
    }

    /// @dev Build msgData for a delegatecall-mode preCheck call.
    function _delegatecallMsgData() internal pure returns (bytes memory) {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory executionData = abi.encodePacked(address(0), uint256(0));
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionData);
    }

    /// @dev Helper to call preCheck from account context.
    function _preCheck(bytes memory msgData) internal returns (bytes memory) {
        vm.prank(account);
        return hook.preCheck(address(0), 0, msgData);
    }

    // ==================== onInstall Tests ====================

    modifier whenCallingOnInstall() {
        _;
    }

    function test_GivenAccountIsAlreadyInitialized() external whenCallingOnInstall {
        // it should revert with AlreadyInitialized
        _install();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, account));
        hook.onInstall("");
    }

    function test_GivenDataIsEmpty() external whenCallingOnInstall {
        // it should mark account as initialized
        // it should emit Initialized event
        vm.prank(account);
        vm.expectEmit(true, false, false, false);
        emit Initialized(account);
        hook.onInstall("");

        assertTrue(hook.isInitialized(account), "Account should be initialized");
    }

    function test_GivenDataContainsAllowlistConfigs() external whenCallingOnInstall {
        // it should mark account as initialized
        // it should set allowlist entries for each config
        // it should emit Initialized event
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](2);

        bytes4[] memory selectors1 = new bytes4[](1);
        selectors1[0] = TRANSFER;
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: selectors1});

        bytes4[] memory selectors2 = new bytes4[](0);
        configs[1] = DefaultSecurityHook.AllowlistConfig({target: address(0xBEEF), selectors: selectors2});

        vm.prank(account);
        vm.expectEmit(true, false, false, false);
        emit Initialized(account);
        hook.onInstall(abi.encode(configs));

        assertTrue(hook.isInitialized(account), "Account should be initialized");
        assertTrue(hook.isAllowlisted(account, randomTarget), "randomTarget should be allowlisted");
        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER selector should be allowed");
        assertFalse(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE selector should not be allowed");
        assertTrue(hook.isAllowlisted(account, address(0xBEEF)), "0xBEEF should be allowlisted");
        assertTrue(
            hook.isSelectorAllowed(account, address(0xBEEF), TRANSFER), "All selectors should be allowed for 0xBEEF"
        );
    }

    // ==================== onUninstall Tests ====================

    modifier whenCallingOnUninstall() {
        _;
    }

    function test_GivenAccountIsNotInitialized() external whenCallingOnUninstall {
        // it should revert with NotInitialized
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, account));
        hook.onUninstall("");
    }

    function test_GivenDataIsEmpty_WhenCallingOnUninstall() external whenCallingOnUninstall {
        // it should mark account as not initialized
        // it should emit Uninitialized event
        _install();

        vm.prank(account);
        vm.expectEmit(true, false, false, false);
        emit Uninitialized(account);
        hook.onUninstall("");

        assertFalse(hook.isInitialized(account), "Account should not be initialized");
    }

    function test_GivenDataContainsTargetsToClean() external whenCallingOnUninstall {
        // it should clear all allowlist entries automatically
        // it should mark account as not initialized
        // it should emit Uninitialized event
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels = new bytes4[](0);
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels});
        _installWithConfig(configs);

        assertTrue(hook.isAllowlisted(account, randomTarget), "Should be allowlisted before uninstall");

        vm.prank(account);
        vm.expectEmit(true, false, false, false);
        emit Uninitialized(account);
        hook.onUninstall("");

        assertFalse(hook.isInitialized(account), "Account should not be initialized");
        assertFalse(hook.isAllowlisted(account, randomTarget), "Allowlist should be cleared");
    }

    // ==================== isModuleType Tests ====================

    modifier whenCallingIsModuleType() {
        _;
    }

    function test_GivenModuleTypeIdIsMODULE_TYPE_HOOK() external whenCallingIsModuleType {
        // it should return true
        assertTrue(hook.isModuleType(MODULE_TYPE_HOOK), "Should return true for MODULE_TYPE_HOOK");
    }

    function test_GivenModuleTypeIdIsNotMODULE_TYPE_HOOK() external whenCallingIsModuleType {
        // it should return false
        assertFalse(hook.isModuleType(1), "Should return false for MODULE_TYPE_VALIDATOR");
        assertFalse(hook.isModuleType(0), "Should return false for 0");
        assertFalse(hook.isModuleType(999), "Should return false for 999");
    }

    // ==================== preCheck DELEGATECALL Tests ====================

    function test_WhenCallingPreCheckWithDELEGATECALLMode() external {
        // it should revert with DelegateCallNotAllowed
        bytes memory msgData = _delegatecallMsgData();

        vm.prank(account);
        vm.expectRevert(DefaultSecurityHook.DelegateCallNotAllowed.selector);
        hook.preCheck(address(0), 0, msgData);
    }

    // ==================== preCheck SINGLE Tests ====================

    modifier whenCallingPreCheckWithSINGLEMode() {
        _;
    }

    function test_GivenTargetIsAllowlistedWithAllSelectors() external whenCallingPreCheckWithSINGLEMode {
        // it should return empty bytes
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels = new bytes4[](0);
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels});
        _installWithConfig(configs);

        // Even a blocked selector should pass when all selectors are allowed
        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(TRANSFER, address(1), 100));
        bytes memory result = _preCheck(msgData);
        assertEq(result, hex"", "Should return empty bytes");
    }

    function test_GivenTargetIsAllowlistedWithSpecificSelectorMatchingCall()
        external
        whenCallingPreCheckWithSINGLEMode
    {
        // it should return empty bytes
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = TRANSFER;
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels});
        _installWithConfig(configs);

        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(TRANSFER, address(1), 100));
        bytes memory result = _preCheck(msgData);
        assertEq(result, hex"", "Should return empty bytes");
    }

    function test_GivenTargetIsAllowlistedWithSpecificSelectorNotMatchingCall()
        external
        whenCallingPreCheckWithSINGLEMode
    {
        // it should revert with TokenTransferNotAllowed
        // Allowlist TRANSFER for the target, but call APPROVE (also blocked)
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = TRANSFER;
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels});
        _installWithConfig(configs);

        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(APPROVE, address(1), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, APPROVE)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenTargetIsSelf() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with SelfCallNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(account, 0, abi.encodeWithSelector(BALANCE_OF, address(1)));
        vm.prank(account);
        vm.expectRevert(DefaultSecurityHook.SelfCallNotAllowed.selector);
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenTargetIsAModule() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with ModuleCallNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(address(mockModule), 0, abi.encodeWithSelector(BALANCE_OF, address(1)));
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, address(mockModule)));
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenValueIsGreaterThanZero() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with ETHTransferNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(randomTarget, 1 ether, hex"");
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, randomTarget, 1 ether)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC20Transfer() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(TRANSFER, address(1), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, TRANSFER)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC20Approve() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(APPROVE, address(1), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, APPROVE)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC20TransferFrom() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData =
            _singleMsgData(randomTarget, 0, abi.encodeWithSelector(TRANSFER_FROM, address(1), address(2), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, TRANSFER_FROM)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC20IncreaseAllowance() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData =
            _singleMsgData(randomTarget, 0, abi.encodeWithSelector(INCREASE_ALLOWANCE, address(1), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, INCREASE_ALLOWANCE
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC20DecreaseAllowance() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData =
            _singleMsgData(randomTarget, 0, abi.encodeWithSelector(DECREASE_ALLOWANCE, address(1), 100));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, DECREASE_ALLOWANCE
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC721SafeTransferFrom() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData =
            _singleMsgData(randomTarget, 0, abi.encodeWithSelector(SAFE_TRANSFER_FROM, address(1), address(2), 1));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, SAFE_TRANSFER_FROM
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC721SafeTransferFromWithData() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(
            randomTarget, 0, abi.encodeWithSelector(SAFE_TRANSFER_FROM_WITH_DATA, address(1), address(2), 1, hex"")
        );
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, SAFE_TRANSFER_FROM_WITH_DATA
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC721SetApprovalForAll() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData =
            _singleMsgData(randomTarget, 0, abi.encodeWithSelector(SET_APPROVAL_FOR_ALL, address(1), true));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, SET_APPROVAL_FOR_ALL
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC1155SafeTransferFrom() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        bytes memory msgData = _singleMsgData(
            randomTarget, 0, abi.encodeWithSelector(SAFE_TRANSFER_FROM_1155, address(1), address(2), 1, 1, hex"")
        );
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, SAFE_TRANSFER_FROM_1155
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenSelectorIsERC1155SafeBatchTransferFrom() external whenCallingPreCheckWithSINGLEMode {
        // it should revert with TokenTransferNotAllowed
        _install();
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;
        bytes memory msgData = _singleMsgData(
            randomTarget,
            0,
            abi.encodeWithSelector(SAFE_BATCH_TRANSFER_FROM, address(1), address(2), ids, amounts, hex"")
        );
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, SAFE_BATCH_TRANSFER_FROM
            )
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenCallHasNoBlockedSelectorAndNoValueAndTargetIsClean() external whenCallingPreCheckWithSINGLEMode {
        // it should return empty bytes
        _install();
        bytes memory msgData = _singleMsgData(randomTarget, 0, abi.encodeWithSelector(BALANCE_OF, address(1)));
        bytes memory result = _preCheck(msgData);
        assertEq(result, hex"", "Should return empty bytes for clean call");
    }

    function test_GivenCalldataIsLessThan4Bytes() external whenCallingPreCheckWithSINGLEMode {
        // it should return empty bytes (no selector to match, and no value, clean target)
        _install();
        // 3 bytes of calldata — less than 4
        bytes memory msgData = _singleMsgData(randomTarget, 0, hex"aabbcc");
        bytes memory result = _preCheck(msgData);
        assertEq(result, hex"", "Should return empty bytes for short calldata");
    }

    // ==================== preCheck BATCH Tests ====================

    modifier whenCallingPreCheckWithBATCHMode() {
        _;
    }

    function test_GivenAllCallsInBatchAreClean() external whenCallingPreCheckWithBATCHMode {
        // it should return empty bytes
        _install();

        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({target: randomTarget, value: 0, callData: abi.encodeWithSelector(BALANCE_OF, address(1))});
        execs[1] = Execution({target: randomTarget, value: 0, callData: abi.encodeWithSelector(BALANCE_OF, address(2))});

        bytes memory msgData = _batchMsgData(execs);
        bytes memory result = _preCheck(msgData);
        assertEq(result, hex"", "Should return empty bytes for clean batch");
    }

    function test_GivenOneCallInBatchHasBlockedSelector() external whenCallingPreCheckWithBATCHMode {
        // it should revert with TokenTransferNotAllowed
        _install();

        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({target: randomTarget, value: 0, callData: abi.encodeWithSelector(BALANCE_OF, address(1))});
        execs[1] =
            Execution({target: randomTarget, value: 0, callData: abi.encodeWithSelector(TRANSFER, address(1), 100)});

        bytes memory msgData = _batchMsgData(execs);
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, randomTarget, TRANSFER)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    function test_GivenBatchHasAllowlistedAndBlockedCalls() external whenCallingPreCheckWithBATCHMode {
        // it should revert for the blocked call
        // Allowlist randomTarget but not another target
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels = new bytes4[](0);
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels});
        _installWithConfig(configs);

        // Use a real non-module contract so isModuleType staticcall reverts
        NonModuleContract blockedNonModule = new NonModuleContract();
        address blockedTarget = address(blockedNonModule);

        Execution[] memory execs = new Execution[](2);
        // This call is allowlisted
        execs[0] =
            Execution({target: randomTarget, value: 0, callData: abi.encodeWithSelector(TRANSFER, address(1), 100)});
        // This call is NOT allowlisted and has a blocked selector
        execs[1] =
            Execution({target: blockedTarget, value: 0, callData: abi.encodeWithSelector(APPROVE, address(1), 100)});

        bytes memory msgData = _batchMsgData(execs);
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, blockedTarget, APPROVE)
        );
        hook.preCheck(address(0), 0, msgData);
    }

    // ==================== postCheck Tests ====================

    function test_WhenCallingPostCheck() external {
        // it should not revert
        hook.postCheck(hex"");
        hook.postCheck(hex"1234");
        assertTrue(true, "postCheck should not revert");
    }

    // ==================== setAllowlist Tests ====================

    modifier whenCallingSetAllowlist() {
        _;
    }

    function test_GivenCallerIsNotInitialized() external whenCallingSetAllowlist {
        // it should revert with Unauthorized
        bytes4[] memory sels = new bytes4[](0);
        vm.prank(account);
        vm.expectRevert(DefaultSecurityHook.Unauthorized.selector);
        hook.setAllowlist(randomTarget, sels);
    }

    function test_GivenSettingWithEmptySelectors() external whenCallingSetAllowlist {
        // it should set allSelectorsAllowed to true
        // it should emit AllowlistSet event
        _install();

        bytes4[] memory sels = new bytes4[](0);
        vm.prank(account);
        vm.expectEmit(true, true, false, true);
        emit AllowlistSet(account, randomTarget, sels);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(hook.isAllowlisted(account, randomTarget), "Target should be allowlisted");
        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "All selectors should be allowed");
    }

    function test_GivenSettingWithSpecificSelectors() external whenCallingSetAllowlist {
        // it should set each selector as allowed
        // it should set allSelectorsAllowed to false
        // it should emit AllowlistSet event
        _install();

        bytes4[] memory sels = new bytes4[](2);
        sels[0] = TRANSFER;
        sels[1] = APPROVE;

        vm.prank(account);
        vm.expectEmit(true, true, false, true);
        emit AllowlistSet(account, randomTarget, sels);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(hook.isAllowlisted(account, randomTarget), "Target should be allowlisted");
        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should be allowed");
        assertTrue(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE should be allowed");
        assertFalse(hook.isSelectorAllowed(account, randomTarget, TRANSFER_FROM), "TRANSFER_FROM should not be allowed");
    }

    // ==================== removeAllowlist Tests ====================

    modifier whenCallingRemoveAllowlist() {
        _;
    }

    function test_GivenCallerIsNotInitialized_WhenCallingRemoveAllowlist() external whenCallingRemoveAllowlist {
        // it should revert with Unauthorized
        vm.prank(account);
        vm.expectRevert(DefaultSecurityHook.Unauthorized.selector);
        hook.removeAllowlist(randomTarget);
    }

    function test_GivenRemovingExistingTarget() external whenCallingRemoveAllowlist {
        // it should set allowed to false
        // it should emit AllowlistRemoved event
        _install();

        bytes4[] memory sels = new bytes4[](0);
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(hook.isAllowlisted(account, randomTarget), "Target should be allowlisted before removal");

        vm.prank(account);
        vm.expectEmit(true, true, false, false);
        emit AllowlistRemoved(account, randomTarget);
        hook.removeAllowlist(randomTarget);

        assertFalse(hook.isAllowlisted(account, randomTarget), "Target should not be allowlisted after removal");
    }

    // ==================== isInitialized Tests ====================

    modifier whenCallingIsInitialized() {
        _;
    }

    function test_GivenAccountIsInitialized() external whenCallingIsInitialized {
        // it should return true
        _install();
        assertTrue(hook.isInitialized(account), "Should return true for initialized account");
    }

    function test_GivenAccountIsNotInitialized_WhenCallingIsInitialized() external whenCallingIsInitialized {
        // it should return false
        assertFalse(hook.isInitialized(account), "Should return false for uninitialized account");
    }

    // ==================== isAllowlisted Tests ====================

    modifier whenCallingIsAllowlisted() {
        _;
    }

    function test_GivenTargetIsAllowlisted() external whenCallingIsAllowlisted {
        // it should return true
        _install();
        bytes4[] memory sels = new bytes4[](0);
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(hook.isAllowlisted(account, randomTarget), "Should return true for allowlisted target");
    }

    function test_GivenTargetIsNotAllowlisted() external whenCallingIsAllowlisted {
        // it should return false
        assertFalse(hook.isAllowlisted(account, randomTarget), "Should return false for non-allowlisted target");
    }

    // ==================== isSelectorAllowed Tests ====================

    modifier whenCallingIsSelectorAllowed() {
        _;
    }

    function test_GivenTargetIsNotAllowlisted_WhenCallingIsSelectorAllowed() external whenCallingIsSelectorAllowed {
        // it should return false
        assertFalse(
            hook.isSelectorAllowed(account, randomTarget, TRANSFER), "Should return false when target not allowlisted"
        );
    }

    function test_GivenTargetIsAllowlistedWithAllSelectors_WhenCallingIsSelectorAllowed()
        external
        whenCallingIsSelectorAllowed
    {
        // it should return true for any selector
        _install();
        bytes4[] memory sels = new bytes4[](0);
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(
            hook.isSelectorAllowed(account, randomTarget, TRANSFER),
            "Should return true for any selector when all allowed"
        );
        assertTrue(
            hook.isSelectorAllowed(account, randomTarget, bytes4(0xdeadbeef)),
            "Should return true for arbitrary selector when all allowed"
        );
    }

    modifier givenTargetIsAllowlistedWithSpecificSelectors() {
        _install();
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = TRANSFER;
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels);
        _;
    }

    function test_GivenQueriedSelectorIsInTheList()
        external
        whenCallingIsSelectorAllowed
        givenTargetIsAllowlistedWithSpecificSelectors
    {
        // it should return true
        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "Should return true for allowed selector");
    }

    function test_GivenQueriedSelectorIsNotInTheList()
        external
        whenCallingIsSelectorAllowed
        givenTargetIsAllowlistedWithSpecificSelectors
    {
        // it should return false
        assertFalse(
            hook.isSelectorAllowed(account, randomTarget, APPROVE), "Should return false for non-allowed selector"
        );
    }

    // ==================== S-01 Regression: Stale selectors cleared on update ====================

    function test_S01_StaleSelectorsAreClearedOnAllowlistUpdate() external {
        _install();

        // Step 1: Allowlist with TRANSFER and APPROVE
        bytes4[] memory sels1 = new bytes4[](2);
        sels1[0] = TRANSFER;
        sels1[1] = APPROVE;
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels1);

        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should be allowed");
        assertTrue(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE should be allowed");

        // Step 2: Update to only TRANSFER
        bytes4[] memory sels2 = new bytes4[](1);
        sels2[0] = TRANSFER;
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels2);

        // APPROVE must be cleared
        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should still be allowed");
        assertFalse(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE should be cleared after update");
    }

    function test_S01_StaleSelectorsAreClearedOnRemoveAllowlist() external {
        _install();

        // Allowlist with specific selectors
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = TRANSFER;
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels);

        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should be allowed");

        // Remove allowlist
        vm.prank(account);
        hook.removeAllowlist(randomTarget);

        // Re-add allowlist with different selectors
        bytes4[] memory sels2 = new bytes4[](1);
        sels2[0] = APPROVE;
        vm.prank(account);
        hook.setAllowlist(randomTarget, sels2);

        // TRANSFER must not persist from the old allowlist
        assertFalse(
            hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should not persist after remove+re-add"
        );
        assertTrue(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE should be allowed");
    }

    // ==================== S-02 Regression: Unknown call types revert ====================

    function test_S02_UnknownCallTypeReverts() external {
        _install();

        // Build msgData with CALLTYPE_STATICCALL (0xfe)
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_STATICCALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory executionData = abi.encodePacked(randomTarget, uint256(0));
        bytes memory msgData = abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionData);

        vm.prank(account);
        vm.expectRevert(DefaultSecurityHook.UnsupportedCallType.selector);
        hook.preCheck(address(0), 0, msgData);
    }

    // ==================== S-03 Regression: onUninstall clears ALL state ====================

    function test_S03_OnUninstallClearsAllTargetsWithoutCallerData() external {
        // Install with two targets
        DefaultSecurityHook.AllowlistConfig[] memory configs = new DefaultSecurityHook.AllowlistConfig[](2);
        bytes4[] memory sels1 = new bytes4[](1);
        sels1[0] = TRANSFER;
        configs[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels1});

        address target2 = address(0xBEEF);
        bytes4[] memory sels2 = new bytes4[](0);
        configs[1] = DefaultSecurityHook.AllowlistConfig({target: target2, selectors: sels2});
        _installWithConfig(configs);

        assertTrue(hook.isAllowlisted(account, randomTarget), "randomTarget should be allowlisted");
        assertTrue(hook.isAllowlisted(account, target2), "target2 should be allowlisted");

        // Uninstall with empty data -- should still clear everything
        vm.prank(account);
        hook.onUninstall("");

        assertFalse(hook.isAllowlisted(account, randomTarget), "randomTarget should be cleared after uninstall");
        assertFalse(hook.isAllowlisted(account, target2), "target2 should be cleared after uninstall");
        assertFalse(
            hook.isSelectorAllowed(account, randomTarget, TRANSFER),
            "TRANSFER selector should be cleared after uninstall"
        );
    }

    function test_S03_StaleStateDoesNotPersistAcrossReinstall() external {
        // Install with target allowlisted
        DefaultSecurityHook.AllowlistConfig[] memory configs1 = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels1 = new bytes4[](1);
        sels1[0] = TRANSFER;
        configs1[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels1});
        _installWithConfig(configs1);

        assertTrue(hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should be allowed");

        // Uninstall (empty data)
        vm.prank(account);
        hook.onUninstall("");

        // Reinstall with different config (APPROVE only)
        DefaultSecurityHook.AllowlistConfig[] memory configs2 = new DefaultSecurityHook.AllowlistConfig[](1);
        bytes4[] memory sels2 = new bytes4[](1);
        sels2[0] = APPROVE;
        configs2[0] = DefaultSecurityHook.AllowlistConfig({target: randomTarget, selectors: sels2});
        _installWithConfig(configs2);

        // TRANSFER must NOT persist from the first installation
        assertFalse(
            hook.isSelectorAllowed(account, randomTarget, TRANSFER), "TRANSFER should not persist across reinstall"
        );
        assertTrue(hook.isSelectorAllowed(account, randomTarget, APPROVE), "APPROVE should be allowed after reinstall");
    }
}
