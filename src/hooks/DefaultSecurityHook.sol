// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook, IModule} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "src/types/Constants.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {IERC7579Execution, IERC7579ModuleConfig} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "openzeppelin-contracts/contracts/token/ERC1155/IERC1155.sol";

interface ITimelockProposalAuthorizer {
    function isProposalCreationAuthorized(address account, bytes calldata createProposalCalldata)
        external
        view
        returns (bytes4 magicValue);
}

/// @title DefaultSecurityHook
/// @notice A default security hook for ERC-7579 smart accounts that blocks delegatecalls, self-calls,
///         module calls, ETH transfers, and a documented set of common token-transfer selectors.
/// @dev The token selector denylist is intentionally finite and is not a complete asset-transfer guarantee.
///      The only module-call exception is an explicitly allowlisted, zero-value Timelock proposal creation
///      backed by a live commitment for the current UserOperation. Integrators must use target/selector
///      allowlists and additional policy controls for their threat model.
/// @author taek <leekt216@gmail.com>
contract DefaultSecurityHook is IHook {
    // ========== Errors ==========

    error DelegateCallNotAllowed();
    error SelfCallNotAllowed();
    error ModuleCallNotAllowed(address target);
    error ETHTransferNotAllowed(address target, uint256 value);
    error TokenTransferNotAllowed(address target, bytes4 selector);
    error Unauthorized();
    error UnsupportedCallType();
    error UnsupportedCallback(bytes4 selector);
    error InvalidCallbackData();
    error ModuleConfigurationNotAllowed(bytes4 selector, uint256 moduleTypeId, address module);

    // ========== Events ==========

    event AllowlistSet(address indexed account, address indexed target, bytes4[] selectors);
    event AllowlistRemoved(address indexed account, address indexed target);
    event Initialized(address indexed account);
    event Uninitialized(address indexed account);

    // ========== Types ==========

    struct AllowlistConfig {
        address target;
        bytes4[] selectors;
    }

    struct AllowlistEntry {
        bool allowed;
        bool allSelectorsAllowed;
        bytes4[] selectorList;
        mapping(bytes4 => bool) selectors;
    }

    // ========== Storage ==========

    mapping(address account => mapping(address target => AllowlistEntry)) internal allowlist;
    mapping(address account => address[]) internal allowlistedTargets;
    mapping(address account => mapping(address target => uint256 indexPlusOne)) internal allowlistedTargetIndex;
    mapping(address account => bool) internal initialized;

    // ========== Blocked Selectors ==========

    // ERC-20
    bytes4 internal constant TRANSFER = IERC20.transfer.selector;
    bytes4 internal constant APPROVE = IERC20.approve.selector;
    bytes4 internal constant TRANSFER_FROM = IERC20.transferFrom.selector;
    bytes4 internal constant INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 internal constant DECREASE_ALLOWANCE = bytes4(keccak256("decreaseAllowance(address,uint256)"));

    // ERC-721 (unique selectors not already covered above)
    // safeTransferFrom is overloaded in IERC721, so we compute selectors from signatures directly
    bytes4 internal constant SAFE_TRANSFER_FROM = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
    bytes4 internal constant SAFE_TRANSFER_FROM_WITH_DATA =
        bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
    bytes4 internal constant SET_APPROVAL_FOR_ALL = IERC721.setApprovalForAll.selector;

    // ERC-1155
    bytes4 internal constant SAFE_TRANSFER_FROM_1155 = IERC1155.safeTransferFrom.selector;
    bytes4 internal constant SAFE_BATCH_TRANSFER_FROM = IERC1155.safeBatchTransferFrom.selector;

    // Gas stipend for isModuleType static call
    uint256 internal constant MODULE_CHECK_GAS = 30_000;
    uint256 internal constant TIMELOCK_AUTH_CHECK_GAS = 150_000;

    // The only module call that can be opted into. TimelockPolicy returns the authorizer
    // selector only while the current EntryPoint UserOp has a live proposal commitment.
    bytes4 internal constant CREATE_TIMELOCK_PROPOSAL = bytes4(keccak256("createProposal(bytes32,bytes,uint256)"));
    bytes4 internal constant TIMELOCK_PROPOSAL_AUTHORIZED =
        ITimelockProposalAuthorizer.isProposalCreationAuthorized.selector;

    // ========== IModule ==========

    function onInstall(bytes calldata data) external payable override {
        if (initialized[msg.sender]) revert AlreadyInitialized(msg.sender);
        initialized[msg.sender] = true;

        if (data.length > 0) {
            AllowlistConfig[] memory configs = abi.decode(data, (AllowlistConfig[]));
            for (uint256 i; i < configs.length; i++) {
                _setAllowlist(msg.sender, configs[i].target, configs[i].selectors);
            }
        }

        emit Initialized(msg.sender);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!initialized[msg.sender]) revert NotInitialized(msg.sender);

        // Pop each active target as it is cleared. The target set contains no duplicates.
        address[] storage targets = allowlistedTargets[msg.sender];
        while (targets.length != 0) {
            _clearAllowlist(msg.sender, targets[targets.length - 1]);
        }

        initialized[msg.sender] = false;
        emit Uninitialized(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    // ========== IHook ==========

    function preCheck(address, uint256, bytes calldata msgData) external payable override returns (bytes memory) {
        if (msgData.length < 4) revert InvalidCallbackData();

        bytes4 callbackSelector = bytes4(msgData[:4]);
        if (
            callbackSelector == IERC7579Execution.execute.selector
                || callbackSelector == IERC7579Execution.executeFromExecutor.selector
        ) {
            _checkExecutionCallback(msgData);
            return hex"";
        }

        if (callbackSelector == IERC7579ModuleConfig.uninstallModule.selector) {
            (uint256 moduleTypeId, address module) = _decodeModuleCallback(msgData);

            // A hook must be able to pass the host callback that removes this hook itself.
            // Other module configuration remains blocked by this security boundary.
            if (moduleTypeId == MODULE_TYPE_HOOK && module == address(this)) return hex"";
            revert ModuleConfigurationNotAllowed(callbackSelector, moduleTypeId, module);
        }

        if (callbackSelector == IERC7579ModuleConfig.installModule.selector) {
            (uint256 moduleTypeId, address module) = _decodeModuleCallback(msgData);
            revert ModuleConfigurationNotAllowed(callbackSelector, moduleTypeId, module);
        }

        revert UnsupportedCallback(callbackSelector);
    }

    function _checkExecutionCallback(bytes calldata msgData) internal view {
        (bytes32 mode, bytes calldata executionData) = _decodeExecutionCallback(msgData);
        bytes1 callType = LibERC7579.getCallType(mode);

        if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            revert DelegateCallNotAllowed();
        }

        if (callType == LibERC7579.CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(executionData);
            _checkCall(target, value, data);
        } else if (callType == LibERC7579.CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
            for (uint256 i; i < pointers.length; i++) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                _checkCall(target, value, data);
            }
        } else {
            revert UnsupportedCallType();
        }
    }

    function postCheck(bytes calldata) external payable override {}

    // ========== Allowlist Management ==========

    function setAllowlist(address target, bytes4[] calldata selectors) external {
        if (!initialized[msg.sender]) revert Unauthorized();
        _setAllowlist(msg.sender, target, selectors);
        emit AllowlistSet(msg.sender, target, selectors);
    }

    function removeAllowlist(address target) external {
        if (!initialized[msg.sender]) revert Unauthorized();
        _clearAllowlist(msg.sender, target);
        emit AllowlistRemoved(msg.sender, target);
    }

    // ========== View ==========

    function isInitialized(address account) external view returns (bool) {
        return initialized[account];
    }

    function isAllowlisted(address account, address target) external view returns (bool) {
        return allowlist[account][target].allowed;
    }

    function isSelectorAllowed(address account, address target, bytes4 selector) external view returns (bool) {
        AllowlistEntry storage entry = allowlist[account][target];
        if (!entry.allowed) return false;
        if (entry.allSelectorsAllowed) return true;
        return entry.selectors[selector];
    }

    // ========== Internal ==========

    function _checkCall(address target, uint256 value, bytes calldata data) internal view {
        // Compatible hosts execute a zero target as a call to the account itself.
        // Normalize before every allowlist and denylist check so the hook sees the same target.
        if (target == address(0)) target = msg.sender;

        // Account self-calls and calls to module-typed targets are hard security boundaries.
        // A narrowly authenticated Timelock proposal-creation call is the only exception.
        // It requires an exact selector allowlist and a live commitment for the current UserOp;
        // wildcard allowlists and every other module callback remain blocked.
        if (target == msg.sender) revert SelfCallNotAllowed();
        if (_isModule(target)) {
            if (_isAuthorizedTimelockProposal(target, value, data)) return;
            revert ModuleCallNotAllowed(target);
        }

        // The allowlist may bypass value and token-selector restrictions for ordinary targets.
        AllowlistEntry storage entry = allowlist[msg.sender][target];
        if (entry.allowed) {
            if (entry.allSelectorsAllowed) return;
            if (data.length >= 4 && entry.selectors[bytes4(data[:4])]) return;
        }

        // ETH transfer check
        if (value > 0) revert ETHTransferNotAllowed(target, value);

        // Blocked selector check
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            if (_isBlockedSelector(selector)) revert TokenTransferNotAllowed(target, selector);
        }
    }

    function _isModule(address target) internal view returns (bool) {
        (bool success, bytes memory result) =
            target.staticcall{gas: MODULE_CHECK_GAS}(abi.encodeWithSelector(IModule.isModuleType.selector, uint256(0)));
        if (!success || result.length != 32) return false;

        // The exact return length was checked above, so conversion reads the full canonical word.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 boolWord = uint256(bytes32(result));
        return boolWord <= 1;
    }

    function _isAuthorizedTimelockProposal(address target, uint256 value, bytes calldata data)
        internal
        view
        returns (bool)
    {
        if (value != 0 || data.length < 4 || bytes4(data[:4]) != CREATE_TIMELOCK_PROPOSAL) return false;

        // Requiring the selector to be listed explicitly prevents a broad target allowlist from
        // silently opting a module into this exceptional path.
        AllowlistEntry storage entry = allowlist[msg.sender][target];
        if (!entry.allowed || entry.allSelectorsAllowed || !entry.selectors[CREATE_TIMELOCK_PROPOSAL]) return false;

        (bool success, bytes memory result) = target.staticcall{gas: TIMELOCK_AUTH_CHECK_GAS}(
            abi.encodeCall(ITimelockProposalAuthorizer.isProposalCreationAuthorized, (msg.sender, data))
        );
        if (!success || result.length != 32) return false;

        bytes32 word;
        assembly ("memory-safe") {
            word := mload(add(result, 0x20))
        }
        // The exact 32-byte ABI return size was checked above; the authorizer magic occupies
        // its high four bytes by the ABI encoding of bytes4.
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes4(word) == TIMELOCK_PROPOSAL_AUTHORIZED;
    }

    function _isBlockedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == TRANSFER || selector == APPROVE || selector == TRANSFER_FROM
            || selector == INCREASE_ALLOWANCE || selector == DECREASE_ALLOWANCE || selector == SAFE_TRANSFER_FROM
            || selector == SAFE_TRANSFER_FROM_WITH_DATA || selector == SET_APPROVAL_FOR_ALL
            || selector == SAFE_TRANSFER_FROM_1155 || selector == SAFE_BATCH_TRANSFER_FROM;
    }

    function _setAllowlist(address account, address target, bytes4[] memory selectors) internal {
        AllowlistEntry storage entry = allowlist[account][target];

        // Maintain a unique, removable set of active targets for bounded uninstall cleanup.
        if (!entry.allowed) {
            allowlistedTargets[account].push(target);
            allowlistedTargetIndex[account][target] = allowlistedTargets[account].length;
        }

        // Clear stale selectors from the mapping (S-01)
        bytes4[] storage oldSelectors = entry.selectorList;
        for (uint256 i; i < oldSelectors.length; i++) {
            entry.selectors[oldSelectors[i]] = false;
        }
        delete entry.selectorList;

        entry.allowed = true;
        if (selectors.length == 0) {
            entry.allSelectorsAllowed = true;
        } else {
            entry.allSelectorsAllowed = false;
            for (uint256 i; i < selectors.length; i++) {
                bytes4 selector = selectors[i];
                if (!entry.selectors[selector]) {
                    entry.selectors[selector] = true;
                    entry.selectorList.push(selector);
                }
            }
        }
    }

    function _clearAllowlist(address account, address target) internal {
        AllowlistEntry storage entry = allowlist[account][target];
        if (!entry.allowed) return;

        // Clear all tracked selectors from the mapping
        bytes4[] storage oldSelectors = entry.selectorList;
        for (uint256 i; i < oldSelectors.length; i++) {
            entry.selectors[oldSelectors[i]] = false;
        }
        delete entry.selectorList;

        entry.allowed = false;
        entry.allSelectorsAllowed = false;

        uint256 indexPlusOne = allowlistedTargetIndex[account][target];
        if (indexPlusOne != 0) {
            address[] storage targets = allowlistedTargets[account];
            uint256 index = indexPlusOne - 1;
            uint256 lastIndex = targets.length - 1;
            if (index != lastIndex) {
                address movedTarget = targets[lastIndex];
                targets[index] = movedTarget;
                allowlistedTargetIndex[account][movedTarget] = index + 1;
            }
            targets.pop();
            delete allowlistedTargetIndex[account][target];
        }
    }

    function _decodeExecutionCallback(bytes calldata msgData)
        internal
        pure
        returns (bytes32 mode, bytes calldata executionData)
    {
        // selector + (bytes32 mode, offset=0x40, bytes length)
        uint256 executionDataLength = _validateDynamicCallback(msgData, 64);
        mode = bytes32(msgData[4:36]);
        executionData = msgData[100:100 + executionDataLength];
    }

    function _decodeModuleCallback(bytes calldata msgData)
        internal
        pure
        returns (uint256 moduleTypeId, address module)
    {
        // selector + (uint256 moduleTypeId, address module, offset=0x60, bytes length)
        _validateDynamicCallback(msgData, 96);
        moduleTypeId = uint256(bytes32(msgData[4:36]));

        uint256 moduleWord = uint256(bytes32(msgData[36:68]));
        if (moduleWord >> 160 != 0) revert InvalidCallbackData();
        // forge-lint: disable-next-line(unsafe-typecast)
        module = address(uint160(moduleWord));
    }

    function _validateDynamicCallback(bytes calldata msgData, uint256 headLength)
        internal
        pure
        returns (uint256 dynamicLength)
    {
        uint256 lengthOffset = 4 + headLength;
        uint256 dataOffset = lengthOffset + 32;
        if (msgData.length < dataOffset) revert InvalidCallbackData();

        // Only canonical ABI calldata is accepted. This also keeps all later slices in bounds.
        uint256 encodedOffset = uint256(bytes32(msgData[4 + headLength - 32:4 + headLength]));
        if (encodedOffset != headLength) revert InvalidCallbackData();

        dynamicLength = uint256(bytes32(msgData[lengthOffset:dataOffset]));
        if (dynamicLength > msgData.length - dataOffset) revert InvalidCallbackData();

        uint256 paddedLength = (dynamicLength + 31) & ~uint256(31);
        if (msgData.length != dataOffset + paddedLength) revert InvalidCallbackData();
    }
}
