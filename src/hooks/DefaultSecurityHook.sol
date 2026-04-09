// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook, IModule} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "src/types/Constants.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "openzeppelin-contracts/contracts/token/ERC1155/IERC1155.sol";

/// @title DefaultSecurityHook
/// @notice A default security hook for ERC-7579 smart accounts that blocks dangerous operations
///         by default and provides a per-account (target, selector[]) allowlisting mechanism.
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

        // Clear ALL allowlisted targets for the account
        address[] storage targets = allowlistedTargets[msg.sender];
        for (uint256 i; i < targets.length; i++) {
            _clearAllowlist(msg.sender, targets[i]);
        }
        delete allowlistedTargets[msg.sender];

        initialized[msg.sender] = false;
        emit Uninitialized(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    // ========== IHook ==========

    function preCheck(address, uint256, bytes calldata msgData) external payable override returns (bytes memory) {
        // msgData layout: [0:4] execute selector, [4:36] mode, [36:..] executionData
        bytes32 mode = bytes32(msgData[4:36]);
        bytes1 callType = LibERC7579.getCallType(mode);

        if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            revert DelegateCallNotAllowed();
        }

        // Extract executionData from the ABI-encoded msgData
        // msgData[4:] is (bytes32 mode, bytes executionData)
        // The bytes param is ABI-encoded with an offset at [36:68] then length + data
        bytes calldata executionData;
        assembly {
            let offsetPos := add(msgData.offset, 36)
            let offset := calldataload(offsetPos)
            let dataStart := add(add(msgData.offset, 4), offset)
            executionData.length := calldataload(dataStart)
            executionData.offset := add(dataStart, 0x20)
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

        return hex"";
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
        // Check allowlist first
        AllowlistEntry storage entry = allowlist[msg.sender][target];
        if (entry.allowed) {
            if (entry.allSelectorsAllowed) return;
            if (data.length >= 4 && entry.selectors[bytes4(data[:4])]) return;
        }

        // Self-call check
        if (target == msg.sender) revert SelfCallNotAllowed();

        // Module check
        if (_isModule(target)) revert ModuleCallNotAllowed(target);

        // ETH transfer check
        if (value > 0) revert ETHTransferNotAllowed(target, value);

        // Blocked selector check
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            if (_isBlockedSelector(selector)) revert TokenTransferNotAllowed(target, selector);
        }
    }

    function _isModule(address target) internal view returns (bool) {
        (bool success,) =
            target.staticcall{gas: MODULE_CHECK_GAS}(abi.encodeWithSelector(IModule.isModuleType.selector, uint256(0)));
        return success;
    }

    function _isBlockedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == TRANSFER || selector == APPROVE || selector == TRANSFER_FROM
            || selector == INCREASE_ALLOWANCE || selector == DECREASE_ALLOWANCE || selector == SAFE_TRANSFER_FROM
            || selector == SAFE_TRANSFER_FROM_WITH_DATA || selector == SET_APPROVAL_FOR_ALL
            || selector == SAFE_TRANSFER_FROM_1155 || selector == SAFE_BATCH_TRANSFER_FROM;
    }

    function _setAllowlist(address account, address target, bytes4[] memory selectors) internal {
        AllowlistEntry storage entry = allowlist[account][target];

        // Track target for cleanup on uninstall (S-03)
        if (!entry.allowed) {
            allowlistedTargets[account].push(target);
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
                entry.selectors[selectors[i]] = true;
                entry.selectorList.push(selectors[i]);
            }
        }
    }

    function _clearAllowlist(address account, address target) internal {
        AllowlistEntry storage entry = allowlist[account][target];

        // Clear all tracked selectors from the mapping
        bytes4[] storage oldSelectors = entry.selectorList;
        for (uint256 i; i < oldSelectors.length; i++) {
            entry.selectors[oldSelectors[i]] = false;
        }
        delete entry.selectorList;

        entry.allowed = false;
        entry.allSelectorsAllowed = false;
    }
}
