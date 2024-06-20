pragma solidity ^0.8.0;

import {IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "kernel/src/types/Constants.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

address constant ENTRYPOINT_0_7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

struct SpendingLimitData {
    address token;
    uint256 allowance;
}

contract SpendingLimit is IHook {
    mapping(address account => uint256) public listLength;
    mapping(uint256 idx => mapping(address => SpendingLimitData)) public spendingLimit;

    error ExceedsAllowance();

    function onInstall(bytes calldata data) external payable {
        require(listLength[msg.sender] == 0, "already initialized");
        bytes[] calldata arr = _parseCalldataArrayBytes(data);
        for (uint256 i = 0; i < arr.length; i++) {
            spendingLimit[i][msg.sender] =
                SpendingLimitData({token: address(bytes20(arr[i][0:20])), allowance: uint256(bytes32(arr[i][20:52]))});
        }
        listLength[msg.sender] = arr.length;
    }

    function onUninstall(bytes calldata) external payable {
        require(listLength[msg.sender] > 0, "not initialized");
        uint256 length = listLength[msg.sender];
        for (uint256 i = 0; i < length; i++) {
            delete spendingLimit[i][msg.sender];
        }
        delete listLength[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return listLength[smartAccount] != 0;
    }

    function preCheck(address, uint256, bytes calldata) external payable override returns (bytes memory) {
        uint256 length = listLength[msg.sender];
        uint256[] memory balances = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            SpendingLimitData memory data = spendingLimit[i][msg.sender];
            if (data.token == address(0)) {
                balances[i] = msg.sender.balance;
            } else {
                balances[i] = ERC20(data.token).balanceOf(msg.sender);
            }
        }
        return abi.encode(balances);
    }

    function postCheck(bytes calldata context, bool, bytes calldata) external payable override {
        uint256 length = listLength[msg.sender];
        uint256[] memory preBalance = abi.decode(context, (uint256[]));
        for (uint256 i = 0; i < length; i++) {
            SpendingLimitData storage data = spendingLimit[i][msg.sender];
            uint256 balance;
            if (data.token == address(0)) {
                balance = msg.sender.balance;
            } else {
                balance = ERC20(data.token).balanceOf(msg.sender);
            }
            // if balance increased, skip the allowance check
            if (balance > preBalance[i]) {
                continue;
            }
            uint256 used = preBalance[i] - balance;
            if (data.allowance < used) {
                revert ExceedsAllowance();
            }
            data.allowance -= used;
        }
    }

    function _parseCalldataArrayBytes(bytes calldata _data) internal pure returns (bytes[] calldata arr) {
        assembly {
            arr.offset := add(add(_data.offset, 0x20), calldataload(_data.offset))
            arr.length := calldataload(sub(arr.offset, 0x20))
        }
    }
}
