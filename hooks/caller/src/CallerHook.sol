pragma solidity ^0.8.13;

import {IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "kernel/src/types/Constants.sol";

contract CallerHook is IHook {
    mapping(address => bool) public installed;
    mapping(address account => address[]) public allowedAccounts;
    error InvalidCaller();

    function onInstall(bytes calldata data) external payable {
        installed[msg.sender] = true;
        address[] memory accounts = abi.decode(data, (address[]));
        for (uint256 i = 0; i < accounts.length; i++) {
            allowedAccounts[msg.sender] = accounts;
        }
    }

    function onUninstall(bytes calldata) external payable {
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installed[smartAccount];
    }

    function preCheck(address msgSender, uint256, bytes calldata) external payable override returns (bytes memory) {
        address[] memory accounts  = allowedAccounts[msg.sender];
        for(uint256 i = 0; i < accounts.length; i++) {
            if(accounts[i] == msgSender) {
                return hex"";
            }
        }
        revert InvalidCaller();
    }

    function postCheck(bytes calldata) external payable override {}
}
