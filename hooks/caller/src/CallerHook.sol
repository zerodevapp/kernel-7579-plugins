pragma solidity ^0.8.13;

import {IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "kernel/src/types/Constants.sol";

contract CallerHook is IHook {
    mapping(address => bool) public installed;
    mapping(address caller => mapping(address account => bool allowed)) public allowed;
    event CallerRegistered(address _user, address _caller);

    function onInstall(bytes calldata data) external payable {
        installed[msg.sender] = true;
        address[] memory accounts = abi.decode(data, (address[]));
        for (uint256 i = 0; i < accounts.length; i++) {
            allowed[accounts[i]][msg.sender] = true;
            emit CallerRegistered(msg.sender, accounts[i]);
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
        require(allowed[msgSender][msg.sender], "not allowed");
        return hex"";
    }

    function postCheck(bytes calldata) external payable override {}
}
