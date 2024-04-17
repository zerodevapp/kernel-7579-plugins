pragma solidity ^0.8.0;

import {IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK} from "kernel/src/types/Constants.sol";

address constant ENTRYPOINT_0_7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

contract OnlyEntryPointHook is IHook {
    mapping(address => bool) public installed;

    function onInstall(bytes calldata) external payable {
        installed[msg.sender] = true;
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
        require(msgSender == ENTRYPOINT_0_7, "only entrypoint");
    }

    function postCheck(bytes calldata, bool, bytes calldata) external payable override {}
}
