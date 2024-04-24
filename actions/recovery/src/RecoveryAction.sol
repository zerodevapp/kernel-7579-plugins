pragma solidity ^0.8.0;

import {IValidator} from "kernel/interfaces/IERC7579Modules.sol";

contract RecoveryAction {
    function doRecovery(address _validator, bytes calldata _data) external {
        IValidator(_validator).onUninstall(hex"");
        IValidator(_validator).onInstall(_data);
    }
}
