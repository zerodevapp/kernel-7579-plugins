pragma solidity ^0.8.0;

import {IValidator} from "kernel/interfaces/IERC7579Modules.sol";

contract RecoveryActionV2 {
    function doRecovery(address _validator, bytes calldata uninstallData, bytes calldata installData) external {
        IValidator(_validator).onUninstall(uninstallData);
        IValidator(_validator).onInstall(installData);
    }
}