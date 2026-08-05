pragma solidity ^0.8.0;

import {IValidator} from "src/interfaces/IERC7579Modules.sol";

/**
 * @title RecoveryAction
 * @notice Executor action that re-initializes a validator with new configuration data.
 * @dev Called via the account to swap a validator's owner/config by uninstalling then
 *      reinstalling it in a single call.
 */
contract RecoveryAction {
    function doRecovery(address _validator, bytes calldata _data) external {
        IValidator(_validator).onUninstall(hex"");
        IValidator(_validator).onInstall(_data);
    }
}
