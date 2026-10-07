pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RecoveryAction} from "src/actions/RecoveryAction.sol";
import {MockValidator} from "./mocks/MockValidator.sol";

contract RecoveryActionTest is Test {
    RecoveryAction internal action;
    MockValidator internal validator;

    function setUp() public {
        action = new RecoveryAction();
        validator = new MockValidator();
    }

    function test_doRecovery_CallsOnUninstallThenOnInstall() public {
        bytes memory newConfig = abi.encode(address(0xBEEF));

        action.doRecovery(address(validator), newConfig);

        assertEq(validator.onUninstallCallCount(), 1, "onUninstall should be called exactly once");
        assertEq(validator.onInstallCallCount(), 1, "onInstall should be called exactly once");
    }

    function test_doRecovery_PassesEmptyBytesToOnUninstall() public {
        bytes memory newConfig = abi.encode(address(0xBEEF));

        action.doRecovery(address(validator), newConfig);

        assertEq(validator.lastOnUninstallData(), hex"", "onUninstall must receive empty calldata");
    }

    function test_doRecovery_PassesDataThroughToOnInstall() public {
        bytes memory newConfig = abi.encode(address(0xCAFE), uint256(42));

        action.doRecovery(address(validator), newConfig);

        assertEq(validator.lastOnInstallData(), newConfig, "onInstall must receive the passed _data unchanged");
    }

    function test_doRecovery_CallsOnUninstallBeforeOnInstall() public {
        bytes memory newConfig = abi.encode(address(0xCAFE));

        action.doRecovery(address(validator), newConfig);

        assertLt(
            validator.onUninstallCallOrder(),
            validator.onInstallCallOrder(),
            "onUninstall must be called strictly before onInstall"
        );
    }

    function test_doRecovery_WithEmptyData_ForwardsEmptyDataToOnInstall() public {
        action.doRecovery(address(validator), hex"");

        assertEq(validator.onInstallCallCount(), 1, "onInstall should still be invoked with empty data");
        assertEq(validator.lastOnInstallData(), hex"", "onInstall should receive empty bytes as-is");
    }

    function test_doRecovery_WhenValidatorReverts_PropagatesRevert() public {
        RevertingValidator revertingValidator = new RevertingValidator();

        vm.expectRevert(RevertingValidator.AlwaysReverts.selector);
        action.doRecovery(address(revertingValidator), "");
    }

    function test_doRecovery_WhenOnUninstallReverts_OnInstallIsNeverCalled() public {
        // onUninstall reverts before onInstall would run, so onInstall must never be reached.
        RevertOnUninstallValidator revertingValidator = new RevertOnUninstallValidator();

        vm.expectRevert(RevertOnUninstallValidator.UninstallReverts.selector);
        action.doRecovery(address(revertingValidator), "");

        assertEq(revertingValidator.onInstallCallCount(), 0, "onInstall must not be called if onUninstall reverts");
    }
}

contract RevertingValidator {
    error AlwaysReverts();

    function onUninstall(bytes calldata) external pure {
        revert AlwaysReverts();
    }

    function onInstall(bytes calldata) external pure {
        revert AlwaysReverts();
    }
}

contract RevertOnUninstallValidator {
    error UninstallReverts();

    uint256 public onInstallCallCount;

    function onUninstall(bytes calldata) external pure {
        revert UninstallReverts();
    }

    function onInstall(bytes calldata) external {
        onInstallCallCount++;
    }
}
