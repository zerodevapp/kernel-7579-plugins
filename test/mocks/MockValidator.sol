pragma solidity ^0.8.0;

import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice Minimal IValidator mock that records onInstall/onUninstall calls for assertions.
contract MockValidator is IValidator {
    uint256 public onInstallCallCount;
    uint256 public onUninstallCallCount;
    bytes public lastOnInstallData;
    bytes public lastOnUninstallData;

    // Records call order so tests can assert onUninstall happens strictly before onInstall.
    uint256 public onUninstallCallOrder;
    uint256 public onInstallCallOrder;
    uint256 internal callCounter;

    function onInstall(bytes calldata data) external payable override {
        onInstallCallCount++;
        lastOnInstallData = data;
        onInstallCallOrder = ++callCounter;
    }

    function onUninstall(bytes calldata data) external payable override {
        onUninstallCallCount++;
        lastOnUninstallData = data;
        onUninstallCallOrder = ++callCounter;
    }

    function isModuleType(uint256) external pure override returns (bool) {
        return true;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable override returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0x1626ba7e;
    }
}
