pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";
import {MODULE_TYPE_STATELESS_VALIDATOR} from "src/types/Constants.sol";

abstract contract StatelessValidatorTestBase is ModuleTestBase {
    function statelessValidationSignature(bytes32 hash, bool valid)
        internal
        view
        virtual
        returns (address, bytes memory);

    function testModuleTypeStatelessValidator() public view {
        IStatelessValidator validatorModule = IStatelessValidator(address(module));
        bool result = validatorModule.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR); // MODULE_TYPE_STATELESS_VALIDATOR = 4
        assertTrue(result);
    }

    function testStatelessValidatorSuccess() external {
        IStatelessValidator validatorModule = IStatelessValidator(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (, bytes memory sig) = statelessValidationSignature(message, true);

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithData(message, sig, installData());
        vm.stopPrank();

        assertTrue(result);
    }

    function testStatlessValidatorFail() external virtual {
        IStatelessValidator validatorModule = IStatelessValidator(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (, bytes memory sig) = statelessValidationSignature(message, false);

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithData(message, sig, installData());
        vm.stopPrank();

        assertFalse(result);
    }
}
