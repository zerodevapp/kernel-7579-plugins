pragma solidity ^0.8.0;


import {Test} from "forge-std/Test.sol";
import {IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER} from "src/types/Constants.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";

abstract contract StatelessValidatorWithSenderTestBase is ModuleTestBase {

    function statelessValidationSignatureWithSender(bytes32 hash, bool valid)
        internal
        view
        virtual
        returns (address, bytes memory);
    
    function testModuleTypeStatelessValidatorWithSender() public view{
        IStatelessValidatorWithSender validatorModule = IStatelessValidatorWithSender(address(module));
        bool result = validatorModule.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER);
        assertTrue(result);
    }

    function testStatelessValidatorWithSenderSuccess() external {
        IStatelessValidatorWithSender validatorModule = IStatelessValidatorWithSender(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (address caller, bytes memory sig) = statelessValidationSignatureWithSender( message, true);

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithDataWithSender(caller, message, sig, installData());
        vm.stopPrank();

        assertTrue(result);
    }

    function testStatelessValidatorWithSenderFail() external {
        IStatelessValidatorWithSender validatorModule = IStatelessValidatorWithSender(address(module));

        bytes32 message = keccak256(abi.encodePacked("TEST_MESSAGE"));
        (address caller, bytes memory sig) = statelessValidationSignatureWithSender( message, false);

        vm.startPrank(WALLET);
        bool result = validatorModule.validateSignatureWithDataWithSender(caller, message, sig, installData());
        vm.stopPrank();

        assertFalse(result);
    }
}
