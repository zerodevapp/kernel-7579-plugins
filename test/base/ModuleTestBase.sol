pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";

abstract contract ModuleTestBase is Test {
    // Common setup or utility functions for module tests can be added here
    IModule module;

    address constant WALLET = address(0x1234);
    IEntryPoint internal ENTRYPOINT;

    function setUp() public virtual {
        module = deployModule();
        ENTRYPOINT = EntryPointLib.deploy();
        _initializeTest();
    }

    function deployModule() internal virtual returns (IModule);

    function installData() internal view virtual returns (bytes memory);

    function _initializeTest() internal virtual;
}
