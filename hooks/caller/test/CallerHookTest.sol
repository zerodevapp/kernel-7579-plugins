pragma solidity ^0.8.13;

import {CallerHook} from "../src/CallerHook.sol";
import {Test} from "forge-std/Test.sol";
import {MockAction} from "./mock/MockAction.sol";
import {Kernel} from "kernel/src/Kernel.sol";
import {IEntryPoint} from "kernel/src/interfaces/IEntryPoint.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {ValidatorLib, ValidationId} from "kernel/src/utils/ValidationTypeLib.sol";
import {KernelFactory} from "kernel/src/factory/KernelFactory.sol";

address constant ENTRYPOINT_0_7_ADDR = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

contract CallerHookTest is Test {
    CallerHook public callerHook;
    address public account1 = makeAddr("account1");
    address public account2 = makeAddr("account2");
    MockAction public mockAction;
    address[] public accounts = [account1, account2];
    MockValidator public mockValidator;
    ValidationId rootValidation;
    bytes[] public initConfig;

    function setUp() public {
        callerHook = new CallerHook();
        mockAction = new MockAction();
        mockValidator = new MockValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(mockValidator);
        initConfig = new bytes[](0);
    }

    function test_install() public {
        callerHook.onInstall(abi.encode(accounts));
        assertTrue(callerHook.installed(address(this)));
        for (uint256 i = 0; i < accounts.length; i++) {
            assertEq(callerHook.allowedAccounts(address(this), i), accounts[i]);
        }
    }

    function test_hook() public {
        address template = address(new Kernel(IEntryPoint(ENTRYPOINT_0_7_ADDR)));
        KernelFactory factory = new KernelFactory(address(template));
        Kernel kernel = Kernel(payable(factory.createAccount(initData(), bytes32(0))));
        address(kernel).call(
            abi.encodeWithSelector(
                Kernel.installModule.selector,
                3,
                address(mockAction),
                abi.encodePacked(
                    MockAction.doSomething.selector,
                    address(callerHook),
                    abi.encode(hex"ff", abi.encodePacked(bytes1(0xff), abi.encode(accounts)))
                )
            )
        );

        vm.prank(account1);
        MockAction(address(kernel)).doSomething();
    }

    function test_update() public {
        address template = address(new Kernel(IEntryPoint(ENTRYPOINT_0_7_ADDR)));
        KernelFactory factory = new KernelFactory(address(template));
        Kernel kernel = Kernel(payable(factory.createAccount(initData(), bytes32(0))));

        vm.startPrank(address(kernel));
        callerHook.onInstall(abi.encode(accounts));
        assertTrue(callerHook.installed(address(kernel)));
        for (uint256 i = 0; i < accounts.length; i++) {
            assertEq(callerHook.allowedAccounts(address(kernel), i), accounts[i]);
        }

        address[] memory newAccounts = new address[](2);
        newAccounts[0] = makeAddr("New Acc1");
        newAccounts[1] = makeAddr("New Acc2");
        // do update
        address(kernel).call(
            abi.encodeWithSelector(
                Kernel.installModule.selector,
                3,
                address(mockAction),
                abi.encodePacked(
                    MockAction.doSomething.selector,
                    address(callerHook),
                    abi.encode(hex"ff", abi.encodePacked(bytes1(0xff), abi.encode(newAccounts)))
                )
            )
        );
        assertTrue(callerHook.installed(address(kernel)));
        for (uint256 i = 0; i < accounts.length; i++) {
            assertEq(callerHook.allowedAccounts(address(kernel), i), newAccounts[i]);
        }

        vm.stopPrank();

        vm.prank(newAccounts[0]);
        MockAction(address(kernel)).doSomething();

        vm.prank(newAccounts[1]);
        MockAction(address(kernel)).doSomething();

        vm.prank(accounts[0]);
        vm.expectRevert();
        MockAction(address(kernel)).doSomething();

        vm.prank(accounts[1]);
        vm.expectRevert();
        MockAction(address(kernel)).doSomething();
    }

    function initData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(Kernel.initialize.selector, rootValidation, address(0), hex"", hex"", initConfig);
    }
}
