pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";

import "src/CallPolicy.sol";

contract MockCallee {
    uint256 public bar;

    bytes public baz;

    function foo(uint256 _bar, bytes memory _baz) external payable {
        bar = _bar;
        baz = _baz;
    }
}

enum Result {
    Success,
    ParamRuleViolation,
    ValueViolation,
    TargetViolation
}

contract TestEncoding is Test {
    CallPolicy callPolicy;

    MockCallee mock;

    function setUp() external {
        callPolicy = new CallPolicy();
        mock = new MockCallee();
    }

    function wrongParam(ParamCondition condition, uint256 param, uint256 random) internal pure returns (bytes32) {
        if (random == 0) {
            random = 1;
        }
        if (condition == ParamCondition.EQUAL) {
            return bytes32(uint256(param + random));
        } else if (condition == ParamCondition.GREATER_THAN) {
            return bytes32(uint256(param - random + 1));
        } else if (condition == ParamCondition.LESS_THAN) {
            return bytes32(uint256(param + random - 1));
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL) {
            return bytes32(uint256(param - random));
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL) {
            return bytes32(uint256(param + random));
        }
        return bytes32(0);
    }

    function goodParam(ParamCondition condition, uint256 param, uint256 random) internal pure returns (bytes32) {
        if (random == 0) {
            random = 1;
        }
        if (condition == ParamCondition.EQUAL) {
            return bytes32(uint256(param));
        } else if (condition == ParamCondition.GREATER_THAN) {
            return bytes32(uint256(param) + random);
        } else if (condition == ParamCondition.LESS_THAN) {
            return bytes32(uint256(param) - random);
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL) {
            return bytes32(uint256(param) + random - 1);
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL) {
            return bytes32(uint256(param) - random + 1);
        }
        return bytes32(0);
    }

    function testEqualSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(0, valueLimit, value, anyTarget, res, param, random);
    }

    function testGreaterThanSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(1, valueLimit, value, anyTarget, res, param, random);
    }

    function testLessThanSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(2, valueLimit, value, anyTarget, res, param, random);
    }

    function testGreaterThanOrEqualSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(3, valueLimit, value, anyTarget, res, param, random);
    }

    function testLessThanOrEqualSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(4, valueLimit, value, anyTarget, res, param, random);
    }

    function testSingle(
        uint8 c,
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) public {
        vm.assume(c <= uint8(ParamCondition.LESS_THAN_OR_EQUAL));
        vm.assume(valueLimit < type(uint256).max);
        vm.assume(value <= valueLimit);
        vm.assume(res <= 3);

        ParamCondition condition = ParamCondition(c);
        param = param % (uint256(type(uint128).max) + 1) + 1;
        random = (random % param) + 1;

        if (anyTarget && res == 3) {
            res--;
        }
        Result result = Result(res);

        bytes32 id = bytes32(bytes4(0x12345678));
        address owner = makeAddr("Owner");
        bytes4 selector = mock.foo.selector;

        bytes32[] memory params = new bytes32[](1);
        params[0] = bytes32(param);
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({condition: condition, offset: 0x00, params: params});

        Permission memory p = Permission({
            callType: CallType.wrap(0x00),
            target: anyTarget ? address(0) : address(mock),
            selector: selector,
            valueLimit: valueLimit,
            rules: rules
        });

        Permission[] memory perms = new Permission[](1);
        perms[0] = p;

        vm.startPrank(owner);
        callPolicy.onInstall(abi.encodePacked(id, abi.encode(perms)));
        vm.stopPrank();

        // check if pass
        PackedUserOperation memory op = PackedUserOperation({
            sender: owner,
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                IERC7579Account.execute.selector,
                bytes32(0),
                ExecLib.encodeSingle(
                    result == Result.TargetViolation ? address(1) : address(mock),
                    result == Result.ValueViolation ? valueLimit + 1 : value,
                    abi.encodeWithSelector(
                        selector,
                        result == Result.ParamRuleViolation
                            ? wrongParam(condition, param, random)
                            : goodParam(condition, param, random),
                        hex"deadbeef"
                    )
                )
            ),
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            signature: hex""
        });
        vm.startPrank(owner);
        if (result == Result.ParamRuleViolation) {
            vm.expectRevert(CallPolicy.CallViolatesParamRule.selector);
        } else if (result == Result.ValueViolation) {
            vm.expectRevert(CallPolicy.CallViolatesValueRule.selector);
        } else if (result == Result.TargetViolation) {
            vm.expectRevert(CallPolicy.CallViolatesTargetRule.selector);
        }
        callPolicy.checkUserOpPolicy(id, op);
        vm.stopPrank();
    }
}
