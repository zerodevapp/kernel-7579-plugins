pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";

import "src/CallPolicy.sol";

contract MockCallee {
    uint256 public bar;

    bytes public baz;

    function foo(uint256 _bar1, uint256 _bar2, bytes memory _baz) external payable {
        bar = _bar1 + _bar2;
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
        } else if (condition == ParamCondition.NOT_EQUAL) {
            return bytes32(uint256(param));
        } else if (condition == ParamCondition.ONE_OF) {
            return keccak256(abi.encodePacked(param, 10 + random));
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
        } else if (condition == ParamCondition.NOT_EQUAL) {
            return bytes32(uint256(param) + random);
        } else if (condition == ParamCondition.ONE_OF) {
            return keccak256(abi.encodePacked(param, random % 10));
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

    function testNotEqualSingle(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        testSingle(5, valueLimit, value, anyTarget, res, param, random);
    }

    function testMultipleParams(
        uint8 c1,
        uint8 c2,
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param1,
        uint256 random1,
        uint256 param2,
        uint256 random2
    ) external {
        vm.assume(c1 <= uint8(ParamCondition.NOT_EQUAL));
        vm.assume(c2 <= uint8(ParamCondition.NOT_EQUAL));
        vm.assume(valueLimit < type(uint256).max);
        vm.assume(value <= valueLimit);
        vm.assume(res <= uint8(Result.TargetViolation));

        ParamCondition condition1 = ParamCondition(c1);
        ParamCondition condition2 = ParamCondition(c2);
        param1 = param1 % (uint256(type(uint128).max) + 1) + 1;
        random1 = (random1 % param1) + 1;
        param2 = param2 % (uint256(type(uint128).max) + 1) + 1;
        random2 = (random2 % param2) + 1;

        if (anyTarget && res == 3) {
            res--;
        }
        Result result = Result(res);

        bytes32 id = bytes32(bytes4(0x12345678));
        address owner = makeAddr("Owner");
        bytes4 selector = mock.foo.selector;

        bytes32[] memory params1 = new bytes32[](1);
        params1[0] = bytes32(param1);
        bytes32[] memory params2 = new bytes32[](1);
        params2[0] = bytes32(param2);
        ParamRule[] memory rules = new ParamRule[](2);
        rules[0] = ParamRule({condition: condition1, offset: 0x00, params: params1});
        rules[1] = ParamRule({condition: condition2, offset: 0x20, params: params2});

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
                        result == Result.ParamRuleViolation && (random1 >= random2)
                            ? wrongParam(condition1, param1, random1)
                            : goodParam(condition1, param1, random1),
                        result == Result.ParamRuleViolation && (random1 <= random2)
                            ? wrongParam(condition2, param2, random2)
                            : goodParam(condition2, param2, random2),
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

    function testSingle(
        uint8 c,
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) public {
        vm.assume(c <= uint8(ParamCondition.NOT_EQUAL));
        vm.assume(valueLimit < type(uint256).max);
        vm.assume(value <= valueLimit);
        vm.assume(res <= uint8(Result.TargetViolation));

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

    function testOneOf(
        uint256 valueLimit,
        uint256 value,
        bool anyTarget,
        uint8 res,
        uint256 param,
        uint256 random
    ) external {
        vm.assume(valueLimit < type(uint256).max);
        vm.assume(value <= valueLimit);
        vm.assume(res <= uint8(Result.TargetViolation));

        param = param % (uint256(type(uint128).max) + 1) +1;
        random = (random % param) + 1;
        
        if(anyTarget && res == 3) {
            res--;
        }
        Result result = Result(res);

        bytes32 id = bytes32(bytes4(0x12345678));
        address owner = makeAddr("Owner");
        bytes4 selector = mock.foo.selector;

        bytes32[] memory params = new bytes32[](10);
        for(uint256 i = 0; i < 10; i++) {
            params[i] = keccak256(abi.encodePacked(param, i));
        }
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition : ParamCondition.ONE_OF,
            offset : 0x00,
            params : params
        });

        Permission memory p = Permission({
            callType : CallType.wrap(0x00),
            target : anyTarget ? address(0) : address(mock),
            selector : selector,
            valueLimit : valueLimit,
            rules : rules
        });

        Permission[] memory perms = new Permission[](1);
        perms[0] = p;

        vm.startPrank(owner);
        callPolicy.onInstall(abi.encodePacked(id, abi.encode(perms)));
        vm.stopPrank();

        // check if pass
        PackedUserOperation memory op = PackedUserOperation({
            sender : owner,
            nonce : 0,
            initCode : hex"",
            callData : abi.encodeWithSelector(
                IERC7579Account.execute.selector,
                bytes32(0),
                ExecLib.encodeSingle(
                    result == Result.TargetViolation? address(1) : address(mock),
                    result == Result.ValueViolation ? valueLimit + 1 : value,
                    abi.encodeWithSelector(
                        selector,
                        result == Result.ParamRuleViolation ? wrongParam(ParamCondition.ONE_OF, param, random) : goodParam(ParamCondition.ONE_OF, param, random),
                        hex"deadbeef"
                    )
                )
            ),
            accountGasLimits : bytes32(0),
            preVerificationGas : 0,
            gasFees : bytes32(0),
            paymasterAndData : hex"",
            signature : hex""
        });
        vm.startPrank(owner);
        if(result == Result.ParamRuleViolation) { 
            vm.expectRevert(CallPolicy.CallViolatesParamRule.selector);
        } else if(result == Result.ValueViolation) {
            vm.expectRevert(CallPolicy.CallViolatesValueRule.selector);
        } else if(result == Result.TargetViolation) {
            vm.expectRevert(CallPolicy.CallViolatesTargetRule.selector);
        }
        callPolicy.checkUserOpPolicy(
            id,
            op
        );
        vm.stopPrank();
    }
}
