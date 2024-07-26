pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";

import "src/CallPolicy.sol";

contract MockCallPolicy is CallPolicy {

    function sudoSetPolicy(bytes32 _id, bytes32 _permissionHash, address _owner, bytes memory _permission) external {
        setPermission(_id, _permissionHash, _owner, _permission);
    }
}

contract TestEncoding is Test {

    MockCallPolicy mock;

    function setUp() external {
        mock = new MockCallPolicy();
    }

    function testEncoding(bytes memory tb) external {
        address owner = makeAddr("Owner");

        mock.sudoSetPolicy(bytes32(uint256(0x12345678)), bytes32(uint256(0x987654321)), owner, tb);

        bytes memory result = mock.encodedPermissions(bytes32(uint256(0x12345678)), bytes32(uint256(0x987654321)), owner);

        assertEq(keccak256(result), keccak256(tb));
    }
}
