pragma solidity ^0.8.0;

contract MockAction {
    event Log(address indexed sender);

    function doSomething() external {
        // do something
        emit Log(msg.sender);
    }
}