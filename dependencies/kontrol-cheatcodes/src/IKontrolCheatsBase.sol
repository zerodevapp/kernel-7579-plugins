// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;
pragma experimental ABIEncoderV2;

interface KontrolCheatsBase {
    enum ComparisonOperator { Equal, NotEqual, LessThanOrEqual, LessThan, GreaterThanOrEqual, GreaterThan }
    // Expects a call using the CALL opcode to an address with the specified calldata.
    function expectRegularCall(address,bytes calldata) external;
    // Expects a call using the CALL opcode to an address with the specified msg.value and calldata.
    function expectRegularCall(address,uint256,bytes calldata) external;
    // Expects a static call to an address with the specified calldata.
    function expectStaticCall(address,bytes calldata) external;
    // Expects a delegate call to an address with the specified calldata.
    function expectDelegateCall(address,bytes calldata) external;
    // Expects that no contract calls are made after invoking the cheatcode.
    function expectNoCall() external;
    // Expects the given address to deploy a new contract, using the CREATE opcode, with the specified value and bytecode.
    function expectCreate(address,uint256,bytes calldata) external;
    // Expects the given address to deploy a new contract, using the CREATE2 opcode, with the specified value and bytecode (appended with a bytes32 salt).
    function expectCreate2(address,uint256,bytes calldata) external;
    // Makes the storage of the given address completely symbolic.
    function symbolicStorage(address) external;
    // Makes the storage of the given address completely symbolic with specified K variable name.
    function symbolicStorage(address, string calldata) external;
    // Adds an address to the whitelist.
    function allowCallsToAddress(address) external;
    // Adds an address and calldata to the whitelist.
    function allowCalls(address, bytes calldata) external;
    // Adds an address and a storage slot to the whitelist.
    function allowChangesToStorage(address,uint256) external;
    // Sets the remaining gas to an infinite value.
    function infiniteGas() external;
    // Sets the current <gas> cell to the supplied amount.
    function setGas(uint256) external;
    // Returns a symbolic unsigned integer
    function freshUInt(uint8) external view returns (uint256);
    // Returns a symbolic unsigned integer with specified K variable name.
    function freshUInt(uint8, string calldata) external view returns (uint256);
    // Returns a symbolic boolean value
    function freshBool() external view returns (bool);
    // Returns a symbolic boolean value with specified K variable name.
    function freshBool(string calldata) external view returns (bool);
    // Returns a symbolic byte array
    function freshBytes(uint256) external view returns (bytes memory);
    // Returns a symbolic byte array with specified K variable name.
    function freshBytes(uint256, string calldata) external view returns (bytes memory);
    // Returns a symbolic address
    function freshAddress() external view returns (address);
    // Returns a symbolic address with specified K variable name.
    function freshAddress(string calldata) external view returns (address);
    // Removes a branching condition from the path constraints
    function forgetBranch(uint256, ComparisonOperator, uint256) external;
}
