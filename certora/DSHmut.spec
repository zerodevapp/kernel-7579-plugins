methods {
    function checkCall(address, uint256, bytes) external;
    function selOf(bytes) external returns (bytes4) envfree;
    function h_allowed(address, address) external returns (bool) envfree;
    function h_allSelectorsAllowed(address, address) external returns (bool) envfree;
    function h_selectorMapped(address, address, bytes4) external returns (bool) envfree;
    function DefaultSecurityHook._isModule(address) internal returns (bool) => notAModule();
}
function notAModule() returns bool { return false; }

definition BLOCKED(bytes4 s) returns bool =
       s == to_bytes4(0xa9059cbb) || s == to_bytes4(0x095ea7b3) || s == to_bytes4(0x23b872dd)
    || s == to_bytes4(0x39509351) || s == to_bytes4(0xa457c2d7) || s == to_bytes4(0x42842e0e)
    || s == to_bytes4(0xb88d4fde) || s == to_bytes4(0xa22cb465) || s == to_bytes4(0xf242432a)
    || s == to_bytes4(0x2eb2c2d6);

definition ALLOW_PASS(address acct, address target, bytes4 sel) returns bool =
    h_allowed(acct, target) && ( h_allSelectorsAllowed(acct, target) || h_selectorMapped(acct, target, sel) );

// MUTANT: asserts the OPPOSITE of the real property. Must be VIOLATED (counterexample),
// proving the assert path is genuinely exercised (deny rule is not vacuous).
rule mutantDenyDoesNotRevert(address target, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender;
    require data.length == 4;
    bytes4 sel = selOf(data);
    require BLOCKED(sel);
    require target != account;
    require !ALLOW_PASS(account, target, sel);
    checkCall@withrevert(e, target, 0, data);
    assert !lastReverted, "MUTANT expected to be violated";
}

// MUTANT: allSelectorsAllowed but asserts it DOES revert. Must be VIOLATED.
rule mutantAllPassReverts(address target, uint256 value, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender;
    require h_allowed(account, target);
    require h_allSelectorsAllowed(account, target);
    checkCall@withrevert(e, target, value, data);
    assert lastReverted, "MUTANT expected to be violated";
}
