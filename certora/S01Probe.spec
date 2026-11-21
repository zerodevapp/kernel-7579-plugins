methods {
    function setAllowlist(address target, bytes4[] selectors) external;
    function isSelectorAllowed(address account, address target, bytes4 selector) external returns (bool) envfree;
    function isInitialized(address account) external returns (bool) envfree;
    function entryPristine(address account, address target, bytes4 selector) external returns (bool) envfree;
    function selectorListLen(address account, address target) external returns (uint256) envfree;
    function selectorMapped(address account, address target, bytes4 selector) external returns (bool) envfree;
    function seedSingle(address account, address target, bytes4 sel) external;
    function _.isModuleType(uint256) external => NONDET;
}

// Isolated clear-loop test: seed selectorList=[b], then setAllowlist([a]); b must clear.
rule seededClearLoop(address target, bytes4 a, bytes4 b) {
    env e;
    address account = e.msg.sender;
    require a != b;
    seedSingle(e, account, target, b);
    // sanity: seed took
    require selectorMapped(account, target, b) == true;
    require selectorListLen(account, target) == 1;
    bytes4[] onlyA;
    require onlyA.length == 1;
    require onlyA[0] == a;
    setAllowlist(e, target, onlyA);
    assert selectorMapped(account, target, b) == false, "seeded b not cleared by setAllowlist([a])";
}

// After pristine start + set[A,B], both A and B are allowed, selectorList length 2.
rule afterFirstSet(address target, bytes4 a, bytes4 b) {
    env e;
    address account = e.msg.sender;
    require isInitialized(account);
    require a != b;
    require entryPristine(account, target, a);
    require entryPristine(account, target, b);
    bytes4[] both;
    require both.length == 2;
    require both[0] == a;
    require both[1] == b;
    setAllowlist(e, target, both);
    assert selectorListLen(account, target) == 2, "selectorList not length 2 after first set";
    assert selectorMapped(account, target, a) == true, "a not mapped after first set";
    assert selectorMapped(account, target, b) == true, "b not mapped after first set";
}

// After pristine + set[A,B] + set[A], B mapping is cleared.
rule afterSecondSet(address target, bytes4 a, bytes4 b) {
    env e;
    require e.msg.sender == e.msg.sender;
    address account = e.msg.sender;
    require isInitialized(account);
    require a != b;
    require entryPristine(account, target, a);
    require entryPristine(account, target, b);
    bytes4[] both;
    require both.length == 2;
    require both[0] == a;
    require both[1] == b;
    setAllowlist(e, target, both);
    bytes4[] onlyA;
    require onlyA.length == 1;
    require onlyA[0] == a;
    setAllowlist(e, target, onlyA);
    assert selectorMapped(account, target, b) == false, "b mapping not cleared after second set";
}
