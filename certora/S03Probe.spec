/* Probe: two-target uninstall — find why t1 survives. @author taek <leekt216@gmail.com> */
methods {
    function onInstall(bytes data) external;
    function onUninstall(bytes data) external;
    function setAllowlist(address target, bytes4[] selectors) external;
    function isInitialized(address account) external returns (bool) envfree;
    function isAllowlisted(address account, address target) external returns (bool) envfree;
    function allowlistedTargetsLength(address account) external returns (uint256) envfree;
    function entryPristine(address account, address target, bytes4 selector) external returns (bool) envfree;
}

function setup2(env eI, env eS1, env eS2, address account, address t1, bytes4 s1, address t2) {
    require eI.msg.sender == account; require eS1.msg.sender == account; require eS2.msg.sender == account;
    require !isInitialized(account);
    require entryPristine(account, t1, s1);
    require t1 != t2;
    bytes empty; require empty.length == 0;
    onInstall(eI, empty);
    bytes4[] sel1; require sel1.length == 1; require sel1[0] == s1; setAllowlist(eS1, t1, sel1);
    bytes4[] sel2; require sel2.length == 0; setAllowlist(eS2, t2, sel2);
}

// Find a CE where t1 survives uninstall.
rule findT1Survives(address t1, bytes4 s1, address t2) {
    env eI; env eS1; env eS2; env eU;
    address account = eI.msg.sender; require eU.msg.sender == account;
    setup2(eI, eS1, eS2, account, t1, s1, t2);
    require isAllowlisted(account, t1);
    require isAllowlisted(account, t2);
    require allowlistedTargetsLength(account) == 2;
    bytes empty; require empty.length == 0;
    onUninstall(eU, empty);
    satisfy isAllowlisted(account, t1) == true;   // can t1 survive?
}
