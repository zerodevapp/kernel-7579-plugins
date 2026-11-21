methods {
    function checkCall(address, uint256, bytes) external;
    function h_selectorMapped(address, address, bytes4) external returns (bool) envfree;
}
function bindSel(bytes4 sel, bytes data) returns bool {
    return data.length == 4 && data[0]==sel[0] && data[1]==sel[1] && data[2]==sel[2] && data[3]==sel[3];
}
rule probeSel(address target, bytes data, bytes4 sel) {
    env e;
    require sel == to_bytes4(0x095ea7b3);
    require bindSel(sel, data);
    bool m = h_selectorMapped(e.msg.sender, target, sel);
    checkCall@withrevert(e, target, 0, data);
    assert true;
}
