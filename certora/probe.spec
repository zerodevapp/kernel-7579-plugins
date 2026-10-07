methods {
    function threshold() external returns (uint24) envfree;
}
rule retValueCheck() {
    env e;
    require e.msg.value == 0;
    require threshold() == 0;
    bytes4 ret = isValidSignatureWithSender(e, 2);
    assert ret == to_bytes4(0xffffffff), "unexpected ret on threshold==0";
}
