// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {CallerPolicy, Status} from "src/policies/CallerPolicy.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
    function store(address, bytes32, bytes32) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for CallerPolicy access semantics (TF-CallerPolicy).
/// @dev Storage-layout facts (CallerPolicy declares two mappings, no other state):
///        slot 0: mapping(bytes32 id => mapping(address account => Status)) status
///        slot 1: mapping(bytes32 id => mapping(address caller => mapping(address wallet => bool))) allowedCaller
///      We write SYMBOLIC values into these slots (via keccak-derived keys that mirror Solidity's
///      layout) so status can be any of NA/Live/Deprecated and allowedCaller any bool — otherwise the
///      etched (all-zero) storage would fix status==NA and the Live branches would be vacuous.
contract CallerPolicyHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    CallerPolicy internal policy;

    uint256 internal constant STATUS_SLOT = 0;
    uint256 internal constant ALLOWED_SLOT = 1;

    function setUp() external {
        // Halmos 0.3.3 cannot execute the via_ir creation bytecode (routes to unsupported
        // deployCode(string)); place runtime code directly. CallerPolicy has an empty constructor
        // (all state set later via onInstall / here via store), so etch is state-equivalent.
        policy = CallerPolicy(address(uint160(uint256(keccak256("CallerPolicy")))));
        vm.etch(address(policy), type(CallerPolicy).runtimeCode);
    }

    // mapping(bytes32 => mapping(address => Status)) : slot = keccak(account, keccak(id, base))
    function _statusSlot(bytes32 id, address account) internal pure returns (bytes32) {
        bytes32 inner = keccak256(abi.encode(id, STATUS_SLOT));
        return keccak256(abi.encode(account, inner));
    }

    // mapping(bytes32 => mapping(address => mapping(address => bool)))
    function _allowedSlot(bytes32 id, address caller, address wallet) internal pure returns (bytes32) {
        bytes32 l1 = keccak256(abi.encode(id, ALLOWED_SLOT));
        bytes32 l2 = keccak256(abi.encode(caller, l1));
        return keccak256(abi.encode(wallet, l2));
    }

    // ============================================================================================
    // (a) checkSignaturePolicy: return == 0  IFF  status[id][wallet]==Live && allowedCaller[id][sender][wallet]
    //     Two-directional equivalence read against storage directly (SPEC predicate, not impl re-run).
    // ============================================================================================

    /// @notice (a) checkSignaturePolicy returns 0 exactly when (Live && allowed), else 1.
    function check_CallerPolicy_signatureAccess(
        bytes32 id,
        address wallet,
        address sender,
        uint8 statusRaw,
        bool allowed,
        bytes32 hash
    ) external {
        vm.assume(statusRaw <= 2); // NA=0, Live=1, Deprecated=2

        // Seed symbolic storage. wallet is the ERC-1271 requester context => it is msg.sender.
        vm.store(address(policy), _statusSlot(id, wallet), bytes32(uint256(statusRaw)));
        vm.store(address(policy), _allowedSlot(id, sender, wallet), bytes32(uint256(allowed ? 1 : 0)));

        // SPEC predicate, read straight from storage — independent of the impl's control flow.
        bool live = statusRaw == uint8(Status.Live);
        bool expectSuccess = live && allowed;

        vm.prank(wallet);
        uint256 ret = policy.checkSignaturePolicy(id, sender, hash, hex"");

        if (expectSuccess) {
            assert(ret == 0);
        } else {
            assert(ret == 1);
        }
    }

    /// @notice (a) reachability: SUCCESS (Live && allowed) leaf is live.
    function check_CallerPolicy_signatureAccess_reachable(bytes32 id, address wallet, address sender, bytes32 hash)
        external
    {
        vm.store(address(policy), _statusSlot(id, wallet), bytes32(uint256(uint8(Status.Live))));
        vm.store(address(policy), _allowedSlot(id, sender, wallet), bytes32(uint256(1)));

        vm.prank(wallet);
        uint256 ret = policy.checkSignaturePolicy(id, sender, hash, hex"");
        // counterexample here proves the (Live && allowed) => 0 path is reachable (non-vacuous).
        assert(ret != 0);
    }

    /// @notice (a) reachability of failure mode #1: not-Live => 1 is live (Deprecated, allowed=true).
    function check_CallerPolicy_signatureAccess_notLive_reachable(
        bytes32 id,
        address wallet,
        address sender,
        bytes32 hash
    ) external {
        vm.store(address(policy), _statusSlot(id, wallet), bytes32(uint256(uint8(Status.Deprecated))));
        vm.store(address(policy), _allowedSlot(id, sender, wallet), bytes32(uint256(1)));

        vm.prank(wallet);
        uint256 ret = policy.checkSignaturePolicy(id, sender, hash, hex"");
        assert(ret != 1); // counterexample => not-Live rejection path is reachable
    }

    /// @notice (a) reachability of failure mode #2: Live-but-not-allowed => 1 is live.
    function check_CallerPolicy_signatureAccess_notAllowed_reachable(
        bytes32 id,
        address wallet,
        address sender,
        bytes32 hash
    ) external {
        vm.store(address(policy), _statusSlot(id, wallet), bytes32(uint256(uint8(Status.Live))));
        vm.store(address(policy), _allowedSlot(id, sender, wallet), bytes32(uint256(0)));

        vm.prank(wallet);
        uint256 ret = policy.checkSignaturePolicy(id, sender, hash, hex"");
        assert(ret != 1); // counterexample => Live-but-not-allowed rejection path is reachable
    }

    // ============================================================================================
    // (b) checkUserOpPolicy: return == 0  IFF  status[id][msg.sender]==Live, else 1.
    // ============================================================================================

    /// @notice (b) checkUserOpPolicy returns 0 exactly when status[id][msg.sender]==Live, else 1.
    function check_CallerPolicy_userOpAccess(bytes32 id, address account, uint8 statusRaw) external {
        vm.assume(statusRaw <= 2);
        vm.store(address(policy), _statusSlot(id, account), bytes32(uint256(statusRaw)));

        bool expectSuccess = statusRaw == uint8(Status.Live); // SPEC predicate from storage

        // PackedUserOperation content is irrelevant (checkUserOpPolicy ignores it); pass a zeroed op.
        PackedUserOperation memory op;
        vm.prank(account);
        uint256 ret = policy.checkUserOpPolicy(id, op);

        if (expectSuccess) {
            assert(ret == SIG_VALIDATION_SUCCESS_UINT);
        } else {
            assert(ret == SIG_VALIDATION_FAILED_UINT);
        }
    }

    /// @notice (b) reachability: SUCCESS (Live) leaf is live.
    function check_CallerPolicy_userOpAccess_reachable(bytes32 id, address account) external {
        vm.store(address(policy), _statusSlot(id, account), bytes32(uint256(uint8(Status.Live))));
        PackedUserOperation memory op;
        vm.prank(account);
        uint256 ret = policy.checkUserOpPolicy(id, op);
        assert(ret != SIG_VALIDATION_SUCCESS_UINT); // counterexample => Live-success path reachable
    }

    /// @notice (b) reachability of failure mode: not-Live => 1 is live (NA).
    function check_CallerPolicy_userOpAccess_notLive_reachable(bytes32 id, address account) external {
        vm.store(address(policy), _statusSlot(id, account), bytes32(uint256(uint8(Status.NA))));
        PackedUserOperation memory op;
        vm.prank(account);
        uint256 ret = policy.checkUserOpPolicy(id, op);
        assert(ret != SIG_VALIDATION_FAILED_UINT); // counterexample => not-Live rejection path reachable
    }

    // ============================================================================================
    // (c) validateSignatureWithDataWithSender(sender,...): return == true IFF sender ∈ decoded address[].
    //     Bounded list length <= 3.
    // ============================================================================================

    /// @notice (c) stateless membership: true IFF sender is a member of the decoded allowlist (len<=3).
    /// @dev The impl does `abi.decode(data,(address[]))`; a SYMBOLIC array length makes the internal
    ///      CALLDATACOPY size symbolic (Halmos NotConcreteError). We therefore branch on a symbolic
    ///      `len` into CONCRETELY-sized arrays so the decode size is concrete on every path, while still
    ///      covering all lengths 0..3. Halmos explores every branch => full bounded coverage.
    function check_CallerPolicy_statelessMembership(uint256 len, address sender, address a0, address a1, address a2)
        external
        view
    {
        vm.assume(len <= 3);

        // Build a CONCRETELY-sized array per branch so the impl's abi.decode CALLDATACOPY size stays
        // concrete (symbolic-size allocation triggers Halmos NotConcreteError). All lengths 0..3 covered.
        address[] memory list;
        if (len == 0) {
            list = new address[](0);
        } else if (len == 1) {
            list = new address[](1);
            list[0] = a0;
        } else if (len == 2) {
            list = new address[](2);
            list[0] = a0;
            list[1] = a1;
        } else {
            list = new address[](3);
            list[0] = a0;
            list[1] = a1;
            list[2] = a2;
        }
        bytes memory data = abi.encode(list);

        // SPEC membership predicate computed independently of the impl loop.
        bool expectMember = (len > 0 && a0 == sender) || (len > 1 && a1 == sender) || (len > 2 && a2 == sender);

        bool ret = policy.validateSignatureWithDataWithSender(sender, bytes32(0), hex"", data);

        assert(ret == expectMember);
    }

    /// @notice (c) reachability: membership==true is live (len==1, a0==sender).
    function check_CallerPolicy_statelessMembership_true_reachable(address sender) external view {
        address[] memory list = new address[](1);
        list[0] = sender;
        bool ret = policy.validateSignatureWithDataWithSender(sender, bytes32(0), hex"", abi.encode(list));
        assert(!ret); // counterexample => membership-true path reachable
    }

    /// @notice (c) reachability: membership==false is live (empty list).
    function check_CallerPolicy_statelessMembership_false_reachable(address sender) external view {
        address[] memory list = new address[](0);
        bool ret = policy.validateSignatureWithDataWithSender(sender, bytes32(0), hex"", abi.encode(list));
        assert(ret); // counterexample => membership-false path reachable
    }
}
