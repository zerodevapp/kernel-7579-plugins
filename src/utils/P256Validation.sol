// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {P256} from "solady/utils/P256.sol";

/// @notice Shared raw P-256 validation helpers for the validator and signer modules.
library P256Validation {
    uint256 internal constant P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 internal constant B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

    function isPrecompileAvailable() internal view returns (bool) {
        return P256.hasPrecompile();
    }

    function isValidPublicKey(uint256 x, uint256 y) internal pure returns (bool) {
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(addmod(mulmod(x, x, P), A, P), x, P), B, P);
        return x < P && y < P && lhs == rhs;
    }

    function decodePublicKey(bytes calldata data) internal pure returns (uint256 x, uint256 y, bool valid) {
        if (data.length != 64) return (0, 0, false);
        assembly ("memory-safe") {
            x := calldataload(data.offset)
            y := calldataload(add(data.offset, 0x20))
        }
        valid = isValidPublicKey(x, y);
    }

    function verify(bytes32 hash, bytes calldata signature, uint256 x, uint256 y) internal view returns (bool) {
        if (signature.length != 64 || !isValidPublicKey(x, y)) return false;

        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
        }
        return P256.verifySignature(hash, r, s, bytes32(x), bytes32(y));
    }
}
