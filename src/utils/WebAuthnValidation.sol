// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Base64} from "solady/utils/Base64.sol";
import {P256} from "solady/utils/P256.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

/// @notice Compatibility and backend wrapper for the WebAuthn signer and validator modules.
library WebAuthnValidation {
    address internal constant DAIMO_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    uint256 internal constant CHALLENGE_LOCATION = 23;
    // An unpadded Base64URL encoding of a bytes32 challenge is always 43 bytes.
    uint256 internal constant ENCODED_CHALLENGE_LENGTH = 43;
    uint256 internal constant P256_N_DIV_2 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    string internal constant RESPONSE_TYPE = '"type":"webauthn.get"';
    string internal constant CHALLENGE_PREFIX = '"challenge":"';

    function verify(
        bytes32 hash,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 responseTypeLocation,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        bytes memory clientData = bytes(clientDataJSON);
        if (!_indicesAreSafe(clientData.length, responseTypeLocation)) return false;

        bytes memory challenge = abi.encodePacked(hash);
        bool isValid = WebAuthn.verify(
            challenge,
            true,
            authenticatorData,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            bytes32(r),
            bytes32(s),
            bytes32(x),
            bytes32(y)
        );
        if (isValid || P256.hasPrecompileOrVerifier()) return isValid;

        // With both Solady backends absent, repeat its non-cryptographic checks before trusting
        // the Daimo verifier's P-256-only result.
        bytes memory encodedChallenge = bytes(Base64.encode(challenge, true, true));
        if (!_hasValidAssertionFields(authenticatorData, clientData, responseTypeLocation, encodedChallenge)) {
            return false;
        }

        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(clientData)));
        return _verifyDaimo(messageHash, r, s, x, y);
    }

    function _indicesAreSafe(uint256 clientDataLength, uint256 responseTypeLocation) private pure returns (bool) {
        uint256 responseTypeLength = bytes(RESPONSE_TYPE).length;
        uint256 challengeFieldLength = bytes(CHALLENGE_PREFIX).length + ENCODED_CHALLENGE_LENGTH;

        // Prove both indexed reads are in bounds before Solady evaluates its Yul expressions.
        if (clientDataLength < responseTypeLength || responseTypeLocation > clientDataLength - responseTypeLength) {
            return false;
        }
        if (clientDataLength <= challengeFieldLength) return false;
        return CHALLENGE_LOCATION <= clientDataLength - challengeFieldLength - 1;
    }

    function _hasValidAssertionFields(
        bytes memory authenticatorData,
        bytes memory clientData,
        uint256 responseTypeLocation,
        bytes memory encodedChallenge
    ) private pure returns (bool) {
        if (authenticatorData.length <= 32 || uint8(authenticatorData[32]) & 0x05 != 0x05) return false;
        if (!_matchesAt(clientData, responseTypeLocation, bytes(RESPONSE_TYPE))) return false;

        bytes memory challengeField = abi.encodePacked(CHALLENGE_PREFIX, encodedChallenge);
        if (!_matchesAt(clientData, CHALLENGE_LOCATION, challengeField)) return false;
        return clientData[CHALLENGE_LOCATION + challengeField.length] == 0x22;
    }

    function _matchesAt(bytes memory input, uint256 location, bytes memory expected) private pure returns (bool) {
        if (location > input.length || expected.length > input.length - location) return false;
        for (uint256 i; i < expected.length; ++i) {
            if (input[location + i] != expected[i]) return false;
        }
        return true;
    }

    function _verifyDaimo(bytes32 messageHash, uint256 r, uint256 s, uint256 x, uint256 y) private view returns (bool) {
        if (s > P256_N_DIV_2) return false;

        (bool success, bytes memory result) = DAIMO_VERIFIER.staticcall(abi.encode(messageHash, r, s, x, y));
        if (!success || result.length != 32) return false;

        uint256 verificationResult;
        assembly ("memory-safe") {
            verificationResult := mload(add(result, 0x20))
        }
        return verificationResult == 1;
    }
}
