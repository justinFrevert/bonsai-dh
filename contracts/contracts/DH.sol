// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.16;

import {IBonsaiProxy} from "./IBonsaiProxy.sol";
import {BonsaiApp} from "./BonsaiApp.sol";

/// @title A starter application using Bonsai through the on-chain proxy.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
//       or difficult to implement function to a RISC Zero guest running on Bonsai.
contract DH is BonsaiApp {
    // We will receive the other party's key for deciphering the text offchain
    bytes otherPartyPublic;
    // Store the cipherText encrypted with the shared key.
    bytes cipherText;
    // The ciphertext is stored encrypted with a nonce
    bytes nonce;

    // Initialize the contract, binding it to a specified Bonsai proxy and RISC Zero guest image.
    constructor(IBonsaiProxy _bonsai_proxy, bytes32 _image_id)
        BonsaiApp(_bonsai_proxy, _image_id)
    {}

    event CalculateFibonacciCallback(bytes n, bytes result);

    // Send the user's key to the ZKVM. Note: this doesn't prove ownership of the key. 
    // In real applications, a message signed by this given key with enough information to prove ownership would need to be verified here or even in the guest
    function sendKey(bytes32 x25519PubKey) external {
        submit_bonsai_request(abi.encode(x25519PubKey));
    }

    function bonsai_callback(bytes memory journal) internal override {
        (bytes memory _cipherText, bytes memory _otherPartyPublic, bytes memory _nonce) = abi.decode(
            journal,
            (bytes, bytes, bytes)
        );

        // Store the values needed for deciphering the secret message: the message itself, and the other party's key to form the shared secret
        cipherText = _cipherText;
        otherPartyPublic = _otherPartyPublic;
        nonce = _nonce;

        emit CalculateFibonacciCallback(_cipherText, _otherPartyPublic);
    }

    // Get other parties key for current private message
    function getOtherPartyPublic() public view returns (bytes memory) {
        return otherPartyPublic;
    }

    // Get the current private message stored as ciphertext
    function getCipherText() public view returns (bytes memory) {
        return cipherText;
    }

    // Get a nonce used for decryption of the ciphertext
    function getNonce() public view returns (bytes memory) {
        return cipherText;
    }
}
