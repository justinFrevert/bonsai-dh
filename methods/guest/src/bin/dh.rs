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

#![no_main]
#![no_std]

use ethabi::Token;
use risc0_zkvm::guest::env;
use risc0_zkvm_platform::syscall::nr::SYS_RANDOM;
use cryptoxide::x25519::{base, dh, PublicKey, SecretKey};
use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
extern crate alloc;
use alloc::vec;

risc0_zkvm::guest::entry!(main);

// const INPUT_LEN: usize = core::mem::size_of::<U256>();
const INPUT_LEN: usize = 64;

// Wrap a SYS_RANDOM Risc0 ZKVM call to get random bytes
fn syscall_random() -> [u8; 32] {
    let mut rand_bytes = [0_u32; 32];
    // Try to get randomness from syscall TODO: check if this is appropriate
    env::syscall(SYS_RANDOM, &[], rand_bytes.as_mut_slice());

    // Adjust from u32s to u8s
    let mut random_bytes_adjusted = vec![];
    for val in &rand_bytes {
        random_bytes_adjusted.extend_from_slice(&val.to_be_bytes());
    }

    random_bytes_adjusted[0..32].try_into().expect("Length should not be over 32")
}

fn generate_keypair_x25519() -> (SecretKey, PublicKey) {
    // Curve25519 can accept random 32 bit string as a key, though this is not a proper way to do it
    let random_bytes = syscall_random();
    let secret_key = SecretKey::from(random_bytes);
    let public_key = base(&secret_key);

    (secret_key, public_key)
}

pub fn main() {
    // NOTE: Reads must be of known length. https://github.com/risc0/risc0/issues/402
    let mut input_bytes = [0u8; INPUT_LEN];
    env::read_slice(&mut input_bytes);

    let pub_key_input_bytes: [u8;32]  = input_bytes[0..32].try_into().unwrap();

    let other_public = PublicKey::try_from(pub_key_input_bytes).expect("Input bytes shouldn't exceed the max expected length");

    let nonce_number = ethabi::decode(&[ethabi::ParamType::Uint(256)], &input_bytes[32..])
        // TODO: remove panic
        .expect("Input bytes shouldn't exceed the max expected length");

    // Nonce accepts 12 at max. That means that the nonce can only increase up to a certain size
    let nonce = Nonce::<Aes256Gcm>::from_slice(&input_bytes[52..64]);

    let (ephemeral_secret, ephemeral_public) = generate_keypair_x25519();

    // Create shared secret using diffie-helman
    let shared_secret = dh(&ephemeral_secret, &other_public);

    // Encrypt and decrypt using the shared secret as the key
    let key = Aes256Gcm::new(shared_secret.as_ref().into());

    // Get some data or result of a computation to use as the private message
    let plaintext = b"hello world!";

    // TODO: Look into whether this may have a max
    let ciphertext = key
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // Commit to the journal the ciphertext, the public key needed to construct the other secret, and the expected nonce
    env::commit_slice(&ethabi::encode(
        &[
        Token::Bytes(ciphertext),
        Token::Bytes(ephemeral_public.as_ref().to_vec()),
        nonce_number.get(0).expect("Nonce should exist").clone()
    ]));
}
