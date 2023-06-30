pub mod utils;

use std::{collections::HashMap, error::Error};

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use cryptoxide::x25519;
use dh_contracts::DH;
use dh_methods::{DH_ELF, DH_ID};
use ethers::prelude::*;
use risc0_zkvm::sha::Digest;

use crate::utils::bonsai_test;

fn to_x25519_helper(public_bytes: ethers::types::Bytes) -> x25519::PublicKey {
    let public_bytes: [u8; 32] = public_bytes.as_ref().try_into().unwrap();
    x25519::PublicKey::from(public_bytes)
}

#[tokio::test]
pub async fn test_successful_contract_usage() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let image_id = Digest::from(DH_ID);
    let registry = HashMap::from([(image_id, DH_ELF)]);

    bonsai_test(registry, |client, bonsai_mock_address| async move {
        let dh_contract = DH::deploy(client.clone(), (bonsai_mock_address, H256(image_id.into())))?
            .send()
            .await?;

        // Subscribe to events on the dh contract.
        let events = dh_contract.events();
        let mut subscription = events.subscribe().await?;

        // Just some key to represent Alice
        let alice_secret = x25519::SecretKey::from([
            0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        // Always 32 length, still should remove unwrap
        let alice_public: [u8; 32] = x25519::base(&alice_secret).as_ref().try_into().unwrap();

        let nonce_initial = dh_contract.get_nonce().call().await?;

        // Nonce inital state
        assert_eq!(nonce_initial, U256::from(0));

        // Call a function which offloads work to Bonsai.
        dh_contract.send_key(alice_public).send().await?;

        // Wait for the callback to come from Bonsai.
        let _callback_log = subscription.next().await.unwrap()?;

        // Alice stores bob's keys as part of the exchange to use offchain
        let bob_public_stored = dh_contract.get_other_party_public().call().await?;
        let bob_public = to_x25519_helper(bob_public_stored);

        // The shared secret is created from combining alice's secret and bob's public
        let shared_secret = x25519::dh(&alice_secret, &bob_public);
        let key = Aes256Gcm::new(shared_secret.as_ref().into());
        let ciphertext = dh_contract.get_cipher_text().call().await?;

        // Recreate incremented nonce for decryption
        let nonce = Nonce::<Aes256Gcm>::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        // Alice decrypts the given ciphertext with the shared secret
        let decrypted_data = key
            .decrypt(&nonce, ciphertext.as_ref())
            .expect("Decryption failed");

        let decrypted_text = std::str::from_utf8(&decrypted_data).expect("Invalid UTF-8");

        // The decrypted plaintext equals the hidden plaintext
        assert_eq!(decrypted_text, "hello world!");

        let nonce_incremented = dh_contract.get_nonce().call().await?;

        // Nonce was incremented
        assert_eq!(nonce_incremented, U256::from(1));
        Ok(())
    })
    .await
}
