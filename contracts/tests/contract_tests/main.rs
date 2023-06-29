pub mod utils;

use std::{collections::HashMap, error::Error};

use cryptoxide::x25519;
use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use ethers::prelude::*;
use dh_contracts::DH;
use dh_methods::{DH_ELF, DH_ID};
use risc0_zkvm::sha::Digest;
use crate::utils::bonsai_test;

#[tokio::test]
pub async fn test_successful_contract_usage() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let image_id = Digest::from(DH_ID);
    let registry = HashMap::from([(image_id, DH_ELF)]);

    bonsai_test(registry, |client, bonsai_mock_address| async move {
        let dh_contract =
            DH::deploy(client.clone(), (bonsai_mock_address, H256(image_id.into())))?
                .send()
                .await?;

        // Subscribe to events on the dh contract.
        let events = dh_contract.events();
        let mut subscription = events.subscribe().await?;

        let alice_secret = x25519::SecretKey::from([
            0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        // Always 32 length, still should remove unwrap
        let alice_public: [u8; 32] = x25519::base(&alice_secret).as_ref().try_into().unwrap();

        // Call a function which offloads work to Bonsai.
        dh_contract.send_key(alice_public).send().await?;

        // Wait for the callback to come from Bonsai.
        let callback_log = subscription.next().await.unwrap()?;

        let bob_public_stored = dh_contract.get_other_party_public().call().await?;
        let bob_public_stored: [u8; 32] = bob_public_stored.as_ref().try_into()?;
        let bob_public = x25519::PublicKey::from(bob_public_stored);

        let shared_secret = x25519::dh(&alice_secret, &bob_public);

        let key = Aes256Gcm::new(shared_secret.as_ref().into());

        // TODO: Figure out how to properly get the nonce here if sent back from the guest
        // let nonce = dh_contract.get_nonce().call().await?;
        // let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce.as_ref()[0..12]);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&[42; 12]);

        let ciphertext = dh_contract.get_cipher_text().call().await?;

        let decrypted_data = key
            .decrypt(&nonce, ciphertext.as_ref())
            .expect("Decryption failed");

        let decrypted_text = std::str::from_utf8(&decrypted_data).expect("Invalid UTF-8");

        assert_eq!(decrypted_text, "hello world!");
        Ok(())
    })
    .await
}
