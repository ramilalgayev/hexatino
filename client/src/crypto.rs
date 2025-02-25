use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    Nonce, PublicKey, SalsaBox, SecretKey,
};
use sha2::{Digest, Sha256};
use base58::ToBase58;

use crate::error::{Error, Result};

pub const NONCE_SIZE: usize = 24;

#[derive(Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { public, secret }
    }
}

pub fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().to_base58()
}

pub async fn encrypt_message(
    message: &[u8],
    peer_public: &PublicKey,
    our_secret: &SecretKey,
) -> Result<Vec<u8>> {
    let cipher = SalsaBox::new(peer_public, our_secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message)?;
    let mut packet = nonce.as_slice().to_vec();
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

pub async fn decrypt_message(
    packet: &[u8],
    peer_public: &PublicKey,
    our_secret: &SecretKey,
) -> Result<Vec<u8>> {
    if packet.len() < NONCE_SIZE {
        return Err(Error::Crypto(crypto_box::aead::Error));
    }
    let (nonce_bytes, ciphertext) = packet.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = SalsaBox::new(peer_public, our_secret);
    cipher.decrypt(nonce, ciphertext).map_err(Into::into)
}