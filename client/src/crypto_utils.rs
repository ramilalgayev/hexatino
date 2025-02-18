use crypto_box::{
    aead::{Aead, AeadCore, OsRng}, Nonce, PublicKey, SalsaBox, SecretKey
};
use sha2::{Sha256, Digest};
use base58::ToBase58;

// Do not change this, as XSalsa20Poly1305 requires it to be 24
pub const NONCE_SIZE: usize = 24;

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    // Generate a new keypair using secure randomness.
    pub fn new() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { public, secret }
    }
}

/// Compute a short fingerprint (first 8 bytes of SHA‑256) of the public key.
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    result.to_base58()
}

/// Encrypt a plaintext message.
/// A random nonce is generated, and the returned packet is: nonce || ciphertext.
pub async fn encrypt_message(
    message: &[u8],
    peer_public: &PublicKey,
    our_secret: &SecretKey,
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let cipher = SalsaBox::new(peer_public, our_secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message)?;
    // Prepend the nonce so the recipient can use it for decryption.
    let mut packet = nonce.as_slice().to_vec();
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

// Decrypt a received packet (nonce || ciphertext) into the original plaintext.
pub async fn decrypt_message(
    packet: &[u8],
    peer_public: &PublicKey,
    our_secret: &SecretKey,
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    if packet.len() < NONCE_SIZE {
        // The packet is too short to even contain the nonce.
        return Err(crypto_box::aead::Error);
    }
    let (nonce_bytes, ciphertext) = packet.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = SalsaBox::new(peer_public, our_secret);
    cipher.decrypt(&nonce, ciphertext)
}
