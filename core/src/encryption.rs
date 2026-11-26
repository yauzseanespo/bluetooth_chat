use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 key-exchange pair for deriving a shared 256-bit AES-GCM session key.
pub struct KeyExchangePair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyExchangePair {
    /// Generate a fresh X25519 key pair using `OsRng`.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the 32-byte public key to send to the peer.
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Derive a 32-byte AES-256-GCM session key from the peer's 32-byte X25519 public key.
    pub fn derive_shared_key(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        let mut hasher = Sha256::new();
        hasher.update(b"bluetooth_chat_x25519_v1");
        hasher.update(shared.as_bytes());
        hasher.finalize().into()
    }
}

/// Generate a cryptographically secure random 256-bit (32-byte) AES-GCM key.
pub fn generate_key() -> [u8; 32] {
    Aes256Gcm::generate_key(OsRng).into()
}

/// Encrypt `plaintext` with AES-256-GCM using a fresh random 96-bit nonce.
/// Returns `(nonce, ciphertext_with_auth_tag)`.
pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` with AES-256-GCM and verify its authentication tag.
pub fn decrypt_message(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decryption failed: {e}"))
}
