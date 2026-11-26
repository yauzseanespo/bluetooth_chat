use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

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
