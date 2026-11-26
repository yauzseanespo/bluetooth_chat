/// Generate a deterministic 32‑byte key (for demo purposes).
/// In a real app you would use a secure RNG and store the key safely.
pub fn generate_key() -> [u8; 32] {
    // Simple pattern – not secure!
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = (i as u8).wrapping_mul(7);
    }
    key
}

/// Very simple XOR “encryption”. Returns (nonce, ciphertext).
/// The nonce is just a random‑looking 12‑byte array generated from the key.
pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Derive a pseudo‑nonce from the key (first 12 bytes XORed with length).
    let mut nonce = key[0..12].to_vec();
    let len = plaintext.len() as u8;
    for b in &mut nonce { *b ^= len; }
    let ciphertext: Vec<u8> = plaintext.iter().zip(nonce.iter().cycle()).map(|(p, n)| p ^ n).collect();
    Ok((nonce, ciphertext))
}

/// Decrypt the XOR ciphertext using the same nonce.
pub fn decrypt_message(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    // Re‑derive the same pseudo‑nonce (should match the passed one).
    let expected_nonce: Vec<u8> = key[0..12].iter().map(|b| b ^ (ciphertext.len() as u8)).collect();
    if expected_nonce != nonce {
        return Err("Invalid nonce".to_string());
    }
    let plaintext: Vec<u8> = ciphertext.iter().zip(nonce.iter().cycle()).map(|(c, n)| c ^ n).collect();
    Ok(plaintext)
}
