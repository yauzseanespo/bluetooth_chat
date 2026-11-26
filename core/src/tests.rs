#[cfg(test)]
mod tests {
    use super::super::bluetooth::{BluetoothAdapter, MockAdapter};
    use super::super::encryption::{generate_key, encrypt_message, decrypt_message};
    use tokio::runtime::Runtime;

    #[test]
    fn mock_adapter_flow() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = MockAdapter::new();
            // Discover
            let devices = adapter.discover().await;
            assert_eq!(devices.len(), 1);
            let device = &devices[0];
            // Connect
            assert!(adapter.connect(device).await.is_ok());
            // Prepare message and encrypt
            let key = generate_key();
            let plaintext = b"Hello Bluetooth";
            let (nonce, ciphertext) = encrypt_message(&key, plaintext).expect("encryption");
            // Send encrypted data
            assert!(adapter.send(&ciphertext).await.is_ok());
            // Receive (should be same ciphertext)
            let recv = adapter.receive().await.expect("receive");
            assert_eq!(recv, ciphertext);
            // Decrypt
            let decrypted = decrypt_message(&key, &nonce, &recv).expect("decryption");
            assert_eq!(decrypted, plaintext);
        });
    }
}
