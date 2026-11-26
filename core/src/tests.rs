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

    #[cfg(all(target_os = "windows", any(feature = "btle", feature = "classic")))]
    #[test]
    fn windows_ble_adapter_basics() {
        use super::super::bluetooth::BluetoothDevice;
        use super::super::windows_ble::WindowsBleAdapter;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = WindowsBleAdapter::new();

            // Sending before connecting should fail cleanly
            let err = adapter.send(b"ping").await.unwrap_err();
            assert!(err.contains("Not connected"));

            // Receiving with empty buffer should return empty Vec
            let empty = adapter.receive().await.unwrap();
            assert!(empty.is_empty());

            // Connecting with invalid address should return parse error
            let invalid = BluetoothDevice {
                name: "Bad".into(),
                address: "invalid-mac".into(),
            };
            let conn_err = adapter.connect(&invalid).await.unwrap_err();
            assert!(conn_err.contains("Invalid Bluetooth address"));
        });
    }

    #[test]
    fn aes_gcm_encryption_validation() {
        use super::super::encryption::{decrypt_message, encrypt_message, generate_key};

        let key = generate_key();
        let wrong_key = generate_key();
        assert_ne!(key, wrong_key);

        let plaintext = b"Secret Bluetooth payload";
        let (nonce, mut ciphertext) = encrypt_message(&key, plaintext).expect("encrypt");
        assert_eq!(nonce.len(), 12);
        assert_ne!(ciphertext, plaintext);

        // Wrong key must fail authentication
        assert!(decrypt_message(&wrong_key, &nonce, &ciphertext).is_err());

        // Invalid nonce length must fail
        assert!(decrypt_message(&key, &[0u8; 8], &ciphertext).is_err());

        // Tampered ciphertext must fail authentication
        ciphertext[0] ^= 0xFF;
        assert!(decrypt_message(&key, &nonce, &ciphertext).is_err());
    }
}
