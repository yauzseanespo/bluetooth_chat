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

    #[test]
    fn x25519_key_exchange_and_aes_gcm_roundtrip() {
        use super::super::encryption::{decrypt_message, encrypt_message, KeyExchangePair};

        let alice = KeyExchangePair::generate();
        let bob = KeyExchangePair::generate();
        let eve = KeyExchangePair::generate();

        let alice_shared = alice.derive_shared_key(&bob.public_bytes());
        let bob_shared = bob.derive_shared_key(&alice.public_bytes());
        let eve_shared = eve.derive_shared_key(&alice.public_bytes());

        assert_eq!(alice_shared, bob_shared);
        assert_ne!(alice_shared, eve_shared);

        let msg = b"End-to-end X25519 + AES-256-GCM message";
        let (nonce, ciphertext) = encrypt_message(&alice_shared, msg).expect("encrypt");
        let decrypted = decrypt_message(&bob_shared, &nonce, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn mtu_chunking_and_reassembly() {
        use super::super::framing::{chunk_message, FrameAssembler};

        let payload = b"Uzun bir Bluetooth sohbet mesaji - 20 byte MTU parcalama testi!";
        let chunks = chunk_message(payload, 20).expect("chunk");
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|c| c.len() <= 20));

        // Reassemble out of order (reverse) to verify sequence handling
        let mut assembler = FrameAssembler::new();
        let mut reassembled = None;
        for chunk in chunks.iter().rev() {
            reassembled = assembler.push_chunk(chunk).expect("push");
        }
        assert_eq!(reassembled.expect("complete"), payload);

        // Invalid MTU and short frame checks
        assert!(chunk_message(payload, 5).is_err());
        assert!(assembler.push_chunk(&[0, 1]).is_err());
    }

    #[cfg(all(target_os = "windows", any(feature = "btle", feature = "classic")))]
    #[test]
    fn windows_ble_peripheral_basics() {
        use super::super::windows_ble_peripheral::WindowsBlePeripheral;

        let peripheral = WindowsBlePeripheral::new();
        assert!(!peripheral.is_advertising());
        assert!(peripheral.take_received().is_empty());

        // Notifying before starting GATT service provider should fail cleanly
        let err = peripheral.notify(b"hello").unwrap_err();
        assert!(err.contains("not started"));
    }
}
