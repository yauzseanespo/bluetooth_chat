#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use bluetooth_core::bluetooth::{BluetoothAdapter, BluetoothDevice, MockAdapter};
use bluetooth_core::encryption::{decrypt_message, encrypt_message, generate_key, KeyExchangePair};
use bluetooth_core::framing::{chunk_message, FrameAssembler};
#[cfg(target_os = "windows")]
use bluetooth_core::windows_ble::WindowsBleAdapter;
#[cfg(target_os = "windows")]
use bluetooth_core::windows_ble_peripheral::WindowsBlePeripheral;

const DEFAULT_BLE_MTU: usize = 20;

struct AppState {
    real_adapter: Arc<dyn BluetoothAdapter + Send + Sync>,
    mock_adapter: Arc<MockAdapter>,
    #[cfg(target_os = "windows")]
    peripheral: WindowsBlePeripheral,
    session_key: Mutex<[u8; 32]>,
    kx_pair: Mutex<KeyExchangePair>,
    assembler: Mutex<FrameAssembler>,
}

impl AppState {
    fn adapter(&self, use_mock: bool) -> &(dyn BluetoothAdapter + Send + Sync) {
        if use_mock {
            self.mock_adapter.as_ref()
        } else {
            self.real_adapter.as_ref()
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], String> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err("Key must be 64 hex characters (32 bytes)".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in hex string".to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| format!("Invalid hex byte '{s}'"))?;
    }
    Ok(out)
}

fn reassemble_stream(assembler: &mut FrameAssembler, raw: &[u8], mtu: usize) -> Result<Option<Vec<u8>>, String> {
    let mut completed = None;
    for chunk in raw.chunks(mtu) {
        if let Some(msg) = assembler.push_chunk(chunk)? {
            completed = Some(msg);
        }
    }
    Ok(completed)
}

#[tauri::command]
fn get_session_key(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let key = state
        .session_key
        .lock()
        .map_err(|_| "Session key lock poisoned".to_string())?;
    Ok(bytes_to_hex(&*key))
}

#[tauri::command]
fn set_session_key(hex_key: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let parsed = hex_to_bytes32(&hex_key)?;
    let mut key = state
        .session_key
        .lock()
        .map_err(|_| "Session key lock poisoned".to_string())?;
    *key = parsed;
    Ok(())
}

#[tauri::command]
fn get_public_key(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let kx = state
        .kx_pair
        .lock()
        .map_err(|_| "Key exchange lock poisoned".to_string())?;
    Ok(bytes_to_hex(&kx.public_bytes()))
}

#[tauri::command]
fn complete_key_exchange(
    peer_public_hex: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let peer_pub = hex_to_bytes32(&peer_public_hex)?;
    let shared = {
        let kx = state
            .kx_pair
            .lock()
            .map_err(|_| "Key exchange lock poisoned".to_string())?;
        kx.derive_shared_key(&peer_pub)
    };
    let mut key = state
        .session_key
        .lock()
        .map_err(|_| "Session key lock poisoned".to_string())?;
    *key = shared;
    Ok(bytes_to_hex(&shared))
}

#[tauri::command]
async fn discover_devices(
    use_mock: bool,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<BluetoothDevice>, String> {
    Ok(state.adapter(use_mock).discover().await)
}

#[tauri::command]
async fn connect_device(
    device: BluetoothDevice,
    use_mock: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.adapter(use_mock).connect(&device).await
}

#[tauri::command]
async fn send_message(
    message: String,
    encrypted: bool,
    use_mock: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let payload = if encrypted {
        let key = {
            *state
                .session_key
                .lock()
                .map_err(|_| "Session key lock poisoned".to_string())?
        };
        let (nonce, ciphertext) = encrypt_message(&key, message.as_bytes())?;
        let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);
        buf
    } else {
        message.into_bytes()
    };

    let frames = chunk_message(&payload, DEFAULT_BLE_MTU)?;
    let adapter = state.adapter(use_mock);
    for frame in frames {
        adapter.send(&frame).await?;
    }
    Ok(())
}

#[tauri::command]
async fn receive_messages(
    encrypted: bool,
    use_mock: bool,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let raw = state.adapter(use_mock).receive().await?;
    if raw.is_empty() {
        return Ok(String::new());
    }

    let assembled = {
        let mut assembler = state
            .assembler
            .lock()
            .map_err(|_| "Assembler lock poisoned".to_string())?;
        reassemble_stream(&mut assembler, &raw, DEFAULT_BLE_MTU)?
    };

    let Some(bytes) = assembled else {
        return Ok(String::new());
    };

    if encrypted {
        if bytes.len() < 12 {
            return Err("Received payload too short for AES-GCM nonce".to_string());
        }
        let key = {
            *state
                .session_key
                .lock()
                .map_err(|_| "Session key lock poisoned".to_string())?
        };
        let (nonce, ciphertext) = bytes.split_at(12);
        let plaintext = decrypt_message(&key, nonce, ciphertext)?;
        Ok(String::from_utf8_lossy(&plaintext).to_string())
    } else {
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[tauri::command]
fn start_peripheral(state: tauri::State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        state.peripheral.start()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = state;
        Err("BLE Peripheral mode is only supported on Windows".to_string())
    }
}

#[tauri::command]
fn stop_peripheral(state: tauri::State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        state.peripheral.stop()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = state;
        Ok(())
    }
}

#[tauri::command]
fn is_peripheral_advertising(state: tauri::State<'_, AppState>) -> bool {
    #[cfg(target_os = "windows")]
    {
        state.peripheral.is_advertising()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = state;
        false
    }
}

fn create_real_adapter() -> Arc<dyn BluetoothAdapter + Send + Sync> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsBleAdapter::new())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Arc::new(MockAdapter::new())
    }
}

fn main() {
    let state = AppState {
        real_adapter: create_real_adapter(),
        mock_adapter: Arc::new(MockAdapter::new()),
        #[cfg(target_os = "windows")]
        peripheral: WindowsBlePeripheral::new(),
        session_key: Mutex::new(generate_key()),
        kx_pair: Mutex::new(KeyExchangePair::generate()),
        assembler: Mutex::new(FrameAssembler::new()),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_session_key,
            set_session_key,
            get_public_key,
            complete_key_exchange,
            discover_devices,
            connect_device,
            send_message,
            receive_messages,
            start_peripheral,
            stop_peripheral,
            is_peripheral_advertising
        ])
        .run(tauri::generate_context!())
        .expect("failed to run tauri app");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_key_roundtrip_and_validation() {
        let key = generate_key();
        let hex = bytes_to_hex(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex_to_bytes32(&hex).unwrap(), key);

        assert!(hex_to_bytes32("abcd").is_err());
        assert!(hex_to_bytes32(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn desktop_x25519_chunked_encrypted_roundtrip() {
        let alice_kx = KeyExchangePair::generate();
        let bob_kx = KeyExchangePair::generate();

        let alice_key = alice_kx.derive_shared_key(&bob_kx.public_bytes());
        let bob_key = bob_kx.derive_shared_key(&alice_kx.public_bytes());
        assert_eq!(alice_key, bob_key);

        let message = "Desktop Tauri MTU + X25519 + AES-256-GCM test mesaji!";
        let (nonce, ciphertext) = encrypt_message(&alice_key, message.as_bytes()).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        let chunks = chunk_message(&payload, DEFAULT_BLE_MTU).unwrap();
        let raw: Vec<u8> = chunks.into_iter().flatten().collect();

        let mut assembler = FrameAssembler::new();
        let assembled = reassemble_stream(&mut assembler, &raw, DEFAULT_BLE_MTU)
            .unwrap()
            .expect("complete frame");

        let (r_nonce, r_cipher) = assembled.split_at(12);
        let decrypted = decrypt_message(&bob_key, r_nonce, r_cipher).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), message);
    }
}
