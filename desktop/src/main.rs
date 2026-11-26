#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use bluetooth_core::bluetooth::{BluetoothAdapter, BluetoothDevice, MockAdapter};
use bluetooth_core::encryption::{decrypt_message, encrypt_message, generate_key};
#[cfg(target_os = "windows")]
use bluetooth_core::windows_ble::WindowsBleAdapter;

struct AppState {
    real_adapter: Arc<dyn BluetoothAdapter + Send + Sync>,
    mock_adapter: Arc<MockAdapter>,
    session_key: Mutex<[u8; 32]>,
}

impl AppState {
    fn adapter(&self, use_mock: bool) -> &dyn BluetoothAdapter {
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

fn hex_to_key(hex: &str) -> Result<[u8; 32], String> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err("Key must be 64 hex characters (32 bytes)".to_string());
    }
    let mut key = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in key".to_string())?;
        key[i] = u8::from_str_radix(s, 16).map_err(|_| format!("Invalid hex byte '{s}'"))?;
    }
    Ok(key)
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
    let parsed = hex_to_key(&hex_key)?;
    let mut key = state
        .session_key
        .lock()
        .map_err(|_| "Session key lock poisoned".to_string())?;
    *key = parsed;
    Ok(())
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
    if encrypted {
        let key = {
            *state
                .session_key
                .lock()
                .map_err(|_| "Session key lock poisoned".to_string())?
        };
        let (nonce, ciphertext) = encrypt_message(&key, message.as_bytes())?;
        let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        state.adapter(use_mock).send(&payload).await
    } else {
        state.adapter(use_mock).send(message.as_bytes()).await
    }
}

#[tauri::command]
async fn receive_messages(
    encrypted: bool,
    use_mock: bool,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let bytes = state.adapter(use_mock).receive().await?;
    if bytes.is_empty() {
        return Ok(String::new());
    }
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
        session_key: Mutex::new(generate_key()),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_session_key,
            set_session_key,
            discover_devices,
            connect_device,
            send_message,
            receive_messages
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
        assert_eq!(hex_to_key(&hex).unwrap(), key);

        assert!(hex_to_key("abcd").is_err());
        assert!(hex_to_key(&"zz".repeat(32)).is_err());
    }
}
