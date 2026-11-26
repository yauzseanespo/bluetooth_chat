use std::sync::{Arc, Mutex, OnceLock};

use bluetooth_core::bluetooth::{BluetoothAdapter, BluetoothDevice, MockAdapter};
use bluetooth_core::encryption::{decrypt_message, encrypt_message, generate_key};
#[cfg(target_os = "windows")]
use bluetooth_core::windows_ble::WindowsBleAdapter;
use flutter_rust_bridge::StreamSink;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

/// Serializable device model exposed across the Flutter FFI bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeDevice {
    pub name: String,
    pub address: String,
}

impl From<BluetoothDevice> for BridgeDevice {
    fn from(d: BluetoothDevice) -> Self {
        Self {
            name: d.name,
            address: d.address,
        }
    }
}

impl From<BridgeDevice> for BluetoothDevice {
    fn from(d: BridgeDevice) -> Self {
        Self {
            name: d.name,
            address: d.address,
        }
    }
}

struct BridgeState {
    runtime: Runtime,
    real_adapter: Arc<dyn BluetoothAdapter + Send + Sync>,
    mock_adapter: Arc<MockAdapter>,
    stream_sink: Mutex<Option<StreamSink<String>>>,
}

impl BridgeState {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime for mobile_bridge");

        #[cfg(target_os = "windows")]
        let real_adapter: Arc<dyn BluetoothAdapter + Send + Sync> =
            Arc::new(WindowsBleAdapter::new());
        #[cfg(not(target_os = "windows"))]
        let real_adapter: Arc<dyn BluetoothAdapter + Send + Sync> = Arc::new(MockAdapter::new());

        Self {
            runtime,
            real_adapter,
            mock_adapter: Arc::new(MockAdapter::new()),
            stream_sink: Mutex::new(None),
        }
    }

    fn adapter(&self, use_mock: bool) -> &dyn BluetoothAdapter {
        if use_mock {
            self.mock_adapter.as_ref()
        } else {
            self.real_adapter.as_ref()
        }
    }
}

static BRIDGE_STATE: OnceLock<BridgeState> = OnceLock::new();

fn state() -> &'static BridgeState {
    BRIDGE_STATE.get_or_init(BridgeState::new)
}

#[no_mangle]
pub extern "C" fn hello() -> i32 {
    let _ = state();
    42
}

/// Registers a Flutter `StreamSink` to receive incoming chat messages.
pub fn init_bridge(sink: StreamSink<String>, use_mock: bool) -> Result<(), String> {
    let st = state();
    let mut guard = st
        .stream_sink
        .lock()
        .map_err(|_| "Stream sink mutex poisoned".to_string())?;
    *guard = Some(sink);
    let mode = if use_mock { "mock" } else { "ble" };
    if let Some(ref s) = *guard {
        s.add(format!("Bridge initialized ({mode} mode)"));
    }
    Ok(())
}

/// Scans for nearby Bluetooth devices.
pub fn discover_devices(use_mock: bool) -> Result<Vec<BridgeDevice>, String> {
    let st = state();
    let devices = st
        .runtime
        .block_on(st.adapter(use_mock).discover())
        .into_iter()
        .map(BridgeDevice::from)
        .collect();
    Ok(devices)
}

/// Connects to the selected Bluetooth device.
pub fn connect_device(name: String, address: String, use_mock: bool) -> Result<(), String> {
    let st = state();
    let dev = BluetoothDevice { name, address };
    st.runtime.block_on(st.adapter(use_mock).connect(&dev))
}

/// Sends a plain UTF-8 message over the active Bluetooth connection.
pub fn send_plain_message(message: String, use_mock: bool) -> Result<(), String> {
    let st = state();
    st.runtime
        .block_on(st.adapter(use_mock).send(message.as_bytes()))
}

/// Encrypts `message` with AES-256-GCM (`12-byte nonce || ciphertext`) and sends it.
pub fn send_encrypted_message(
    message: String,
    key: Vec<u8>,
    use_mock: bool,
) -> Result<Vec<u8>, String> {
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| "Encryption key must be exactly 32 bytes".to_string())?;
    let (nonce, ciphertext) = encrypt_message(&key_arr, message.as_bytes())?;

    let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    let st = state();
    st.runtime.block_on(st.adapter(use_mock).send(&payload))?;
    Ok(payload)
}

/// Receives raw bytes from the active Bluetooth adapter and forwards UTF-8 text to the sink if set.
pub fn receive_messages(use_mock: bool) -> Result<Vec<u8>, String> {
    let st = state();
    let bytes = st.runtime.block_on(st.adapter(use_mock).receive())?;
    if !bytes.is_empty() {
        if let Ok(guard) = st.stream_sink.lock() {
            if let Some(ref sink) = *guard {
                sink.add(String::from_utf8_lossy(&bytes).to_string());
            }
        }
    }
    Ok(bytes)
}

/// Generates a random 32-byte AES-256-GCM session key.
pub fn generate_encryption_key() -> Vec<u8> {
    generate_key().to_vec()
}

/// Decrypts a `12-byte nonce || ciphertext` payload using the 32-byte session key.
pub fn decrypt_payload(key: Vec<u8>, payload: Vec<u8>) -> Result<String, String> {
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| "Encryption key must be exactly 32 bytes".to_string())?;
    if payload.len() < 12 {
        return Err("Encrypted payload too short to contain 12-byte nonce".to_string());
    }
    let (nonce, ciphertext) = payload.split_at(12);
    let plaintext = decrypt_message(&key_arr, nonce, ciphertext)?;
    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8 plaintext: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_mock_plain_and_encrypted_flow() {
        assert_eq!(hello(), 42);

        let devices = discover_devices(true).expect("discover");
        assert_eq!(devices.len(), 1);
        let dev = &devices[0];
        assert_eq!(dev.name, "MockDevice");

        connect_device(dev.name.clone(), dev.address.clone(), true).expect("connect");

        // Plain message test
        send_plain_message("Merhaba Flutter".to_string(), true).expect("send plain");
        let received = receive_messages(true).expect("receive plain");
        assert!(String::from_utf8_lossy(&received).contains("Merhaba Flutter"));

        // Encrypted message round-trip via fresh key & payload verification
        let key = generate_encryption_key();
        assert_eq!(key.len(), 32);
        let payload =
            send_encrypted_message("Gizli Mobil Mesaj".to_string(), key.clone(), true)
                .expect("send encrypted");
        let decrypted = decrypt_payload(key, payload).expect("decrypt");
        assert_eq!(decrypted, "Gizli Mobil Mesaj");
    }

    #[test]
    fn bridge_invalid_key_and_payload_errors() {
        assert!(send_encrypted_message("test".into(), vec![1, 2, 3], true).is_err());
        assert!(decrypt_payload(vec![0u8; 32], vec![1, 2, 3]).is_err());
    }
}
