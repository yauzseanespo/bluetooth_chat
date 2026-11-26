use async_trait::async_trait;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BluetoothDevice {
    pub name: String,
    pub address: String,
}

#[async_trait]
pub trait BluetoothAdapter {
    async fn discover(&self) -> Vec<BluetoothDevice>;
    async fn connect(&self, device: &BluetoothDevice) -> Result<(), String>;
    async fn send(&self, data: &[u8]) -> Result<(), String>;
    async fn receive(&self) -> Result<Vec<u8>, String>;
}

/// Mock adapter used for unit tests – simply echoes sent data.
pub struct MockAdapter {
    buffer: std::sync::Mutex<Vec<u8>>,
}

impl MockAdapter {
    pub fn new() -> Self {
        Self { buffer: std::sync::Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl BluetoothAdapter for MockAdapter {
    async fn discover(&self) -> Vec<BluetoothDevice> {
        vec![BluetoothDevice { name: "MockDevice".into(), address: "00:11:22:33:44:55".into() }]
    }

    async fn connect(&self, _device: &BluetoothDevice) -> Result<(), String> {
        Ok(())
    }

    async fn send(&self, data: &[u8]) -> Result<(), String> {
        let mut buf = self.buffer.lock().unwrap();
        buf.extend_from_slice(data);
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, String> {
        let buf = self.buffer.lock().unwrap();
        Ok(buf.clone())
    }
}
