use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
};
use windows::Devices::Bluetooth::BluetoothLEDevice;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattCharacteristicProperties,
    GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
    GattValueChangedEventArgs,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};

use crate::bluetooth::{BluetoothAdapter, BluetoothDevice};

#[derive(Default)]
struct ConnectionState {
    device: Option<BluetoothLEDevice>,
    tx_characteristic: Option<GattCharacteristic>,
    rx_characteristic: Option<GattCharacteristic>,
}

/// Real Windows BLE adapter powered by WinRT (`windows` crate).
pub struct WindowsBleAdapter {
    scan_duration: Duration,
    state: Mutex<ConnectionState>,
    rx_buffer: Arc<Mutex<Vec<u8>>>,
}

impl WindowsBleAdapter {
    pub fn new() -> Self {
        Self::with_scan_duration(Duration::from_secs(4))
    }

    pub fn with_scan_duration(scan_duration: Duration) -> Self {
        Self {
            scan_duration,
            state: Mutex::new(ConnectionState::default()),
            rx_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn format_address(addr: u64) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (addr >> 40) & 0xFF,
            (addr >> 32) & 0xFF,
            (addr >> 24) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF,
            addr & 0xFF
        )
    }

    fn parse_address(address: &str) -> Result<u64, String> {
        let hex: String = address.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 {
            return Err(format!("Invalid Bluetooth address: {address}"));
        }
        u64::from_str_radix(&hex, 16)
            .map_err(|e| format!("Failed to parse Bluetooth address '{address}': {e}"))
    }
    fn discover_blocking(scan_duration: Duration) -> Vec<BluetoothDevice> {
        let discovered: Arc<Mutex<HashMap<u64, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let discovered_clone = Arc::clone(&discovered);

        let watcher = match BluetoothLEAdvertisementWatcher::new() {
            Ok(w) => w,
            Err(_) => return Vec::new(),
        };

        let handler = TypedEventHandler::new(
            move |_watcher: &Option<BluetoothLEAdvertisementWatcher>,
                  args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args {
                    if let Ok(addr) = args.BluetoothAddress() {
                        let name = args
                            .Advertisement()
                            .ok()
                            .and_then(|adv| adv.LocalName().ok())
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "Unknown BLE Device".to_string());

                        if let Ok(mut map) = discovered_clone.lock() {
                            map.entry(addr)
                                .and_modify(|existing| {
                                    if existing == "Unknown BLE Device" && name != "Unknown BLE Device" {
                                        *existing = name.clone();
                                    }
                                })
                                .or_insert(name);
                        }
                    }
                }
                Ok(())
            },
        );

        let token = match watcher.Received(&handler) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        if watcher.Start().is_err() {
            let _ = watcher.RemoveReceived(token);
            return Vec::new();
        }

        std::thread::sleep(scan_duration);

        let _ = watcher.Stop();
        let _ = watcher.RemoveReceived(token);

        let map = discovered.lock().unwrap();
        let mut devices: Vec<BluetoothDevice> = map
            .iter()
            .map(|(&addr, name)| BluetoothDevice {
                name: name.clone(),
                address: Self::format_address(addr),
            })
            .collect();
        devices.sort_by(|a, b| a.address.cmp(&b.address));
        devices
    }
}

impl Default for WindowsBleAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BluetoothAdapter for WindowsBleAdapter {
    async fn discover(&self) -> Vec<BluetoothDevice> {
        let scan_duration = self.scan_duration;
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            let devices = Self::discover_blocking(scan_duration);
            let _ = tx.send(devices);
        });

        rx.await.unwrap_or_default()
    }

    async fn connect(&self, device: &BluetoothDevice) -> Result<(), String> {
        let addr = Self::parse_address(&device.address)?;

        let ble_device = BluetoothLEDevice::FromBluetoothAddressAsync(addr)
            .map_err(|e| format!("FromBluetoothAddressAsync failed: {e}"))?
            .get()
            .map_err(|e| format!("Failed to connect to BLE device: {e}"))?;

        let services_result = ble_device
            .GetGattServicesAsync()
            .map_err(|e| format!("GetGattServicesAsync failed: {e}"))?
            .get()
            .map_err(|e| format!("Failed to query GATT services: {e}"))?;

        if services_result.Status().map_err(|e| e.to_string())? != GattCommunicationStatus::Success {
            return Err("GATT service discovery did not succeed".to_string());
        }

        let services = services_result.Services().map_err(|e| e.to_string())?;
        let mut tx_char: Option<GattCharacteristic> = None;
        let mut rx_char: Option<GattCharacteristic> = None;

        for service in services {
            let chars_result = match service.GetCharacteristicsAsync() {
                Ok(op) => match op.get() {
                    Ok(res) => res,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            if chars_result.Status().ok() != Some(GattCommunicationStatus::Success) {
                continue;
            }

            let Ok(characteristics) = chars_result.Characteristics() else {
                continue;
            };

            for ch in characteristics {
                let Ok(props) = ch.CharacteristicProperties() else {
                    continue;
                };

                let can_write = (props & GattCharacteristicProperties::Write)
                    == GattCharacteristicProperties::Write
                    || (props & GattCharacteristicProperties::WriteWithoutResponse)
                        == GattCharacteristicProperties::WriteWithoutResponse;
                let can_notify = (props & GattCharacteristicProperties::Notify)
                    == GattCharacteristicProperties::Notify
                    || (props & GattCharacteristicProperties::Indicate)
                        == GattCharacteristicProperties::Indicate;

                if tx_char.is_none() && can_write {
                    tx_char = Some(ch.clone());
                }
                if rx_char.is_none() && can_notify {
                    rx_char = Some(ch);
                }

                if tx_char.is_some() && rx_char.is_some() {
                    break;
                }
            }

            if tx_char.is_some() && rx_char.is_some() {
                break;
            }
        }

        if let Some(ref rx) = rx_char {
            let buffer_clone = Arc::clone(&self.rx_buffer);
            let value_handler = TypedEventHandler::new(
                move |_ch: &Option<GattCharacteristic>, args: &Option<GattValueChangedEventArgs>| {
                    if let Some(args) = args {
                        if let Ok(buf) = args.CharacteristicValue() {
                            if let Ok(len) = buf.Length() {
                                if let Ok(reader) = DataReader::FromBuffer(&buf) {
                                    let mut bytes = vec![0u8; len as usize];
                                    if reader.ReadBytes(&mut bytes).is_ok() {
                                        if let Ok(mut rx_buf) = buffer_clone.lock() {
                                            rx_buf.extend(bytes);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                },
            );

            rx.ValueChanged(&value_handler)
                .map_err(|e| format!("Failed to attach ValueChanged handler: {e}"))?;

            let _ = rx
                .WriteClientCharacteristicConfigurationDescriptorAsync(
                    GattClientCharacteristicConfigurationDescriptorValue::Notify,
                )
                .map_err(|e| format!("Failed to enable GATT notifications: {e}"))?
                .get();
        }

        let mut state = self.state.lock().unwrap();
        state.device = Some(ble_device);
        state.tx_characteristic = tx_char;
        state.rx_characteristic = rx_char;

        Ok(())
    }

    async fn send(&self, data: &[u8]) -> Result<(), String> {
        let tx = {
            let state = self.state.lock().unwrap();
            state
                .tx_characteristic
                .clone()
                .ok_or_else(|| "Not connected to a writable BLE characteristic".to_string())?
        };

        let writer = DataWriter::new().map_err(|e| format!("DataWriter::new failed: {e}"))?;
        writer
            .WriteBytes(data)
            .map_err(|e| format!("DataWriter::WriteBytes failed: {e}"))?;
        let buffer = writer
            .DetachBuffer()
            .map_err(|e| format!("DataWriter::DetachBuffer failed: {e}"))?;

        let status = tx
            .WriteValueAsync(&buffer)
            .map_err(|e| format!("WriteValueAsync failed: {e}"))?
            .get()
            .map_err(|e| format!("GATT write failed: {e}"))?;

        if status != GattCommunicationStatus::Success {
            return Err(format!("GATT write returned non-success status: {status:?}"));
        }

        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, String> {
        let mut buf = self.rx_buffer.lock().unwrap();
        Ok(std::mem::take(&mut *buf))
    }
}
