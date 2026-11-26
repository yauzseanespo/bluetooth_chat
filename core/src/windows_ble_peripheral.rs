use std::sync::{Arc, Mutex};

use windows::core::GUID;
use windows::Devices::Bluetooth::BluetoothError;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisingParameters,
    GattWriteRequestedEventArgs,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};

/// Nordic UART-compatible GATT Service & Characteristic UUIDs for Bluetooth Chat.
pub const CHAT_SERVICE_UUID: GUID = GUID::from_u128(0x6E400001_B5A3_F393_E0A9_E50E24DCCA9E);
pub const CHAT_RX_CHAR_UUID: GUID = GUID::from_u128(0x6E400002_B5A3_F393_E0A9_E50E24DCCA9E);
pub const CHAT_TX_CHAR_UUID: GUID = GUID::from_u128(0x6E400003_B5A3_F393_E0A9_E50E24DCCA9E);

#[derive(Default)]
struct PeripheralState {
    provider: Option<GattServiceProvider>,
    tx_characteristic: Option<GattLocalCharacteristic>,
    advertising: bool,
}

/// Windows BLE GATT Server (Peripheral) for accepting incoming connections and writes.
pub struct WindowsBlePeripheral {
    state: Mutex<PeripheralState>,
    rx_buffer: Arc<Mutex<Vec<u8>>>,
}

impl WindowsBlePeripheral {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PeripheralState::default()),
            rx_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn is_advertising(&self) -> bool {
        self.state.lock().map(|s| s.advertising).unwrap_or(false)
    }

    /// Creates the GATT chat service, attaches the `WriteRequested` handler, and starts BLE advertising.
    pub fn start(&self) -> Result<(), String> {
        {
            let guard = self.state.lock().map_err(|_| "Peripheral lock poisoned")?;
            if guard.advertising {
                return Ok(());
            }
        }

        let service_result = GattServiceProvider::CreateAsync(CHAT_SERVICE_UUID)
            .map_err(|e| format!("GattServiceProvider::CreateAsync failed: {e}"))?
            .get()
            .map_err(|e| format!("Failed to create GATT service provider: {e}"))?;

        let err = service_result.Error().map_err(|e| e.to_string())?;
        if err != BluetoothError::Success {
            return Err(format!("GATT service provider error: {err:?}"));
        }

        let provider = service_result
            .ServiceProvider()
            .map_err(|e| e.to_string())?;
        let service = provider.Service().map_err(|e| e.to_string())?;

        // RX characteristic (Central writes here -> Peripheral receives)
        let rx_params = GattLocalCharacteristicParameters::new().map_err(|e| e.to_string())?;
        rx_params
            .SetCharacteristicProperties(
                GattCharacteristicProperties::Write
                    | GattCharacteristicProperties::WriteWithoutResponse,
            )
            .map_err(|e| e.to_string())?;
        rx_params
            .SetWriteProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| e.to_string())?;

        let rx_result = service
            .CreateCharacteristicAsync(CHAT_RX_CHAR_UUID, &rx_params)
            .map_err(|e| format!("CreateCharacteristicAsync (RX) failed: {e}"))?
            .get()
            .map_err(|e| format!("Failed to create RX characteristic: {e}"))?;

        if rx_result.Error().map_err(|e| e.to_string())? != BluetoothError::Success {
            return Err("Failed to initialize RX GATT characteristic".to_string());
        }
        let rx_char = rx_result.Characteristic().map_err(|e| e.to_string())?;

        let buffer_clone = Arc::clone(&self.rx_buffer);
        rx_char
            .WriteRequested(&TypedEventHandler::new(
                move |_sender: &Option<GattLocalCharacteristic>,
                      args: &Option<GattWriteRequestedEventArgs>| {
                    if let Some(args) = args {
                        if let Ok(deferral) = args.GetDeferral() {
                            let args_clone = args.clone();
                            let buf_ref = Arc::clone(&buffer_clone);
                            std::thread::spawn(move || {
                                if let Ok(op) = args_clone.GetRequestAsync() {
                                    if let Ok(request) = op.get() {
                                        if let Ok(value) = request.Value() {
                                            if let Ok(reader) = DataReader::FromBuffer(&value) {
                                                let len =
                                                    reader.UnconsumedBufferLength().unwrap_or(0)
                                                        as usize;
                                                let mut bytes = vec![0u8; len];
                                                if reader.ReadBytes(&mut bytes).is_ok() {
                                                    if let Ok(mut rx_buf) = buf_ref.lock() {
                                                        rx_buf.extend(bytes);
                                                    }
                                                }
                                            }
                                        }
                                        let _ = request.Respond();
                                    }
                                }
                                let _ = deferral.Complete();
                            });
                        }
                    }
                    Ok(())
                },
            ))
            .map_err(|e| format!("Failed to attach WriteRequested handler: {e}"))?;

        // TX characteristic (Peripheral notifies connected Central devices)
        let tx_params = GattLocalCharacteristicParameters::new().map_err(|e| e.to_string())?;
        tx_params
            .SetCharacteristicProperties(
                GattCharacteristicProperties::Notify | GattCharacteristicProperties::Read,
            )
            .map_err(|e| e.to_string())?;
        tx_params
            .SetReadProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| e.to_string())?;

        let tx_result = service
            .CreateCharacteristicAsync(CHAT_TX_CHAR_UUID, &tx_params)
            .map_err(|e| format!("CreateCharacteristicAsync (TX) failed: {e}"))?
            .get()
            .map_err(|e| format!("Failed to create TX characteristic: {e}"))?;

        if tx_result.Error().map_err(|e| e.to_string())? != BluetoothError::Success {
            return Err("Failed to initialize TX GATT characteristic".to_string());
        }
        let tx_char = tx_result.Characteristic().map_err(|e| e.to_string())?;

        let adv_params =
            GattServiceProviderAdvertisingParameters::new().map_err(|e| e.to_string())?;
        adv_params.SetIsConnectable(true).map_err(|e| e.to_string())?;
        adv_params
            .SetIsDiscoverable(true)
            .map_err(|e| e.to_string())?;

        provider
            .StartAdvertisingWithParameters(&adv_params)
            .map_err(|e| format!("StartAdvertisingWithParameters failed: {e}"))?;

        let mut guard = self.state.lock().map_err(|_| "Peripheral lock poisoned")?;
        guard.provider = Some(provider);
        guard.tx_characteristic = Some(tx_char);
        guard.advertising = true;

        Ok(())
    }

    /// Stops BLE peripheral advertising and clears active GATT provider handles.
    pub fn stop(&self) -> Result<(), String> {
        let mut guard = self.state.lock().map_err(|_| "Peripheral lock poisoned")?;
        if let Some(ref provider) = guard.provider {
            let _ = provider.StopAdvertising();
        }
        guard.provider = None;
        guard.tx_characteristic = None;
        guard.advertising = false;
        Ok(())
    }

    /// Sends a notification payload to subscribed central clients via the TX characteristic.
    pub fn notify(&self, data: &[u8]) -> Result<(), String> {
        let tx = {
            let guard = self.state.lock().map_err(|_| "Peripheral lock poisoned")?;
            guard
                .tx_characteristic
                .clone()
                .ok_or_else(|| "Peripheral GATT server is not started".to_string())?
        };

        let writer = DataWriter::new().map_err(|e| e.to_string())?;
        writer.WriteBytes(data).map_err(|e| e.to_string())?;
        let buffer = writer.DetachBuffer().map_err(|e| e.to_string())?;

        let _ = tx
            .NotifyValueAsync(&buffer)
            .map_err(|e| format!("NotifyValueAsync failed: {e}"))?
            .get()
            .map_err(|e| format!("GATT notify failed: {e}"))?;

        Ok(())
    }

    /// Drains and returns all bytes written to the RX characteristic so far.
    pub fn take_received(&self) -> Vec<u8> {
        let mut buf = self.rx_buffer.lock().unwrap();
        std::mem::take(&mut *buf)
    }
}

impl Default for WindowsBlePeripheral {
    fn default() -> Self {
        Self::new()
    }
}
