pub mod bluetooth;
pub mod encryption;
pub mod framing;

#[cfg(all(target_os = "windows", any(feature = "btle", feature = "classic")))]
pub mod windows_ble;

#[cfg(all(target_os = "windows", any(feature = "btle", feature = "classic")))]
pub mod windows_ble_peripheral;

#[cfg(test)]
mod tests;

