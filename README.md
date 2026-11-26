# Bluetooth Chat

Cross-platform Bluetooth chat application built with Rust.

## Architecture

```
bluetooth_chat/
├── .github/workflows/  # CI workflow (Windows & Ubuntu)
├── core/               # Shared library (bluetooth_core)
│   ├── bluetooth       # BluetoothAdapter trait + MockAdapter
│   ├── windows_ble     # Windows BLE (WinRT) adapter
│   └── encryption      # AES-256-GCM authenticated encryption
├── desktop/            # Tauri desktop app (Windows/macOS/Linux)
├── mobile_bridge/      # Flutter FFI bridge via flutter_rust_bridge
└── dist/               # Desktop frontend UI
```

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- Windows: WebView2 (pre-installed on Windows 10/11)

## Build & Run

```bash
# Run all workspace tests
cargo test

# Run desktop app (supports both real Windows BLE & Mock Mode + AES-256-GCM)
cargo run -p desktop

# Release build
cargo build --release
```

## Crates

| Crate | Description |
|-------|-------------|
| `bluetooth_core` | `BluetoothAdapter` trait, `MockAdapter`, `WindowsBleAdapter` (WinRT BLE), AES-256-GCM encryption |
| `desktop` | Tauri-based desktop GUI with BLE scanning, session key management & encrypted chat |
| `mobile_bridge` | FFI bridge for Flutter (`discover_devices`, `connect_device`, `send_encrypted_message`, `receive_messages`, `StreamSink`) |

## Status

- 🟢 Core library (`bluetooth_core`) — Windows BLE + AES-256-GCM + unit tests passing
- 🟢 Desktop app (`desktop`) — Tauri UI connected to BLE & AES-256-GCM + unit tests passing
- 🟢 Mobile bridge (`mobile_bridge`) — Flutter FFI API + unit tests passing
- 🟢 CI/CD — GitHub Actions workflow configured

## License

MIT
