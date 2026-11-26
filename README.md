# Bluetooth Chat

Cross-platform Bluetooth chat application built with Rust.

## Architecture

```
bluetooth_chat/
├── core/           # Shared library (bluetooth_core)
│   ├── bluetooth   # BluetoothAdapter trait + MockAdapter
│   └── encryption  # XOR-based encryption (demo)
├── desktop/        # Tauri desktop app (Windows/macOS/Linux)
├── mobile_bridge/  # Flutter bridge via flutter_rust_bridge
└── dist/           # Frontend assets (placeholder)
```

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- Windows: WebView2 (pre-installed on Windows 10/11)

## Build & Run

```bash
# Run tests
cargo test

# Run desktop app
cargo run -p desktop

# Release build
cargo build --release
```

## Crates

| Crate | Description |
|-------|-------------|
| `bluetooth_core` | Bluetooth adapter trait, device model, mock adapter, XOR encryption |
| `desktop` | Tauri-based desktop GUI |
| `mobile_bridge` | FFI bridge for Flutter mobile app |

## Status

🟢 Core library — tests passing  
🟡 Desktop app — skeleton UI (placeholder HTML)  
🟡 Mobile bridge — placeholder FFI  
🔴 Real Bluetooth — not yet implemented  

## License

MIT
