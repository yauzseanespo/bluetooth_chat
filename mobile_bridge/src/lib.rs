// Placeholder for flutter_rust_bridge generated bindings.
// The actual bridge functions will be added later.

use bluetooth_core::bluetooth::MockAdapter;
use flutter_rust_bridge::StreamSink;

#[no_mangle]
pub extern "C" fn hello() -> i32 {
    // Verify core crate is linked
    let _adapter = MockAdapter::new();
    42 // dummy value
}

/// Placeholder bridge function – will stream chat messages to Flutter.
pub fn init_bridge(_sink: StreamSink<String>) {
    // TODO: wire up real Bluetooth adapter here
}
