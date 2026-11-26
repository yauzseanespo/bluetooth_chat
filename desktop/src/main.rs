use bluetooth_core::bluetooth::MockAdapter;

fn main() {
    // Initialize a mock adapter to verify the core crate is linked.
    let _adapter = MockAdapter::new();

    // Placeholder Tauri app – UI assets can be added later.
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to run tauri app");
}
