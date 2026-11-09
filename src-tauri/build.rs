fn main() {
    // wpcap.dll comes from the separately-installed Npcap driver package. Delay-loading it lets
    // NEXUS start without Npcap and show installation guidance instead of a loader error.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
        // Test binaries that use Tauri's mock runtime need the Common-Controls v6 manifest that
        // tauri-build embeds only in the application itself.
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-tests=/MANIFESTINPUT:{dir}/tests/windows-test.manifest");
        println!("cargo:rerun-if-changed=tests/windows-test.manifest");
    }
    tauri_build::build()
}
