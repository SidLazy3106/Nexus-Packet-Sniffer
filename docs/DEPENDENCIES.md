# Dependencies and redistribution

## External driver (NOT bundled)

| Component | Role | Licence / redistribution |
|---|---|---|
| **Npcap** (runtime) | Packet capture driver and `wpcap.dll` | Separate product by Nmap Software LLC. The free licence permits personal/internal use; **redistribution or bundling in a product requires an Npcap OEM licence**. NEXUS therefore does not include it and never installs it silently - users install it from <https://npcap.com> |
| **Npcap SDK** | `wpcap.lib` for linking at build time | Developer download; not redistributed in this repository |
| **Microsoft WebView2** | Renders the UI | Evergreen runtime; the Tauri installer downloads the bootstrapper when absent |

## Rust crates (direct)

tauri, tauri-plugin-dialog (MIT/Apache-2.0) · serde, serde_json (MIT/Apache-2.0) · parking_lot (MIT/Apache-2.0) ·
thiserror (MIT/Apache-2.0) · tracing, tracing-subscriber (MIT) · rusqlite with bundled SQLite (MIT; SQLite is public domain) ·
pcap (MIT/Apache-2.0) · sysinfo (MIT) · tokio (MIT) · ipconfig (MIT/Apache-2.0) · windows-sys (MIT/Apache-2.0).

## JavaScript packages (direct)

react, react-dom (MIT) · recharts (MIT) · @tanstack/react-virtual (MIT) · lucide-react (ISC) ·
@tauri-apps/api, @tauri-apps/plugin-dialog (MIT/Apache-2.0) · tailwindcss, @tailwindcss/vite (MIT) · vite, vitest, typescript (MIT/Apache-2.0).

Run `cargo tree` / `npm ls` for the full transitive lists; generate a licence report with `cargo install cargo-about` and `npx license-checker` before distributing binaries. The authoritative terms are those in each package; verify them before redistribution.
