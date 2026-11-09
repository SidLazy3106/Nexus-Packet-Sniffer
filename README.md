# NEXUS - Network Packet Analyzer

A native Windows desktop application (Tauri 2 + Rust + React/TypeScript) that captures
authorised network traffic through Npcap, decodes packets at header level, and produces
evidence-based diagnostics. All analysis is local; nothing is uploaded.

> **Only capture networks you are authorised to monitor.** Captures can contain sensitive data.

## What you need

| Where | Requirement | Why |
|---|---|---|
| **Running** NEXUS (end user) | Windows 10/11 x64 | Target platform |
| | [Npcap](https://npcap.com/#download) (separate install) | Live capture driver. **Not bundled.** Import/analysis of PCAP files works without it |
| | Microsoft WebView2 runtime | Preinstalled on Windows 11 and current Windows 10; the installer downloads it if missing |
| | Administrator rights *or* Npcap installed without "Restrict to Administrators" | Npcap's default access policy. NEXUS never elevates itself |
| **Building** from source | Rust (stable, MSVC toolchain) | Backend |
| | Visual Studio 2022 Build Tools, "Desktop development with C++" | MSVC linker/SDK |
| | Node.js 20+ | Frontend build |
| | [Npcap SDK](https://npcap.com/#download) | `wpcap.lib` import library (build time only) |

End users do **not** need Node.js or Rust.

## Build

```powershell
# one-time: unzip the Npcap SDK to C:\Npcap-SDK (or set LIBPCAP_LIBDIR to the folder holding wpcap.lib)
$env:LIBPCAP_LIBDIR = "C:\Npcap-SDK\Lib\x64"      # optional if you used the default path

npm install
npm run build                    # frontend only (type-check + bundle)
npx tauri build                  # release exe + NSIS and MSI installers
```

Outputs (installer notes: the **NSIS** installer is per-user and needs no administrator rights; the **MSI** is per-machine and does):

- Executable: `src-tauri/target/release/nexus.exe`
- NSIS installer: `src-tauri/target/release/bundle/nsis/NEXUS_0.1.0_x64-setup.exe`
- MSI installer: `src-tauri/target/release/bundle/msi/NEXUS_0.1.0_x64_en-US.msi`

Development: `npx tauri dev` (run the terminal as Administrator to capture).

## Tests

```powershell
cd src-tauri
cargo test --lib          # decoder, diagnostics, analytics, pcap I/O, storage, engine, capture pipeline
cargo test --test commands   # Tauri command layer (mock app)
# real Npcap + network (Npcap dir must be on PATH):
#   $env:Path += ";C:\Windows\System32\Npcap"
#   cargo test --test live_capture -- --ignored --test-threads=1
cd ..
npm test                  # frontend filter logic (vitest)
```

## Using NEXUS

1. **Live Capture** - pick an interface, optionally enter a BPF filter (validated as you type), press *Start*.
   *Pause* keeps the capture open but discards packets until you *Resume* (they are counted, not buffered).
   Click a packet to inspect it; Ctrl/Shift-click to select several; *Export* writes the selection or everything to PCAP/PCAPNG.
2. **Packet Explorer** - protocol tree, per-field explanations, highlighted raw bytes.
3. **Protocol Analysis / Traffic Analytics** - protocol mix, rates, top talkers, connections, measured latencies.
4. **Root Cause Analysis** - findings with confirmed observations, supporting packets, *hypotheses* (clearly separate), troubleshooting steps and the limits of each conclusion. Click a packet number to jump to it.
5. **Capture Sessions** - live captures are recorded automatically; reopen, rename, delete, import PCAP/PCAPNG, export reports (JSON/CSV).
6. **Settings** - buffers, retention, privacy masking, thresholds.

### Display filter syntax

Space-separated terms are ANDed: `10.0.0.5 syn`, `port:443`, `ip:10.0.0.1`, `src:192.168`, `dst:8.8.8.8`, `proto:dns`, `-arp` (exclude).

## Privacy and security

- Analysis is local. NEXUS makes no network connections of its own.
- No credential extraction and no decryption are implemented.
- *Payload bytes retained* (default 256) limits how much application data is kept in memory and in recorded/exported files; *Mask payload* hides payload bytes in the hex viewer.
- Recorded sessions and reports live in `%APPDATA%\com.nexus.packetanalyzer` and inherit your user profile's permissions. Reports contain IP addresses.

## Design

The interface follows wabi-sabi: muted earthy tokens (sumi ink, unbleached-silk text, indigo, celadon, aged-gold seam), generous space, serif headings (Lora, bundled locally), restrained motion that honours *reduce motion*. Tokens are defined once in `src/index.css`; see [design-system/nexus/MASTER.md](design-system/nexus/MASTER.md).

## Known limitations

See [docs/RELEASE_VERIFICATION.md](docs/RELEASE_VERIFICATION.md) for exactly what was and was not tested, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#limitations) 
