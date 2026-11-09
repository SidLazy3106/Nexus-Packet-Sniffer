# NEXUS 0.1.0 - release verification report

Everything below was actually executed on the build machine (Windows 11 Home 10.0.26300, 1920x1080 at 125% scaling, non-elevated user, Npcap installed with *AdminOnly=0*, Wi-Fi adapter). Items not executed are listed as such.

## Artifacts

| Artifact | Path (relative to repo) | Size |
|---|---|---|
| Release executable (x64) | `src-tauri/target/release/nexus.exe` | 13.5 MiB |
| NSIS installer (per-user, recommended) | `src-tauri/target/release/bundle/nsis/NEXUS_0.1.0_x64-setup.exe` | 3.6 MiB |
| MSI installer (per-machine) | `src-tauri/target/release/bundle/msi/NEXUS_0.1.0_x64_en-US.msi` | 5.0 MiB |

Installers are unsigned (SmartScreen will warn). There is no portable build: the executable needs the WebView2 runtime and, for live capture, Npcap, so a loose `nexus.exe` is supported only where those are present.

## Test results

| Suite | Command | Result |
|---|---|---|
| Backend unit + pipeline (incl. driver-free capture pipeline over a `PacketSource`) | `cargo test --lib` | **97 passed**, 0 failed (6 consecutive identical runs) |
| Tauri command layer on a mock app | `cargo test --test commands` | **6 passed** |
| Live capture on real Npcap | `cargo test --test live_capture -- --ignored --test-threads=1` (Npcap dir on PATH) | **4 passed** (interface enumeration, real capture + pause/resume + session save, BPF filter, error mapping, shutdown under traffic) |
| Frontend | `npm test` | **18 passed** (display filter, formatters, finding grouping) |
| Type checks / lint | `tsc -b`, `cargo clippy` (library) | clean |

**Coverage** (`cargo llvm-cov`, all three Rust suites combined): **89.9% of lines**, 85.8% of functions. Not 100%: the app bootstrap (`lib.rs`, `main.rs`), the three commands that need a real webview `AppHandle` (`start_capture`, `import_capture`, `open_session`; their logic is covered through `AppState`), and rarer decoder branches are uncovered. Frontend coverage was not measured.

Not covered by automated tests: React components and pages (verified by hand via screenshots below) and the MSI package.

## Installation checks

| Check | Result |
|---|---|
| NSIS silent install (`/S`), non-elevated | exit 0 in ~2 s. Installs to `%LOCALAPPDATA%\NEXUS` (`nexus.exe`, `uninstall.exe`), Start Menu + Desktop shortcuts, Add/Remove Programs entry "NEXUS 0.1.0" |
| Upgrade install over existing | exit 0, binary replaced, app launched and reopened a saved session |
| Launch of installed exe | Responding; 36-46 MB working set; title "NEXUS - Network Packet Analyzer" |
| NSIS silent uninstall | exit 0; install folder, shortcuts and registry key removed; **user data (settings, sessions) intentionally kept** in `%APPDATA%\com.nexus.packetanalyzer` |
| MSI install (`msiexec /qn`) | **Failed, exit 1603**: the package is per-machine (`ALLUSERS=1`) and the test shell was not elevated. **MSI install/uninstall is unverified.** Use the NSIS installer, or test the MSI from an elevated shell |
| Clean-machine launch | **Not performed.** The test machine has Rust, Node and the Npcap SDK installed. What was verified instead: the exe is self-contained apart from WebView2/Npcap (the release binary does not import Node or Rust components), and it starts and reports Npcap status correctly because `wpcap.dll` is delay-loaded and located via `SetDllDirectory`. A genuinely clean VM check remains to do |
| Behaviour with Npcap absent | **Not executed** (uninstalling the driver from the dev machine was out of scope). Implemented and unit-tested at the code level: delay-loaded `wpcap.dll`, `npcap::status()` check, a banner with download link and admin guidance, live-capture controls disabled, file import still usable |

## Dependencies and prerequisites

See [DEPENDENCIES.md](DEPENDENCIES.md). In short: **Npcap is not bundled and never installed silently** (its licence restricts redistribution without an OEM licence). Live capture does not work without it. The Tauri installer downloads the WebView2 bootstrapper if the runtime is missing (not exercised here: WebView2 was already present).

## Manual UI verification (real release build, real traffic)

Driven by mouse against the installed app. Screenshots were taken locally and are **not committed** (they show the tester's real network addresses):

- Live Capture: real Wi-Fi capture of IPv4/IPv6 TCP, ARP, ICMPv6, DNS with peaks near 400 packets/s, 0 driver drops, 0 queue drops; status pill, filter chips, selection, auto-scroll.
- Capture Sessions: session auto-saved on Stop (4,374 packets); reopened from its file with **identical** findings (57) and counters (101 retransmissions), demonstrating reproducibility.
- Root Cause Analysis: grouped findings, evidence with packet links, confidence, hypotheses vs observations, limits.
- Packet Explorer: Ethernet/IPv6/TCP tree with byte ranges. Traffic Analytics: per-second charts, protocol mix, top talkers. Settings: Npcap detected.
- Not exercised by hand: Export dialogs (covered by the engine/pipeline tests), the redaction toggle in the GUI, the graphite theme, windows narrower than the default.

## Quality work after the first verification pass

- `tcp_event` (300 lines) split into one handler per event; all findings built through `Spec`/`Evidence` builders (21 literal structs removed).
- Nine inline thresholds moved into `DiagConfig` (and Settings); health weights and caps moved into `constants.rs`, and the health explanation text is generated from them.
- `PacketSource` trait added so the capture pipeline is testable without Npcap.
- Frontend: duplicated stat-row components merged, timing constants named, finding grouping extracted and tested.
- `wpcap.dll` is now delay-loaded for every build target, not only the shipped binary.

## Defects found and fixed during verification

1. Unknown-interface error was reported as a *permissions* problem (misleading) → now "interface not found".
2. Unusable "WAN Miniport" adapters sorted first and could be auto-selected → usable adapters (up, has IPv4) first.
3. Default window (1440x900) exceeded a 1920x1080 / 125% display → 1180x720 default, 900x560 minimum.
4. Health score summed unbounded per-flow penalties (47 findings → 0 "Poor") → grouped with logarithmic repeats.
5. A flat per-flow findings list was unreadable → grouped by finding type.
6. Clipped labels ("Root Cause Anal…", "No local …") → wider sidebar, shorter values.
7. DNS/DHCP decoding of snaplen-cut packets raised false "malformed" anomalies → only flagged for complete frames.
8. First IP fragment's description was overwritten by the transport summary → fragment label kept.

## Known limitations and open items

- No clean-VM, no Npcap-absent, no MSI, no Windows 10 testing (only Windows 11).
- Findings semantics were validated on hand-built sequences and on one real capture; there is **no comparison against a reference tool such as Wireshark/tshark** (none installed; the Wireshark sample capture could not be downloaded). Counts such as "retransmissions" use NEXUS' documented rules and may differ from Wireshark's.
- Windows TCP tail-loss probes and spurious retransmissions are reported as retransmissions (as Wireshark does); the finding text says so only in general terms.
- Packet-table sorting by length/descending re-sorts at most every 500 ms; very large captures (>250k rows) are windowed in the UI.
- Not implemented: IP reassembly, DNS over TCP, TLS inspection, checksum validation (deliberate), multi-interface capture, portable build.
- Performance was only observed, not benchmarked: a short real Wi-Fi capture peaked near 400 packets/s with no drops and the process stayed at 36-46 MB. Behaviour under multi-Gbps load is untested.
