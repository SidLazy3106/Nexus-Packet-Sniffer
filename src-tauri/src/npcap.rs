//! Npcap availability check. NEXUS never bundles or silently installs the driver.

use crate::constants::*;
use crate::error::{NexusError, Result};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NpcapStatus {
    pub available: bool,
    pub detail: String,
    pub download_url: &'static str,
    pub admin_note: &'static str,
}

const ADMIN_NOTE: &str = "Capturing packets needs the Npcap driver. By default Npcap restricts capture to Administrators: run NEXUS as Administrator, or reinstall Npcap with the 'Restrict Npcap driver's access to Administrators only' option unchecked. NEXUS never elevates itself.";

#[cfg(windows)]
pub fn status() -> NpcapStatus {
    use std::path::Path;
    let dir = Path::new(NPCAP_DIR_WINDOWS);
    let dll = dir.join("wpcap.dll");
    let available = dll.exists();
    if available {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives the call.
        unsafe {
            windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(wide.as_ptr());
        }
    }
    NpcapStatus {
        available,
        detail: if available {
            format!("Found {}", dll.display())
        } else {
            format!("{} was not found. Install Npcap (WinPcap API-compatible mode is not required).", dll.display())
        },
        download_url: NPCAP_DOWNLOAD_URL,
        admin_note: ADMIN_NOTE,
    }
}

#[cfg(not(windows))]
pub fn status() -> NpcapStatus {
    NpcapStatus { available: true, detail: "libpcap assumed present on this platform".into(), download_url: NPCAP_DOWNLOAD_URL, admin_note: ADMIN_NOTE }
}

/// Make sure live capture can work, returning an actionable error otherwise.
pub fn ensure() -> Result<()> {
    let s = status();
    if s.available {
        Ok(())
    } else {
        Err(NexusError::NpcapMissing(format!("{} Download: {}", s.detail, s.download_url)))
    }
}
