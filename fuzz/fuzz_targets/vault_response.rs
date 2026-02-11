#![no_main]
#![allow(dead_code)]
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

/// Mirror of vault::AddressBookEntry — the struct deserialized from Vault KV responses.
#[derive(Deserialize)]
struct AddressBookEntry {
    #[serde(rename = "type")]
    session_type: String,
    hostname: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    private_key: Option<String>,
    url: Option<String>,
    domain: Option<String>,
    security: Option<String>,
    ignore_cert: Option<bool>,
    display_name: Option<String>,
    enable_drive: Option<bool>,
    auth_pkg: Option<String>,
    kdc_url: Option<String>,
    prompt_credentials: Option<bool>,
    color_depth: Option<u8>,
    jump_hosts: Option<Vec<JumpHost>>,
}

#[derive(Deserialize)]
struct JumpHost {
    hostname: String,
    #[serde(default)]
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
}

/// Mirror of Vault KV v2 read response wrapper.
#[derive(Deserialize)]
struct VaultKvResponse {
    data: Option<VaultKvData>,
}

#[derive(Deserialize)]
struct VaultKvData {
    data: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

/// Mirror of vault folder config (stored at <folder>/.config).
#[derive(Deserialize)]
struct FolderConfig {
    allowed_groups: Option<Vec<String>>,
    description: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    // Fuzz Vault response parsing: entry, KV wrapper, and folder config
    let _ = serde_json::from_slice::<AddressBookEntry>(data);
    let _ = serde_json::from_slice::<VaultKvResponse>(data);
    let _ = serde_json::from_slice::<FolderConfig>(data);

    // Also fuzz extracting an entry from a nested KV response (the real code path)
    if let Ok(wrapper) = serde_json::from_slice::<VaultKvResponse>(data) {
        if let Some(kv_data) = wrapper.data {
            if let Some(inner) = kv_data.data {
                let _ = serde_json::from_value::<AddressBookEntry>(inner);
            }
        }
    }
});
