#![no_main]
#![allow(dead_code)]
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

/// Mirror of session::CreateSessionRequest for fuzz testing.
#[derive(Deserialize)]
struct CreateSessionRequest {
    #[serde(default)]
    session_type: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    private_key: Option<String>,
    generate_keypair: Option<bool>,
    url: Option<String>,
    domain: Option<String>,
    security: Option<String>,
    ignore_cert: Option<bool>,
    auth_pkg: Option<String>,
    kdc_url: Option<String>,
    kerberos_cache: Option<String>,
    color_depth: Option<u8>,
    jump_hosts: Option<Vec<JumpHost>>,
    jump_host: Option<String>,
    jump_port: Option<u16>,
    jump_username: Option<String>,
    jump_password: Option<String>,
    jump_private_key: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    dpi: Option<u32>,
    banner: Option<String>,
    enable_drive: Option<bool>,
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

/// Mirror of api::ConnectRequest.
#[derive(Deserialize)]
struct ConnectRequest {
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
    #[serde(default)]
    dpi: Option<u32>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

/// Mirror of api::CreateEntryRequest.
#[derive(Deserialize)]
struct CreateEntryRequest {
    name: String,
    #[serde(flatten)]
    entry: AddressBookEntry,
}

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

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON deserialization of all API request types
    let _ = serde_json::from_slice::<CreateSessionRequest>(data);
    let _ = serde_json::from_slice::<ConnectRequest>(data);
    let _ = serde_json::from_slice::<CreateEntryRequest>(data);
});
