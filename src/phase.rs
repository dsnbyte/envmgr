use crate::model::{HostMode, PhaseConfig};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2b512, Blake2bVar, Digest,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEnvInfo {
    pub id: String,
    pub name: String,
    pub identity_key: String,
    pub wrapped_seed: String,
    pub wrapped_salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseAppInfo {
    pub id: String,
    pub name: String,
    pub environments: Vec<PhaseEnvInfo>,
}

#[derive(Debug, Clone)]
pub struct PssToken {
    pub token_type: String,
    pub app_token: String,
    pub pss_user_public_key: String,
    pub keyshare0: String,
    pub keyshare1_unwrap_key: String,
}

impl PssToken {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let segments: Vec<&str> = trimmed.split(':').collect();
        if segments.len() != 6 {
            return Err(
                "Invalid PAT format. Expected Phase token: pss_user:v1:... or pss_service:v2:..."
                    .to_string(),
            );
        }
        let prefix = segments[0];
        let version = segments[1];
        if prefix != "pss_user" && prefix != "pss_service" {
            return Err(format!(
                "Invalid token prefix '{}'. Expected 'pss_user' or 'pss_service'",
                prefix
            ));
        }
        let token_type = if prefix == "pss_service" {
            if version == "v2" {
                "ServiceAccount".to_string()
            } else {
                "Service".to_string()
            }
        } else {
            "User".to_string()
        };

        Ok(Self {
            token_type,
            app_token: segments[2].to_string(),
            pss_user_public_key: segments[3].to_string(),
            keyshare0: segments[4].to_string(),
            keyshare1_unwrap_key: segments[5].to_string(),
        })
    }
}

pub fn decode_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex for {}: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid length for {}: expected 32 bytes, got {}",
            label,
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn decrypt_raw(combined_ct: &[u8], rx_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // 24-byte XChaCha20 nonce at the end + 16-byte Poly1305 tag minimum
    if combined_ct.len() < 40 {
        return Err(format!(
            "Ciphertext too short ({} bytes)",
            combined_ct.len()
        ));
    }
    let nonce_start = combined_ct.len() - 24;
    let ciphertext = &combined_ct[..nonce_start];
    let nonce = XNonce::from_slice(&combined_ct[nonce_start..]);

    let cipher = XChaCha20Poly1305::new(rx_key.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "XChaCha20-Poly1305 decryption failed".to_string())
}

pub fn decrypt_b64(b64_ct: &str, rx_key: &[u8; 32]) -> Result<String, String> {
    let ct = BASE64
        .decode(b64_ct.trim())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    let plain_bytes = decrypt_raw(&ct, rx_key)?;
    String::from_utf8(plain_bytes).map_err(|e| format!("Invalid UTF-8 in plaintext: {}", e))
}

pub fn server_session_keys(
    server_pk: &[u8; 32],
    server_sk: &[u8; 32],
    client_pk: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let shared = x25519_dalek::x25519(*server_sk, *client_pk);
    let mut hasher = Blake2b512::new();
    Digest::update(&mut hasher, shared);
    Digest::update(&mut hasher, client_pk);
    Digest::update(&mut hasher, server_pk);
    let digest = hasher.finalize();

    let mut rx = [0u8; 32];
    let mut tx = [0u8; 32];
    // Server swaps Rx and Tx compared to client
    rx.copy_from_slice(&digest[32..64]);
    tx.copy_from_slice(&digest[0..32]);
    (rx, tx)
}

pub fn decrypt_asymmetric(
    ciphertext_str: &str,
    private_key_hex: &str,
    public_key_hex: &str,
) -> Result<String, String> {
    let segments: Vec<&str> = ciphertext_str.split(':').collect();
    if segments.len() != 4 || segments[0] != "ph" {
        return Err("Invalid Phase ciphertext format".to_string());
    }
    if segments[1] != "v1" {
        return Err(format!("Unsupported ciphertext version: {}", segments[1]));
    }

    let ephemeral_pk = decode_hex_32(segments[2], "ephemeral public key")?;
    let priv_key = decode_hex_32(private_key_hex, "private key")?;
    let pub_key = decode_hex_32(public_key_hex, "public key")?;

    let (rx, _) = server_session_keys(&pub_key, &priv_key, &ephemeral_pk);
    decrypt_b64(segments[3], &rx)
}

pub fn generate_env_keypair(seed_hex: &str) -> Result<(String, String), String> {
    let seed = decode_hex_32(seed_hex, "environment seed")?;
    let mut hasher = Blake2bVar::new(32).map_err(|e| format!("Blake2b init error: {}", e))?;
    Update::update(&mut hasher, &seed);
    let mut secret = [0u8; 32];
    hasher
        .finalize_variable(&mut secret)
        .map_err(|e| format!("Blake2b finalize error: {}", e))?;

    let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    Ok((hex::encode(public), hex::encode(secret)))
}

pub fn reconstruct_secret(share0_hex: &str, share1_hex: &str) -> Result<String, String> {
    let s0 = decode_hex_32(share0_hex, "keyshare0")?;
    let s1 = decode_hex_32(share1_hex, "keyshare1")?;
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = s0[i] ^ s1[i];
    }
    Ok(hex::encode(out))
}

impl PssToken {
    pub fn decrypt_wrapped(
        &self,
        phase_ciphertext: &str,
        wrapped_key_share_hex: &str,
    ) -> Result<String, String> {
        let wrapped_bytes = hex::decode(wrapped_key_share_hex.trim())
            .map_err(|e| format!("Failed to hex-decode wrapped_key_share: {}", e))?;
        let unwrap_key = decode_hex_32(&self.keyshare1_unwrap_key, "keyshare1_unwrap_key")?;
        let keyshare1_bytes = decrypt_raw(&wrapped_bytes, &unwrap_key)?;
        let keyshare1_hex = String::from_utf8(keyshare1_bytes)
            .map_err(|e| format!("Invalid UTF-8 in keyshare1: {}", e))?;

        let app_priv_key_hex = reconstruct_secret(&self.keyshare0, &keyshare1_hex)?;
        decrypt_asymmetric(
            phase_ciphertext,
            &app_priv_key_hex,
            &self.pss_user_public_key,
        )
    }
}

#[derive(Debug, Deserialize)]
struct TokensApiResponse {
    #[serde(default)]
    apps: Vec<RawApp>,
    #[serde(default)]
    wrapped_key_share: String,
}

#[derive(Debug, Deserialize)]
struct RawApp {
    id: String,
    name: String,
    #[serde(default)]
    environment_keys: Vec<RawEnvKey>,
}

#[derive(Debug, Deserialize)]
struct RawEnvKey {
    environment: RawEnvironment,
    #[serde(default)]
    identity_key: String,
    #[serde(default)]
    wrapped_seed: String,
    #[serde(default)]
    wrapped_salt: String,
}

#[derive(Debug, Deserialize)]
struct RawEnvironment {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawSecret {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    override_val: Option<RawOverride>,
    #[serde(rename = "override")]
    override_field: Option<RawOverride>,
}

#[derive(Debug, Deserialize)]
struct RawOverride {
    #[serde(default)]
    value: String,
    #[serde(default, alias = "isActive")]
    is_active: bool,
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
}

/// Fetches the list of accessible Applications and Environments from Phase.dev
/// and validates the PAT token.
pub fn fetch_apps_and_envs(config: &PhaseConfig) -> Result<Vec<PhaseAppInfo>, String> {
    if !config.is_configured() {
        return Err("Phase.dev connection is not configured yet.".to_string());
    }

    let pss = PssToken::parse(&config.pat_token)?;
    let host = config.effective_host();
    let url = format!("{}/service/secrets/tokens/", host);
    let auth_header = format!("Bearer {} {}", pss.token_type, pss.app_token);

    let resp = http_agent()
        .get(&url)
        .set("Authorization", &auth_header)
        .set("User-Agent", "envmgr-rust/0.1.0")
        .call()
        .map_err(|e| format!("Phase API request failed ({}): {}", url, e))?;

    let data: TokensApiResponse = resp
        .into_json()
        .map_err(|e| format!("Failed to parse Phase API response: {}", e))?;

    // Validate that wrapped_key_share can be decrypted with the provided token
    if !data.wrapped_key_share.is_empty() {
        let wrapped_bytes = hex::decode(data.wrapped_key_share.trim())
            .map_err(|e| format!("Invalid wrapped_key_share hex: {}", e))?;
        let unwrap_key = decode_hex_32(&pss.keyshare1_unwrap_key, "keyshare1_unwrap_key")?;
        let _ = decrypt_raw(&wrapped_bytes, &unwrap_key)
            .map_err(|_| "PAT keyshare decryption failed (invalid token)".to_string())?;
    }

    let apps = data
        .apps
        .into_iter()
        .map(|a| PhaseAppInfo {
            id: a.id,
            name: a.name,
            environments: a
                .environment_keys
                .into_iter()
                .map(|ek| PhaseEnvInfo {
                    id: ek.environment.id,
                    name: ek.environment.name,
                    identity_key: ek.identity_key,
                    wrapped_seed: ek.wrapped_seed,
                    wrapped_salt: ek.wrapped_salt,
                })
                .collect(),
        })
        .collect();

    Ok(apps)
}

/// Fetches and decrypts all secrets for a given App ID and Environment ID from Phase.dev.
pub fn fetch_secrets_for_env(
    config: &PhaseConfig,
    app_id: &str,
    env_id: &str,
) -> Result<Vec<(String, String)>, String> {
    let pss = PssToken::parse(&config.pat_token)?;
    let host = config.effective_host();
    let tokens_url = format!("{}/service/secrets/tokens/", host);
    let auth_header = format!("Bearer {} {}", pss.token_type, pss.app_token);

    let agent = http_agent();
    let user_resp = agent
        .get(&tokens_url)
        .set("Authorization", &auth_header)
        .set("User-Agent", "envmgr-rust/0.1.0")
        .call()
        .map_err(|e| format!("Failed to fetch Phase user context: {}", e))?;

    let user_data: TokensApiResponse = user_resp
        .into_json()
        .map_err(|e| format!("Failed to decode Phase user context: {}", e))?;

    // Find matching app & environment key
    let mut target_env_key: Option<RawEnvKey> = None;
    for app in user_data.apps {
        if !app_id.is_empty() && app.id != app_id {
            continue;
        }
        for ek in app.environment_keys {
            if ek.environment.id == env_id {
                target_env_key = Some(ek);
                break;
            }
        }
        if target_env_key.is_some() {
            break;
        }
    }

    let env_key =
        target_env_key.ok_or_else(|| format!("Environment '{}' not found in Phase", env_id))?;

    let decrypted_seed = pss.decrypt_wrapped(&env_key.wrapped_seed, &user_data.wrapped_key_share)?;
    let (_, env_priv_key) = generate_env_keypair(&decrypted_seed)?;
    let env_pub_key = env_key.identity_key;

    let secrets_url = format!("{}/service/secrets/", host);
    let secrets_resp = agent
        .get(&secrets_url)
        .set("Authorization", &auth_header)
        .set("User-Agent", "envmgr-rust/0.1.0")
        .set("Environment", env_id)
        .set("KeyDigest", "")
        .call()
        .map_err(|e| format!("Failed to fetch secrets from Phase: {}", e))?;

    let raw_secrets: Vec<RawSecret> = secrets_resp
        .into_json()
        .map_err(|e| format!("Failed to parse secrets JSON: {}", e))?;

    let mut pairs = Vec::with_capacity(raw_secrets.len());
    for item in raw_secrets {
        if item.key.is_empty() {
            continue;
        }
        let ov = item.override_field.as_ref().or(item.override_val.as_ref());
        let val_cipher = match ov {
            Some(o) if o.is_active && !o.value.is_empty() => &o.value,
            _ => &item.value,
        };

        let key_plain = decrypt_asymmetric(&item.key, &env_priv_key, &env_pub_key)?;
        let val_plain = if val_cipher.is_empty() {
            String::new()
        } else {
            decrypt_asymmetric(val_cipher, &env_priv_key, &env_pub_key)?
        };

        pairs.push((key_plain, val_plain));
    }

    // Sort alphabetically by key for deterministic order
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(pairs)
}

/// Helper to read local Phase CLI credentials (~/.phase/config.json) if user wants to import it
pub fn try_detect_local_phase_cli_host() -> Option<(HostMode, String)> {
    let home = std::env::var("HOME").ok()?;
    let cfg_path = std::path::PathBuf::from(home)
        .join(".phase")
        .join("config.json");
    let content = std::fs::read_to_string(cfg_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&content).ok()?;
    let host = val.get("host")?.as_str()?.trim_end_matches('/').to_string();
    if host.is_empty() || host == "https://console.phase.dev" {
        Some((HostMode::Cloud, String::new()))
    } else {
        Some((HostMode::SelfHosted, host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_roundtrip_and_env_keypair() {
        // Generate an env keypair from a 32-byte hex seed
        let seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let (server_pub_hex, server_priv_hex) =
            generate_env_keypair(seed_hex).expect("should derive keypair");

        // Simulate client ephemeral keypair
        let client_seed = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let (client_pub_hex, client_priv_hex) =
            generate_env_keypair(client_seed).expect("should derive client keypair");

        let server_pk = decode_hex_32(&server_pub_hex, "srv_pk").unwrap();
        let client_pk = decode_hex_32(&client_pub_hex, "cli_pk").unwrap();
        let client_sk = decode_hex_32(&client_priv_hex, "cli_sk").unwrap();

        // Client session keys: Blake2b512(shared || client_pk || server_pk) -> tx is [32..64]
        let shared = x25519_dalek::x25519(client_sk, server_pk);
        let mut h = Blake2b512::new();
        Digest::update(&mut h, shared);
        Digest::update(&mut h, client_pk);
        Digest::update(&mut h, server_pk);
        let digest = h.finalize();
        let mut client_tx = [0u8; 32];
        client_tx.copy_from_slice(&digest[32..64]);

        // Encrypt with XChaCha20Poly1305 and append 24-byte nonce
        let nonce_bytes = [7u8; 24];
        let cipher = XChaCha20Poly1305::new((&client_tx).into());
        let mut ct = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), b"DATABASE_URL=postgres://localhost/db".as_ref())
            .unwrap();
        ct.extend_from_slice(&nonce_bytes);
        let ph_ciphertext = format!("ph:v1:{}:{}", client_pub_hex, BASE64.encode(&ct));

        // Decrypt using decrypt_asymmetric
        let decrypted =
            decrypt_asymmetric(&ph_ciphertext, &server_priv_hex, &server_pub_hex).unwrap();
        assert_eq!(decrypted, "DATABASE_URL=postgres://localhost/db");
    }

    #[test]
    fn test_pss_token_parse() {
        let sample = format!(
            "pss_user:v1:{}:{}:{}:{}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let parsed = PssToken::parse(&sample).unwrap();
        assert_eq!(parsed.token_type, "User");

        let sample_sa = format!(
            "pss_service:v2:{}:{}:{}:{}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let parsed_sa = PssToken::parse(&sample_sa).unwrap();
        assert_eq!(parsed_sa.token_type, "ServiceAccount");
    }
}
