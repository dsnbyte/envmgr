use crate::model::{AppStateData, HostMode, PhaseAuthMethod, PhaseConfig, PHASE_CLOUD_HOST};
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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEnvInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub identity_key: String,
    #[serde(default)]
    pub wrapped_seed: String,
    #[serde(default)]
    pub wrapped_salt: String,
    #[serde(default)]
    pub var_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseAppInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub environments: Vec<PhaseEnvInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PhaseCliStatus {
    pub installed: bool,
    pub binary_path: Option<String>,
    pub version: Option<String>,
    pub logged_in: bool,
    pub host: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub account_id: Option<String>,
}

impl PhaseCliStatus {
    pub fn summary_badge(&self) -> String {
        if !self.installed {
            return "Not installed".to_string();
        }
        let ver = self
            .version
            .as_deref()
            .map(|v| format!(" v{}", v))
            .unwrap_or_default();
        if self.logged_in {
            let user = self
                .email
                .as_deref()
                .or(self.organization.as_deref())
                .unwrap_or("Authenticated");
            format!("Installed{} ({})", ver, user)
        } else {
            format!("Installed{} (Not logged in — run `phase auth`)", ver)
        }
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Locates the `phase` CLI binary on the machine without spawning a subprocess.
pub fn find_phase_binary() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("ENVMGR_PHASE_BIN") {
        let trimmed = custom.trim();
        if trimmed.is_empty() {
            return None;
        }
        let p = PathBuf::from(trimmed);
        if is_executable_file(&p) {
            return Some(p);
        }
        return None;
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("phase");
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    for fallback in ["/usr/bin/phase", "/usr/local/bin/phase"] {
        let p = PathBuf::from(fallback);
        if is_executable_file(&p) {
            return Some(p);
        }
    }

    None
}

fn phase_config_candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(custom) = std::env::var("ENVMGR_PHASE_CONFIG") {
        if !custom.trim().is_empty() {
            paths.push(PathBuf::from(custom.trim()));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let base = PathBuf::from(home).join(".phase");
        paths.push(base.join("secrets").join("config.json"));
        paths.push(base.join("config.json"));
    }
    paths
}

pub fn parse_phase_cli_config_json(content: &str, status: &mut PhaseCliStatus) {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };

    let default_user_id = val
        .get("default-user")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Some(users) = val.get("phase-users").and_then(|v| v.as_array()) {
        let chosen = if !default_user_id.is_empty() {
            users
                .iter()
                .find(|u| u.get("id").and_then(|v| v.as_str()) == Some(default_user_id))
                .or_else(|| users.first())
        } else {
            users.first()
        };

        if let Some(u) = chosen {
            if let Some(h) = u.get("host").and_then(|v| v.as_str()) {
                let clean = h.trim().trim_end_matches('/').to_string();
                if !clean.is_empty() {
                    status.host = Some(clean);
                }
            }
            if let Some(email) = u.get("email").and_then(|v| v.as_str()) {
                if !email.trim().is_empty() {
                    status.email = Some(email.trim().to_string());
                }
            }
            if let Some(org) = u.get("organization_name").and_then(|v| v.as_str()) {
                if !org.trim().is_empty() {
                    status.organization = Some(org.trim().to_string());
                }
            }
            if let Some(id) = u.get("id").and_then(|v| v.as_str()) {
                if !id.trim().is_empty() {
                    status.account_id = Some(id.trim().to_string());
                    status.logged_in = true;
                }
            }
        }
    }

    if status.host.is_none() {
        if let Some(h) = val.get("host").and_then(|v| v.as_str()) {
            let clean = h.trim().trim_end_matches('/').to_string();
            if !clean.is_empty() {
                status.host = Some(clean);
            }
        }
    }
}

/// Fast, non-blocking detection of the installed Phase CLI and local configuration.
pub fn detect_phase_cli() -> PhaseCliStatus {
    let mut status = PhaseCliStatus::default();
    let Some(bin_path) = find_phase_binary() else {
        return status;
    };

    status.installed = true;
    status.binary_path = Some(bin_path.to_string_lossy().into_owned());

    for cfg_path in phase_config_candidate_paths() {
        if let Ok(content) = std::fs::read_to_string(&cfg_path) {
            parse_phase_cli_config_json(&content, &mut status);
            if status.logged_in || status.host.is_some() {
                break;
            }
        }
    }

    if let Ok(env_host) = std::env::var("PHASE_HOST") {
        if !env_host.trim().is_empty() {
            status.host = Some(env_host.trim().trim_end_matches('/').to_string());
        }
    }

    if let Ok(svc_tok) = std::env::var("PHASE_SERVICE_TOKEN") {
        if !svc_tok.trim().is_empty() {
            status.logged_in = true;
            if status.host.is_none() {
                status.host = Some(PHASE_CLOUD_HOST.to_string());
            }
        }
    }

    status
}

/// Detailed CLI detection that also queries `phase --version` (and `phase users whoami` if needed).
pub fn detect_phase_cli_detailed() -> PhaseCliStatus {
    let mut status = detect_phase_cli();
    let Some(bin) = status.binary_path.clone() else {
        return status;
    };

    if let Ok(out) = Command::new(&bin).arg("--version").output() {
        if out.status.success() {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !ver.is_empty() {
                status.version = Some(ver);
            }
        }
    }

    if !status.logged_in {
        if let Ok(out) = clean_phase_command(&bin).args(["users", "whoami"]).output() {
            if out.status.success() {
                status.logged_in = true;
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if let Some((_, val)) = line.split_once("Email:") {
                        let v = val.trim();
                        if !v.is_empty() {
                            status.email = Some(v.to_string());
                        }
                    } else if let Some((_, val)) = line.split_once("Organization:") {
                        let v = val.trim();
                        if !v.is_empty() {
                            status.organization = Some(v.to_string());
                        }
                    } else if let Some((_, val)) = line.split_once("Host:") {
                        let v = val.trim().trim_end_matches('/');
                        if !v.is_empty() {
                            status.host = Some(v.to_string());
                        }
                    }
                }
            }
        }
    }

    status
}

/// Helper to read local Phase CLI host if user wants to prefill it.
pub fn try_detect_local_phase_cli_host() -> Option<(HostMode, String)> {
    let cli = detect_phase_cli();
    let host = cli.host?;
    let trimmed = host.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == PHASE_CLOUD_HOST {
        Some((HostMode::Cloud, String::new()))
    } else {
        Some((HostMode::SelfHosted, trimmed.to_string()))
    }
}

/// Builds a `Command` for `phase` CLI with AI-agent detection env vars cleared
/// so `phase` CLI never redacts secret values with `[REDACTED]`.
fn clean_phase_command(bin: &str) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("CLAUDECODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("CODEX")
        .env_remove("OPENCODE")
        .env_remove("AGENT");
    cmd
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
    path: String,
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

#[derive(Debug, Deserialize)]
struct CliAppEntry {
    id: String,
    name: String,
    #[serde(default)]
    environments: Vec<CliEnvEntry>,
}

#[derive(Debug, Deserialize)]
struct CliEnvEntry {
    id: String,
    name: String,
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
}

pub fn parse_cli_apps_json(raw_json: &str) -> Result<Vec<PhaseAppInfo>, String> {
    let entries: Vec<CliAppEntry> = serde_json::from_str(raw_json.trim())
        .map_err(|e| format!("Failed to parse `phase apps list` JSON output: {}", e))?;
    Ok(entries
        .into_iter()
        .map(|a| PhaseAppInfo {
            id: a.id,
            name: a.name,
            environments: a
                .environments
                .into_iter()
                .map(|e| PhaseEnvInfo {
                    id: e.id,
                    name: e.name,
                    identity_key: String::new(),
                    wrapped_seed: String::new(),
                    wrapped_salt: String::new(),
                    var_count: None,
                })
                .collect(),
        })
        .collect())
}

pub fn parse_cli_secrets_json(raw_json: &str) -> Result<Vec<(String, String)>, String> {
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw_json.trim())
        .map_err(|e| format!("Failed to parse `phase secrets export` JSON: {}", e))?;
    let mut pairs: Vec<(String, String)> = map
        .into_iter()
        .map(|(k, v)| {
            let val_str = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            (k, val_str)
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(pairs)
}

fn fetch_apps_and_envs_via_cli() -> Result<Vec<PhaseAppInfo>, String> {
    let Some(bin) = find_phase_binary() else {
        return Err("Phase CLI binary (`phase`) not found in PATH.".to_string());
    };
    let bin_str = bin.to_string_lossy().into_owned();
    let out = clean_phase_command(&bin_str)
        .args(["apps", "list"])
        .output()
        .map_err(|e| format!("Failed to execute `phase apps list`: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("Phase CLI error: {}", detail));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_cli_apps_json(&stdout)
}

fn fetch_secrets_for_env_via_cli(
    app_id: &str,
    env_id: &str,
    env_name_hint: Option<&str>,
    export_all_paths: bool,
) -> Result<Vec<(String, String)>, String> {
    let Some(bin) = find_phase_binary() else {
        return Err("Phase CLI binary (`phase`) not found in PATH.".to_string());
    };
    let bin_str = bin.to_string_lossy().into_owned();

    let resolved_env_name = match env_name_hint {
        Some(name) if !name.trim().is_empty() => name.trim().to_string(),
        _ => {
            let apps = fetch_apps_and_envs_via_cli()?;
            apps.into_iter()
                .filter(|a| app_id.is_empty() || a.id == app_id)
                .flat_map(|a| a.environments)
                .find(|e| e.id == env_id || e.name.eq_ignore_ascii_case(env_id))
                .map(|e| e.name)
                .unwrap_or_else(|| env_id.to_string())
        }
    };

    let mut cmd = clean_phase_command(&bin_str);
    cmd.args(["secrets", "export"]);
    if !app_id.trim().is_empty() {
        cmd.args(["--app-id", app_id.trim()]);
    }
    cmd.args(["--env", &resolved_env_name, "--format", "json"]);
    if export_all_paths {
        cmd.args(["--path", ""]);
    } else {
        cmd.args(["--path", "/"]);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("Failed to execute `phase secrets export`: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("Phase CLI export failed: {}", detail));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_cli_secrets_json(&stdout)
}

/// Fetches the list of accessible Applications and Environments from Phase.dev
/// using either the installed Phase CLI or the configured API Token.
pub fn fetch_apps_and_envs(config: &PhaseConfig) -> Result<Vec<PhaseAppInfo>, String> {
    if config.auth_method == PhaseAuthMethod::Cli {
        return fetch_apps_and_envs_via_cli();
    }

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
                    var_count: None,
                })
                .collect(),
        })
        .collect();

    Ok(apps)
}

/// Populates variable counts for all environments within a single Phase application.
pub fn populate_app_env_var_counts(config: &PhaseConfig, app: &mut PhaseAppInfo) {
    if config.auth_method == PhaseAuthMethod::Cli {
        let Some(bin) = find_phase_binary() else {
            for env in &mut app.environments {
                env.var_count = Some(0);
            }
            return;
        };
        let bin_str = bin.to_string_lossy().into_owned();
        for env in &mut app.environments {
            let out = clean_phase_command(&bin_str)
                .args([
                    "secrets", "export",
                    "--app-id", &app.id,
                    "--env", &env.name,
                    "--format", "json",
                    "--path", "",
                ])
                .output();
            if let Ok(out) = out {
                if out.status.success() {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(stdout.trim()) {
                        env.var_count = Some(map.len());
                        continue;
                    }
                }
            }
            env.var_count = Some(0);
        }
    } else if config.is_configured() {
        for env in &mut app.environments {
            match fetch_secrets_for_env(config, &app.id, &env.id, Some(&env.name), true) {
                Ok(vars) => env.var_count = Some(vars.len()),
                Err(_) => env.var_count = Some(0),
            }
        }
    }
}

/// Fetches and decrypts all secrets for a given App and Environment from Phase.dev.
pub fn fetch_secrets_for_env(
    config: &PhaseConfig,
    app_id: &str,
    env_id: &str,
    env_name_hint: Option<&str>,
    export_all_paths: bool,
) -> Result<Vec<(String, String)>, String> {
    if config.auth_method == PhaseAuthMethod::Cli {
        return fetch_secrets_for_env_via_cli(app_id, env_id, env_name_hint, export_all_paths);
    }

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
        if !export_all_paths && !item.path.is_empty() && item.path != "/" {
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

    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(pairs)
}

/// Synchronizes Phase.dev collections in `state`.
/// If `only_collection_idx` is `Some(idx)`, syncs only that collection; otherwise syncs all eligible Phase collections.
/// Returns `(synced_collection_count, total_vars_fetched)`.
pub fn sync_phase_collections(
    state: &mut AppStateData,
    only_collection_idx: Option<usize>,
) -> Result<(usize, usize), String> {
    if !state.phase.is_configured() {
        return Err("Phase.dev authentication is not configured.".to_string());
    }

    let only_enabled = state.settings.sync_only_enabled_collections && only_collection_idx.is_none();

    let targets: Vec<(usize, crate::model::PhaseBinding)> = state
        .collections
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| {
            if let Some(target_idx) = only_collection_idx {
                if idx != target_idx {
                    return None;
                }
            } else if only_enabled && !c.enabled {
                return None;
            }
            c.phase_binding.clone().map(|b| (idx, b))
        })
        .collect();

    if targets.is_empty() {
        return Ok((0, 0));
    }

    let mut synced_collections = 0;
    let mut total_vars = 0;

    for (idx, binding) in targets {
        let fetched = fetch_secrets_for_env(
            &state.phase,
            &binding.app_id,
            &binding.env_id,
            Some(&binding.env_name),
            binding.export_all_paths,
        )?;
        total_vars += fetched.len();
        if let Some(coll) = state.collections.get_mut(idx) {
            coll.set_phase_vars(binding, fetched);
            synced_collections += 1;
        }
    }

    state.last_phase_sync_epoch = AppStateData::current_epoch_secs();
    Ok((synced_collections, total_vars))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_roundtrip_and_env_keypair() {
        let seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let (server_pub_hex, server_priv_hex) =
            generate_env_keypair(seed_hex).expect("should derive keypair");

        let client_seed = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let (client_pub_hex, client_priv_hex) =
            generate_env_keypair(client_seed).expect("should derive client keypair");

        let server_pk = decode_hex_32(&server_pub_hex, "srv_pk").unwrap();
        let client_pk = decode_hex_32(&client_pub_hex, "cli_pk").unwrap();
        let client_sk = decode_hex_32(&client_priv_hex, "cli_sk").unwrap();

        let shared = x25519_dalek::x25519(client_sk, server_pk);
        let mut h = Blake2b512::new();
        Digest::update(&mut h, shared);
        Digest::update(&mut h, client_pk);
        Digest::update(&mut h, server_pk);
        let digest = h.finalize();
        let mut client_tx = [0u8; 32];
        client_tx.copy_from_slice(&digest[32..64]);

        let nonce_bytes = [7u8; 24];
        let cipher = XChaCha20Poly1305::new((&client_tx).into());
        let mut ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                b"DATABASE_URL=postgres://localhost/db".as_ref(),
            )
            .unwrap();
        ct.extend_from_slice(&nonce_bytes);
        let ph_ciphertext = format!("ph:v1:{}:{}", client_pub_hex, BASE64.encode(&ct));

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

    #[test]
    fn test_parse_phase_cli_config_and_outputs() {
        let sample_cfg = r#"{
            "default-user": "user-2",
            "phase-users": [
                {
                    "id": "user-1",
                    "email": "one@example.com",
                    "organization_name": "OrgOne",
                    "host": "https://console.phase.dev"
                },
                {
                    "id": "user-2",
                    "email": "two@example.com",
                    "organization_name": "OrgTwo",
                    "host": "https://phase.internal.example.com/"
                }
            ]
        }"#;
        let mut st = PhaseCliStatus::default();
        parse_phase_cli_config_json(sample_cfg, &mut st);
        assert!(st.logged_in);
        assert_eq!(st.account_id.as_deref(), Some("user-2"));
        assert_eq!(st.email.as_deref(), Some("two@example.com"));
        assert_eq!(st.organization.as_deref(), Some("OrgTwo"));
        assert_eq!(
            st.host.as_deref(),
            Some("https://phase.internal.example.com")
        );

        let apps_json = r#"[
            {
                "id": "app-123",
                "name": "my-service",
                "environments": [
                    { "id": "env-dev", "name": "Development", "env_type": "DEV" },
                    { "id": "env-prod", "name": "Production", "env_type": "PROD" }
                ]
            }
        ]"#;
        let apps = parse_cli_apps_json(apps_json).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, "app-123");
        assert_eq!(apps[0].name, "my-service");
        assert_eq!(apps[0].environments.len(), 2);
        assert_eq!(apps[0].environments[1].name, "Production");

        let secrets_json = r#"{
            "Z_KEY": "z_val",
            "A_KEY": "a_val"
        }"#;
        let pairs = parse_cli_secrets_json(secrets_json).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("A_KEY".to_string(), "a_val".to_string()),
                ("Z_KEY".to_string(), "z_val".to_string()),
            ]
        );
    }
}
