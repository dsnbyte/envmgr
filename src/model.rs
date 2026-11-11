use crate::phase::detect_phase_cli;
use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PHASE_CLOUD_HOST: &str = "https://console.phase.dev";
pub const MIN_AUTO_SYNC_INTERVAL_MINS: u64 = 1;
pub const DEFAULT_AUTO_SYNC_INTERVAL_MINS: u64 = 30;

/// Hardcoded master key phrase compiled directly into the binary.
/// Changing this key requires modifying the source code and rebuilding the program.
pub const HARDCODED_MASTER_KEY: &[u8] = b"envmgr-hardcoded-master-key-v1-change-in-source";

fn derived_cipher_key() -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    Digest::update(&mut hasher, b"envmgr-state-aead-key-v1:");
    Digest::update(&mut hasher, HARDCODED_MASTER_KEY);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

/// Encrypts raw bytes using ChaCha20-Poly1305 (12-byte random nonce prepended to ciphertext+tag).
pub fn encrypt_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = derived_cipher_key();
    let cipher = ChaCha20Poly1305::new((&key).into());

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate random nonce: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed".to_string())?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

/// Decrypts a blob (12-byte nonce + ciphertext + 16-byte Poly1305 tag) back into raw bytes.
pub fn decrypt_bytes(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 + 16 {
        return Err("Encrypted payload is too short".to_string());
    }
    let key = derived_cipher_key();
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| "Decryption failed (hardcoded key mismatch or corrupted state file)".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostMode {
    #[default]
    Cloud,
    SelfHosted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAuthMethod {
    #[default]
    Token,
    Cli,
}

impl PhaseAuthMethod {
    pub fn label(&self) -> &'static str {
        match self {
            PhaseAuthMethod::Token => "API Token",
            PhaseAuthMethod::Cli => "Phase CLI",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseConfig {
    #[serde(default)]
    pub auth_method: PhaseAuthMethod,
    #[serde(default)]
    pub host_mode: HostMode,
    #[serde(default)]
    pub custom_url: String,
    #[serde(default)]
    pub pat_token: String,
}

impl Default for PhaseConfig {
    fn default() -> Self {
        let cli = detect_phase_cli();
        let (host_mode, custom_url) = match cli.host.as_deref() {
            Some(h) if !h.is_empty() && h != PHASE_CLOUD_HOST => {
                (HostMode::SelfHosted, h.to_string())
            }
            _ => (HostMode::Cloud, String::new()),
        };
        let auth_method = if cli.installed {
            PhaseAuthMethod::Cli
        } else {
            PhaseAuthMethod::Token
        };
        Self {
            auth_method,
            host_mode,
            custom_url,
            pat_token: String::new(),
        }
    }
}

impl PhaseConfig {
    pub fn effective_host(&self) -> String {
        if self.auth_method == PhaseAuthMethod::Cli {
            let cli = detect_phase_cli();
            if let Some(host) = cli.host {
                if !host.trim().is_empty() {
                    return host.trim().trim_end_matches('/').to_string();
                }
            }
        }
        match self.host_mode {
            HostMode::Cloud => PHASE_CLOUD_HOST.to_string(),
            HostMode::SelfHosted => {
                let trimmed = self.custom_url.trim().trim_end_matches('/');
                if trimmed.is_empty() {
                    PHASE_CLOUD_HOST.to_string()
                } else if let Some(stripped) = trimmed.strip_suffix("/service/public") {
                    stripped.to_string()
                } else {
                    trimmed.to_string()
                }
            }
        }
    }

    pub fn is_configured(&self) -> bool {
        match self.auth_method {
            PhaseAuthMethod::Cli => {
                let cli = detect_phase_cli();
                cli.installed && cli.logged_in
            }
            PhaseAuthMethod::Token => {
                !self.pat_token.trim().is_empty()
                    && (self.host_mode == HostMode::Cloud || !self.custom_url.trim().is_empty())
            }
        }
    }

    /// Automatically switches to CLI auth if no token is configured and the Phase CLI is installed.
    pub fn auto_detect_cli(&mut self) {
        let cli = detect_phase_cli();
        if self.pat_token.trim().is_empty() && cli.installed {
            self.auth_method = PhaseAuthMethod::Cli;
            if let Some(host) = cli.host {
                let trimmed = host.trim().trim_end_matches('/');
                if trimmed.is_empty() || trimmed == PHASE_CLOUD_HOST {
                    self.host_mode = HostMode::Cloud;
                } else {
                    self.host_mode = HostMode::SelfHosted;
                    if self.custom_url.trim().is_empty() {
                        self.custom_url = trimmed.to_string();
                    }
                }
            }
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_sync_interval_mins() -> u64 {
    DEFAULT_AUTO_SYNC_INTERVAL_MINS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    /// Automatically synchronize Phase.dev profiles at a configurable interval (default: true).
    #[serde(default = "default_true")]
    pub auto_sync_enabled: bool,
    /// Interval in minutes for automatic Phase.dev sync (default: 30, minimum: 1).
    #[serde(default = "default_sync_interval_mins")]
    pub auto_sync_interval_mins: u64,
    /// When auto-syncing, only sync enabled Phase.dev profiles (default: true).
    #[serde(default = "default_true")]
    pub sync_only_enabled_profiles: bool,
    /// Export secrets across all Phase paths (`--path ""`) instead of root `/` only (default: true).
    #[serde(default = "default_true")]
    pub phase_export_all_paths: bool,
    /// Mask secret values by default when launching the TUI (default: true).
    #[serde(default = "default_true")]
    pub mask_secrets_by_default: bool,
    /// Insert newly created profiles at top priority (#1) instead of bottom (default: true).
    #[serde(default = "default_true")]
    pub insert_new_profile_at_top: bool,
    /// Enable live shell prompt auto-reload hook in ~/.bashrc (default: true).
    #[serde(default = "default_true")]
    pub shell_prompt_hook: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_sync_enabled: true,
            auto_sync_interval_mins: DEFAULT_AUTO_SYNC_INTERVAL_MINS,
            sync_only_enabled_profiles: true,
            phase_export_all_paths: true,
            mask_secrets_by_default: true,
            insert_new_profile_at_top: true,
            shell_prompt_hook: true,
        }
    }
}

impl AppSettings {
    pub fn clamp_interval(mins: u64) -> u64 {
        mins.clamp(MIN_AUTO_SYNC_INTERVAL_MINS, 1440)
    }

    pub fn effective_interval_mins(&self) -> u64 {
        Self::clamp_interval(self.auto_sync_interval_mins)
    }

    pub fn set_interval_mins(&mut self, mins: u64) {
        self.auto_sync_interval_mins = Self::clamp_interval(mins);
    }

    pub fn normalize(&mut self) {
        self.auto_sync_interval_mins = Self::clamp_interval(self.auto_sync_interval_mins);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VarSource {
    Custom,
    Phase {
        app_name: String,
        env_name: String,
    },
}

impl VarSource {
    pub fn label(&self) -> String {
        match self {
            VarSource::Custom => "Custom".to_string(),
            VarSource::Phase { app_name, env_name } => format!("Phase ({}/{})", app_name, env_name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
    pub source: VarSource,
}

pub fn compute_prefix_suffix(value: &str) -> (String, String) {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() >= 6 {
        let prefix: String = chars[..3].iter().collect();
        let suffix: String = chars[chars.len() - 3..].iter().collect();
        (prefix, suffix)
    } else {
        (String::new(), String::new())
    }
}

impl EnvVar {
    pub fn new(key: String, value: String, source: VarSource) -> Self {
        let (prefix, suffix) = compute_prefix_suffix(&value);
        Self {
            key,
            value,
            prefix,
            suffix,
            source,
        }
    }

    pub fn set_value(&mut self, new_val: String) {
        let (prefix, suffix) = compute_prefix_suffix(&new_val);
        self.value = new_val;
        self.prefix = prefix;
        self.suffix = suffix;
    }

    pub fn masked_display(&self, show_raw: bool) -> String {
        if show_raw {
            self.value.clone()
        } else if self.value.is_empty() {
            "<empty>".to_string()
        } else if !self.prefix.is_empty() && !self.suffix.is_empty() {
            format!("{}••••{}", self.prefix, self.suffix)
        } else {
            "••••••••".to_string()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseBinding {
    pub app_id: String,
    pub app_name: String,
    pub env_id: String,
    pub env_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub enabled: bool,
    pub phase_binding: Option<PhaseBinding>,
    pub vars: Vec<EnvVar>,
}

impl Profile {
    pub fn new_custom(name: String) -> Self {
        Self {
            name,
            enabled: true,
            phase_binding: None,
            vars: Vec::new(),
        }
    }

    pub fn new_phase(name: String, binding: PhaseBinding, fetched: Vec<(String, String)>) -> Self {
        let mut prof = Self {
            name,
            enabled: true,
            phase_binding: Some(binding.clone()),
            vars: Vec::new(),
        };
        prof.set_phase_vars(binding, fetched);
        prof
    }

    pub fn is_phase(&self) -> bool {
        self.phase_binding.is_some()
    }

    pub fn is_custom(&self) -> bool {
        self.phase_binding.is_none()
    }

    pub fn source_label(&self) -> String {
        match &self.phase_binding {
            Some(b) => format!("Phase ({}/{})", b.app_name, b.env_name),
            None => "Custom".to_string(),
        }
    }

    /// Replaces the profile's variables exclusively with Phase.dev variables for the bound app/env.
    pub fn set_phase_vars(&mut self, binding: PhaseBinding, fetched: Vec<(String, String)>) {
        let app_name = binding.app_name.clone();
        let env_name = binding.env_name.clone();
        self.phase_binding = Some(binding);
        self.vars.clear();
        for (k, v) in fetched {
            self.vars.push(EnvVar::new(
                k,
                v,
                VarSource::Phase {
                    app_name: app_name.clone(),
                    env_name: env_name.clone(),
                },
            ));
        }
    }

    /// Upserts a custom variable if and only if this profile is a Custom profile.
    /// Returns an error if the profile is bound to Phase.dev.
    pub fn upsert_custom_var(&mut self, key: String, value: String) -> Result<(), String> {
        if self.is_phase() {
            return Err(format!(
                "Profile '{}' is synchronized with Phase.dev; custom variables cannot be mixed.",
                self.name
            ));
        }
        AppStateData::upsert_custom_var(&mut self.vars, key, value);
        Ok(())
    }

    /// Ensures the profile contains variables from only one data source matching its profile type.
    pub fn sanitize_single_source(&mut self) {
        if let Some(binding) = &self.phase_binding {
            let app_name = binding.app_name.clone();
            let env_name = binding.env_name.clone();
            self.vars.retain(|v| matches!(v.source, VarSource::Phase { .. }));
            for v in &mut self.vars {
                v.source = VarSource::Phase {
                    app_name: app_name.clone(),
                    env_name: env_name.clone(),
                };
            }
        } else {
            self.vars.retain(|v| matches!(v.source, VarSource::Custom));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveVar {
    pub key: String,
    pub value: String,
    pub prefix: String,
    pub suffix: String,
    pub winning_owner: String,
    pub source_label: String,
}

impl EffectiveVar {
    #[cfg(test)]
    pub fn new(key: String, value: String, winning_owner: String, source_label: String) -> Self {
        let (prefix, suffix) = compute_prefix_suffix(&value);
        Self {
            key,
            value,
            prefix,
            suffix,
            winning_owner,
            source_label,
        }
    }

    pub fn masked_display(&self, show_raw: bool) -> String {
        if show_raw {
            self.value.clone()
        } else if self.value.is_empty() {
            "<empty>".to_string()
        } else if !self.prefix.is_empty() && !self.suffix.is_empty() {
            format!("{}••••{}", self.prefix, self.suffix)
        } else {
            "••••••••".to_string()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateData {
    #[serde(default)]
    pub phase: PhaseConfig,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub last_phase_sync_epoch: u64,
}

impl Default for AppStateData {
    fn default() -> Self {
        Self {
            phase: PhaseConfig::default(),
            profiles: vec![Profile::new_custom("default".to_string())],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        }
    }
}

impl AppStateData {
    pub fn current_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn config_dir() -> PathBuf {
        if let Ok(custom) = std::env::var("ENVMGR_CONFIG_DIR") {
            if !custom.trim().is_empty() {
                return PathBuf::from(custom);
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config").join("envmgr")
    }

    pub fn state_file_path() -> PathBuf {
        Self::config_dir().join("state.enc")
    }

    pub fn load() -> Self {
        Self::load_from_dir(&Self::config_dir())
    }

    pub fn load_from_dir(dir: &Path) -> Self {
        let state_file = dir.join("state.enc");
        let Ok(encrypted) = fs::read(&state_file) else {
            return Self::default();
        };
        let Ok(decrypted) = decrypt_bytes(&encrypted) else {
            return Self::default();
        };
        let mut state: Self = serde_json::from_slice(&decrypted).unwrap_or_default();
        state.settings.normalize();
        state.phase.auto_detect_cli();
        for prof in &mut state.profiles {
            prof.sanitize_single_source();
            for var in &mut prof.vars {
                if var.prefix.is_empty() && var.suffix.is_empty() && !var.value.is_empty() {
                    let (p, s) = compute_prefix_suffix(&var.value);
                    var.prefix = p;
                    var.suffix = s;
                }
            }
        }
        state
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to_dir(&Self::config_dir())
    }

    pub fn save_to_dir(&self, dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;

        let json_bytes = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;
        let encrypted = encrypt_bytes(&json_bytes)?;

        let state_file = dir.join("state.enc");
        let tmp_file = dir.join("state.enc.tmp");
        fs::write(&tmp_file, &encrypted)
            .map_err(|e| format!("Failed to write temporary state file: {}", e))?;
        fs::rename(&tmp_file, &state_file)
            .map_err(|e| format!("Failed to commit encrypted state file: {}", e))?;

        Ok(())
    }

    /// Computes the final effective environment variables.
    /// Rules:
    /// 1. Only enabled profiles contribute variables.
    /// 2. Among enabled profiles, the profile highest in the list (smallest index, e.g. #1 at top) wins!
    pub fn compute_effective_vars(&self) -> Vec<EffectiveVar> {
        let mut map: HashMap<String, EffectiveVar> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        // Apply enabled profiles from bottom to top so the topmost enabled profile overwrites lower ones
        for profile in self.profiles.iter().rev() {
            if !profile.enabled {
                continue;
            }
            let owner = profile.name.clone();
            let prof_source = profile.source_label();
            for var in &profile.vars {
                if !map.contains_key(&var.key) {
                    order.push(var.key.clone());
                }
                map.insert(
                    var.key.clone(),
                    EffectiveVar {
                        key: var.key.clone(),
                        value: var.value.clone(),
                        prefix: var.prefix.clone(),
                        suffix: var.suffix.clone(),
                        winning_owner: owner.clone(),
                        source_label: prof_source.clone(),
                    },
                );
            }
        }

        order
            .into_iter()
            .filter_map(|k| map.remove(&k))
            .collect()
    }

    pub fn upsert_custom_var(target: &mut Vec<EnvVar>, key: String, value: String) {
        target.retain(|v| matches!(v.source, VarSource::Custom));
        if let Some(existing) = target.iter_mut().find(|v| v.key == key) {
            existing.set_value(value);
            existing.source = VarSource::Custom;
        } else {
            target.push(EnvVar::new(key, value, VarSource::Custom));
        }
    }

    /// Checks whether automatic Phase.dev sync is due at `now_epoch` (seconds).
    pub fn is_auto_sync_due(&self, now_epoch: u64) -> bool {
        if !self.settings.auto_sync_enabled || !self.phase.is_configured() {
            return false;
        }
        let has_eligible_profile = self.profiles.iter().any(|p| {
            p.is_phase() && (!self.settings.sync_only_enabled_profiles || p.enabled)
        });
        if !has_eligible_profile {
            return false;
        }
        let interval_secs = self.settings.effective_interval_mins().saturating_mul(60);
        now_epoch.saturating_sub(self.last_phase_sync_epoch) >= interval_secs
    }
}

pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_bytes_roundtrip() {
        let secret = b"super-secret-value-!@#$%^&*()_+-=";
        let encrypted = encrypt_bytes(secret).expect("should encrypt");
        assert!(!encrypted.windows(secret.len()).any(|w| w == secret));
        let decrypted = decrypt_bytes(&encrypted).expect("should decrypt");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_prefix_suffix_and_masked_display() {
        let (p, s) = compute_prefix_suffix("sk-123456789xyz");
        assert_eq!(p, "sk-");
        assert_eq!(s, "xyz");

        let var = EnvVar::new("API_KEY".to_string(), "sk-123456789xyz".to_string(), VarSource::Custom);
        assert_eq!(var.prefix, "sk-");
        assert_eq!(var.suffix, "xyz");
        assert_eq!(var.masked_display(false), "sk-••••xyz");
        assert_eq!(var.masked_display(true), "sk-123456789xyz");

        let short_var = EnvVar::new("SHORT".to_string(), "12345".to_string(), VarSource::Custom);
        assert_eq!(short_var.prefix, "");
        assert_eq!(short_var.suffix, "");
        assert_eq!(short_var.masked_display(false), "••••••••");
        assert_eq!(short_var.masked_display(true), "12345");

        let empty_var = EnvVar::new("EMPTY".to_string(), "".to_string(), VarSource::Custom);
        assert_eq!(empty_var.masked_display(false), "<empty>");
    }

    #[test]
    fn test_encrypted_state_file_never_stores_plaintext_on_disk() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("envmgr_state_test_{}", uniq));
        fs::create_dir_all(&temp_dir).unwrap();

        let plaintext_key = "SUPER_SENSITIVE_KEY_NAME";
        let plaintext_secret_1 = "MY_SUPER_SECRET_DB_PASSWORD_99999";
        let plaintext_secret_2 = "PHASE_SECRET_TOKEN_VALUE_88888";

        let state = AppStateData {
            phase: PhaseConfig {
                auth_method: PhaseAuthMethod::Token,
                host_mode: HostMode::Cloud,
                custom_url: String::new(),
                pat_token: "pss_user:v1:secret_pat_token_12345".to_string(),
            },
            profiles: vec![
                Profile {
                    name: "default".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar::new(
                        plaintext_key.to_string(),
                        plaintext_secret_1.to_string(),
                        VarSource::Custom,
                    )],
                },
                Profile {
                    name: "prod_profile_secret".to_string(),
                    enabled: true,
                    phase_binding: Some(PhaseBinding {
                        app_id: "app-1".to_string(),
                        app_name: "my-app".to_string(),
                        env_id: "env-1".to_string(),
                        env_name: "production".to_string(),
                    }),
                    vars: vec![EnvVar::new(
                        "API_TOKEN".to_string(),
                        plaintext_secret_2.to_string(),
                        VarSource::Phase {
                            app_name: "my-app".to_string(),
                            env_name: "production".to_string(),
                        },
                    )],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        state.save_to_dir(&temp_dir).expect("should save state.enc");

        let raw_bytes = fs::read(temp_dir.join("state.enc")).expect("state.enc should exist");
        assert!(
            !raw_bytes
                .windows(plaintext_key.len())
                .any(|w| w == plaintext_key.as_bytes()),
            "Variable key name must not appear in plaintext on disk"
        );
        assert!(
            !raw_bytes
                .windows(plaintext_secret_1.len())
                .any(|w| w == plaintext_secret_1.as_bytes()),
            "Plaintext secret 1 must not appear on disk"
        );
        assert!(
            !raw_bytes
                .windows(plaintext_secret_2.len())
                .any(|w| w == plaintext_secret_2.as_bytes()),
            "Plaintext secret 2 must not appear on disk"
        );
        assert!(
            !raw_bytes
                .windows(b"secret_pat_token_12345".len())
                .any(|w| w == b"secret_pat_token_12345"),
            "PAT token must not appear in plaintext on disk"
        );

        let loaded = AppStateData::load_from_dir(&temp_dir);
        assert_eq!(loaded.phase.pat_token, "pss_user:v1:secret_pat_token_12345");
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(loaded.profiles[0].vars[0].key, plaintext_key);
        assert_eq!(loaded.profiles[0].vars[0].value, plaintext_secret_1);
        assert_eq!(loaded.profiles[0].vars[0].prefix, "MY_");
        assert_eq!(loaded.profiles[0].vars[0].suffix, "999");
        assert_eq!(loaded.profiles[1].vars[0].value, plaintext_secret_2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_single_source_per_profile_never_mixes() {
        let binding = PhaseBinding {
            app_id: "app1".to_string(),
            app_name: "Backend".to_string(),
            env_id: "env1".to_string(),
            env_name: "Prod".to_string(),
        };
        let mut phase_prof = Profile::new_phase(
            "phase_prod".to_string(),
            binding.clone(),
            vec![("DB_URL".to_string(), "postgres://prod".to_string())],
        );
        assert!(phase_prof.is_phase());
        assert!(!phase_prof.is_custom());
        assert!(phase_prof
            .upsert_custom_var("CUSTOM_KEY".to_string(), "123".to_string())
            .is_err());
        assert_eq!(phase_prof.vars.len(), 1);

        // Even if corrupted in memory and sanitized, custom vars are stripped from Phase profile
        phase_prof.vars.push(EnvVar::new(
            "MIXED".to_string(),
            "bad".to_string(),
            VarSource::Custom,
        ));
        phase_prof.sanitize_single_source();
        assert_eq!(phase_prof.vars.len(), 1);
        assert_eq!(phase_prof.vars[0].key, "DB_URL");

        // Custom profile strips any Phase vars on sanitize
        let mut custom_prof = Profile::new_custom("local_dev".to_string());
        custom_prof
            .upsert_custom_var("LOCAL_PORT".to_string(), "8080".to_string())
            .unwrap();
        custom_prof.vars.push(EnvVar::new(
            "PHASE_LEAK".to_string(),
            "secret".to_string(),
            VarSource::Phase {
                app_name: "Backend".to_string(),
                env_name: "Prod".to_string(),
            },
        ));
        custom_prof.sanitize_single_source();
        assert_eq!(custom_prof.vars.len(), 1);
        assert_eq!(custom_prof.vars[0].key, "LOCAL_PORT");
    }

    #[test]
    fn test_settings_defaults_and_interval_clamping() {
        let mut settings = AppSettings::default();
        assert!(settings.auto_sync_enabled);
        assert_eq!(settings.auto_sync_interval_mins, 30);

        settings.set_interval_mins(0);
        assert_eq!(settings.auto_sync_interval_mins, 1);
        assert_eq!(settings.effective_interval_mins(), 1);

        settings.set_interval_mins(15);
        assert_eq!(settings.auto_sync_interval_mins, 15);
    }

    #[test]
    fn test_priority_top_profile_wins_over_lower() {
        let state = AppStateData {
            phase: PhaseConfig::default(),
            profiles: vec![
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "from_profile_satu".to_string(), VarSource::Custom),
                        EnvVar::new("B".to_string(), "b_from_satu".to_string(), VarSource::Custom),
                    ],
                },
                Profile {
                    name: "profile_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "from_profile_dua".to_string(), VarSource::Custom),
                        EnvVar::new("C".to_string(), "c_from_dua".to_string(), VarSource::Custom),
                    ],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        let effective = state.compute_effective_vars();
        let map: HashMap<_, _> = effective.into_iter().map(|v| (v.key.clone(), v)).collect();

        // Profile profile_satu wins over Profile profile_dua for key A
        assert_eq!(map["A"].value, "from_profile_satu");
        assert_eq!(map["A"].winning_owner, "profile_satu");
        assert_eq!(map["B"].value, "b_from_satu");
        assert_eq!(map["B"].winning_owner, "profile_satu");
        assert_eq!(map["C"].value, "c_from_dua");
        assert_eq!(map["C"].winning_owner, "profile_dua");
    }

    #[test]
    fn test_disabled_top_profile_falls_back_to_next_enabled() {
        let mut state = AppStateData {
            phase: PhaseConfig::default(),
            profiles: vec![
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: false,
                    phase_binding: None,
                    vars: vec![EnvVar::new("A".to_string(), "from_profile_satu".to_string(), VarSource::Custom)],
                },
                Profile {
                    name: "profile_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar::new("A".to_string(), "from_profile_dua".to_string(), VarSource::Custom)],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        let effective = state.compute_effective_vars();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].value, "from_profile_dua");

        state.profiles[1].enabled = false;
        let effective2 = state.compute_effective_vars();
        assert!(effective2.is_empty());
    }
}
