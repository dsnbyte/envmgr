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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    /// When syncing collections, only sync enabled collections (default: true).
    #[serde(default = "default_true", alias = "sync_only_enabled_profiles")]
    pub sync_only_enabled_collections: bool,
    /// Insert newly created collections at top priority (#1) instead of bottom (default: true).
    #[serde(default = "default_true", alias = "insert_new_profile_at_top")]
    pub insert_new_collection_at_top: bool,
    /// Enable live shell prompt auto-reload hook in ~/.bashrc (default: true).
    #[serde(default = "default_true")]
    pub shell_prompt_hook: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            sync_only_enabled_collections: true,
            insert_new_collection_at_top: true,
            shell_prompt_hook: true,
        }
    }
}

pub fn normalize_secret_path(path: &str) -> String {
    let segments: Vec<&str> = path
        .trim()
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn default_root_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseVarRef {
    pub app_id: String,
    pub app_name: String,
    pub env_id: String,
    pub env_name: String,
    #[serde(default = "default_root_path")]
    pub path: String,
    pub secret_key: String,
}

impl PhaseVarRef {
    pub fn normalized_path(&self) -> String {
        normalize_secret_path(&self.path)
    }

    pub fn reference_syntax(&self) -> String {
        let path = self.normalized_path();
        if path == "/" {
            format!(
                "${{{}::{}.{}}}",
                self.app_name, self.env_name, self.secret_key
            )
        } else {
            format!(
                "${{{}::{}.{}/{}}}",
                self.app_name, self.env_name, path, self.secret_key
            )
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
    pub source: VarSource,
    #[serde(default)]
    pub phase_ref: Option<PhaseVarRef>,
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
    #[allow(dead_code)]
    pub fn new(key: String, value: String, source: VarSource) -> Self {
        Self::with_comment(key, value, String::new(), source)
    }

    pub fn with_comment(key: String, value: String, comment: String, source: VarSource) -> Self {
        let (prefix, suffix) = compute_prefix_suffix(&value);
        Self {
            key,
            value,
            enabled: true,
            comment,
            prefix,
            suffix,
            source,
            phase_ref: None,
        }
    }

    pub fn with_phase_ref(
        key: String,
        value: String,
        comment: String,
        phase_ref: Option<PhaseVarRef>,
    ) -> Self {
        let (prefix, suffix) = compute_prefix_suffix(&value);
        Self {
            key,
            value,
            enabled: true,
            comment,
            prefix,
            suffix,
            source: VarSource::Custom,
            phase_ref,
        }
    }

    pub fn is_phase_synced(&self) -> bool {
        matches!(self.source, VarSource::Phase { .. }) || self.phase_ref.is_some()
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
    #[serde(default = "default_true")]
    pub export_all_paths: bool,
}

impl PhaseBinding {
    #[allow(dead_code)]
    pub fn new(
        app_id: impl Into<String>,
        app_name: impl Into<String>,
        env_id: impl Into<String>,
        env_name: impl Into<String>,
        export_all_paths: bool,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_name: app_name.into(),
            env_id: env_id.into(),
            env_name: env_name.into(),
            export_all_paths,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collection {
    pub name: String,
    pub enabled: bool,
    pub phase_binding: Option<PhaseBinding>,
    #[serde(default)]
    pub last_sync_epoch: Option<u64>,
    pub vars: Vec<EnvVar>,
}

impl Collection {
    pub fn new_custom(name: String) -> Self {
        Self {
            name,
            enabled: true,
            phase_binding: None,
            last_sync_epoch: None,
            vars: Vec::new(),
        }
    }

    pub fn new_phase(
        name: String,
        binding: PhaseBinding,
        fetched: Vec<(String, String, String)>,
    ) -> Self {
        let mut coll = Self {
            name,
            enabled: true,
            phase_binding: Some(binding.clone()),
            last_sync_epoch: Some(AppStateData::current_epoch_secs()),
            vars: Vec::new(),
        };
        coll.set_phase_vars(binding, fetched);
        coll
    }

    pub fn is_phase(&self) -> bool {
        self.phase_binding.is_some()
    }

    pub fn is_custom(&self) -> bool {
        self.phase_binding.is_none()
    }

    pub fn has_phase_vars(&self) -> bool {
        self.vars.iter().any(|v| v.phase_ref.is_some())
    }

    pub fn source_label(&self) -> String {
        match &self.phase_binding {
            Some(b) => format!("Phase ({}/{})", b.app_name, b.env_name),
            None => "Manual".to_string(),
        }
    }

    pub fn var_source_label(&self, var: &EnvVar) -> String {
        if let Some(pref) = &var.phase_ref {
            let p = pref.normalized_path();
            if p == "/" {
                format!("Phase ({}/{})", pref.app_name, pref.env_name)
            } else {
                format!("Phase ({}/{}{})", pref.app_name, pref.env_name, p)
            }
        } else {
            self.source_label()
        }
    }

    /// Replaces the collection's variables exclusively with Phase.dev variables for the bound app/env,
    /// preserving individual variable enabled/disabled states for matching keys.
    pub fn set_phase_vars(
        &mut self,
        binding: PhaseBinding,
        fetched: Vec<(String, String, String)>,
    ) {
        let app_name = binding.app_name.clone();
        let env_name = binding.env_name.clone();
        let prev_enabled: HashMap<String, bool> = self
            .vars
            .iter()
            .map(|v| (v.key.clone(), v.enabled))
            .collect();
        self.phase_binding = Some(binding);
        self.last_sync_epoch = Some(AppStateData::current_epoch_secs());
        self.vars.clear();
        for (k, v, c) in fetched {
            let enabled = prev_enabled.get(&k).copied().unwrap_or(true);
            let mut var = EnvVar::with_comment(
                k,
                v,
                c,
                VarSource::Phase {
                    app_name: app_name.clone(),
                    env_name: env_name.clone(),
                },
            );
            var.enabled = enabled;
            self.vars.push(var);
        }
    }

    /// Upserts a custom variable with an optional Phase.dev reference if and only if this collection is a Custom collection.
    /// Returns an error if the collection is bound to Phase.dev.
    pub fn upsert_custom_var_with_phase_ref(
        &mut self,
        key: String,
        value: String,
        comment: String,
        phase_ref: Option<PhaseVarRef>,
    ) -> Result<(), String> {
        if self.is_phase() {
            return Err(format!(
                "Collection '{}' is synchronized with Phase.dev; custom variables cannot be mixed.",
                self.name
            ));
        }
        AppStateData::upsert_custom_var_with_ref(&mut self.vars, key, value, comment, phase_ref);
        Ok(())
    }

    /// Ensures the collection contains variables from only one data source matching its collection type.
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
    #[serde(default, alias = "profiles")]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub last_phase_sync_epoch: u64,
}

impl Default for AppStateData {
    fn default() -> Self {
        Self {
            phase: PhaseConfig::default(),
            collections: vec![Collection::new_custom("default".to_string())],
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
        state.phase.auto_detect_cli();
        for coll in &mut state.collections {
            coll.sanitize_single_source();
            for var in &mut coll.vars {
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
    /// 1. Only enabled collections contribute variables (disabling a collection disables all its vars).
    /// 2. Within an enabled collection, only individually enabled variables are included.
    /// 3. Among enabled variables, the collection highest in the list (smallest index, e.g. #1 at top) wins!
    pub fn compute_effective_vars(&self) -> Vec<EffectiveVar> {
        let mut map: HashMap<String, EffectiveVar> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        // Apply enabled collections from bottom to top so the topmost enabled collection overwrites lower ones
        for collection in self.collections.iter().rev() {
            if !collection.enabled {
                continue;
            }
            let owner = collection.name.clone();
            for var in &collection.vars {
                if !var.enabled {
                    continue;
                }
                if !map.contains_key(&var.key) {
                    order.push(var.key.clone());
                }
                let source_label = collection.var_source_label(var);
                map.insert(
                    var.key.clone(),
                    EffectiveVar {
                        key: var.key.clone(),
                        value: var.value.clone(),
                        prefix: var.prefix.clone(),
                        suffix: var.suffix.clone(),
                        winning_owner: owner.clone(),
                        source_label,
                    },
                );
            }
        }

        order
            .into_iter()
            .filter_map(|k| map.remove(&k))
            .collect()
    }

    pub fn upsert_custom_var_with_ref(
        target: &mut Vec<EnvVar>,
        key: String,
        value: String,
        comment: String,
        phase_ref: Option<PhaseVarRef>,
    ) {
        target.retain(|v| matches!(v.source, VarSource::Custom));
        let comment = if comment.chars().count() > 100 {
            comment.chars().take(100).collect()
        } else {
            comment
        };
        if let Some(existing) = target.iter_mut().find(|v| v.key == key) {
            existing.set_value(value);
            existing.comment = comment;
            existing.source = VarSource::Custom;
            existing.phase_ref = phase_ref;
        } else {
            target.push(EnvVar::with_phase_ref(key, value, comment, phase_ref));
        }
    }
}

/// Formats the elapsed time since a given sync epoch into a human-friendly string.
/// Returns "never" if epoch is None or 0.
pub fn format_relative_sync_time(sync_epoch: Option<u64>, now_epoch: u64, compact: bool) -> String {
    let Some(epoch) = sync_epoch.filter(|&e| e > 0) else {
        return "never".to_string();
    };

    if now_epoch <= epoch {
        return "just now".to_string();
    }

    let diff = now_epoch - epoch;
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        let mins = (diff / 60).max(1);
        if compact {
            format!("{}m ago", mins)
        } else if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", mins)
        }
    } else if diff < 86400 {
        let hours = (diff / 3600).max(1);
        if compact {
            format!("{}h ago", hours)
        } else if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else {
        let days = (diff / 86400).max(1);
        if compact {
            format!("{}d ago", days)
        } else if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
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
            collections: vec![
                Collection {
                    name: "default".to_string(),
                    enabled: true,
                    phase_binding: None,
                    last_sync_epoch: None,
                    vars: vec![EnvVar::new(
                        plaintext_key.to_string(),
                        plaintext_secret_1.to_string(),
                        VarSource::Custom,
                    )],
                },
                Collection {
                    name: "prod_collection_secret".to_string(),
                    enabled: true,
                    phase_binding: Some(PhaseBinding {
                        app_id: "app-1".to_string(),
                        app_name: "my-app".to_string(),
                        env_id: "env-1".to_string(),
                        env_name: "production".to_string(),
                        export_all_paths: true,
                    }),
                    last_sync_epoch: None,
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
        assert_eq!(loaded.collections.len(), 2);
        assert_eq!(loaded.collections[0].vars[0].key, plaintext_key);
        assert_eq!(loaded.collections[0].vars[0].value, plaintext_secret_1);
        assert_eq!(loaded.collections[0].vars[0].prefix, "MY_");
        assert_eq!(loaded.collections[0].vars[0].suffix, "999");
        assert_eq!(loaded.collections[1].vars[0].value, plaintext_secret_2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_single_source_per_collection_never_mixes() {
        let binding = PhaseBinding {
            app_id: "app1".to_string(),
            app_name: "Backend".to_string(),
            env_id: "env1".to_string(),
            env_name: "Prod".to_string(),
            export_all_paths: true,
        };
        let mut phase_coll = Collection::new_phase(
            "phase_prod".to_string(),
            binding.clone(),
            vec![("DB_URL".to_string(), "postgres://prod".to_string(), "Prod DB connection".to_string())],
        );
        assert!(phase_coll.is_phase());
        assert!(!phase_coll.is_custom());
        assert_eq!(phase_coll.vars[0].comment, "Prod DB connection");
        assert!(phase_coll
            .upsert_custom_var_with_phase_ref(
                "CUSTOM_KEY".to_string(),
                "123".to_string(),
                "comment".to_string(),
                None
            )
            .is_err());
        assert_eq!(phase_coll.vars.len(), 1);

        // Even if corrupted in memory and sanitized, custom vars are stripped from Phase collection
        phase_coll.vars.push(EnvVar::new(
            "MIXED".to_string(),
            "bad".to_string(),
            VarSource::Custom,
        ));
        phase_coll.sanitize_single_source();
        assert_eq!(phase_coll.vars.len(), 1);
        assert_eq!(phase_coll.vars[0].key, "DB_URL");

        // Custom collection strips any Phase vars on sanitize
        let mut custom_coll = Collection::new_custom("local_dev".to_string());
        custom_coll
            .upsert_custom_var_with_phase_ref(
                "LOCAL_PORT".to_string(),
                "8080".to_string(),
                "Local listening port".to_string(),
                None,
            )
            .unwrap();
        assert_eq!(custom_coll.vars[0].comment, "Local listening port");
        custom_coll.vars.push(EnvVar::new(
            "PHASE_LEAK".to_string(),
            "secret".to_string(),
            VarSource::Phase {
                app_name: "Backend".to_string(),
                env_name: "Prod".to_string(),
            },
        ));
        custom_coll.sanitize_single_source();
        assert_eq!(custom_coll.vars.len(), 1);
        assert_eq!(custom_coll.vars[0].key, "LOCAL_PORT");
    }

    #[test]
    fn test_custom_var_comment_100_char_limit() {
        let mut coll = Collection::new_custom("dev".to_string());
        let long_comment = "x".repeat(150);
        coll.upsert_custom_var_with_phase_ref(
            "MY_KEY".to_string(),
            "my_val".to_string(),
            long_comment,
            None,
        )
        .unwrap();
        assert_eq!(coll.vars.len(), 1);
        assert_eq!(coll.vars[0].comment.chars().count(), 100);
        assert_eq!(coll.vars[0].comment, "x".repeat(100));
    }

    #[test]
    fn test_settings_defaults_and_relative_sync_time() {
        let settings = AppSettings::default();
        assert!(settings.sync_only_enabled_collections);
        assert!(settings.insert_new_collection_at_top);
        assert!(settings.shell_prompt_hook);

        let now = 1_000_000;
        assert_eq!(format_relative_sync_time(None, now, false), "never");
        assert_eq!(format_relative_sync_time(Some(0), now, false), "never");
        assert_eq!(format_relative_sync_time(Some(now), now, false), "just now");
        assert_eq!(format_relative_sync_time(Some(now - 30), now, false), "just now"); // 30s ago
        assert_eq!(format_relative_sync_time(Some(now - 60), now, false), "1 minute ago"); // 60s ago
        assert_eq!(format_relative_sync_time(Some(now - 60), now, true), "1m ago");
        assert_eq!(format_relative_sync_time(Some(now - 300), now, false), "5 minutes ago"); // 300s ago
        assert_eq!(format_relative_sync_time(Some(now - 300), now, true), "5m ago");
        assert_eq!(format_relative_sync_time(Some(now - 3600), now, false), "1 hour ago");
        assert_eq!(format_relative_sync_time(Some(now - 3600), now, true), "1h ago");
        assert_eq!(format_relative_sync_time(Some(now - 7200), now, false), "2 hours ago");
        assert_eq!(format_relative_sync_time(Some(now - 7200), now, true), "2h ago");
        assert_eq!(format_relative_sync_time(Some(now - 86400), now, false), "1 day ago");
        assert_eq!(format_relative_sync_time(Some(now - 86400), now, true), "1d ago");
        assert_eq!(format_relative_sync_time(Some(now - 172800), now, false), "2 days ago");
        assert_eq!(format_relative_sync_time(Some(now - 172800), now, true), "2d ago");
    }

    #[test]
    fn test_priority_top_collection_wins_over_lower() {
        let state = AppStateData {
            phase: PhaseConfig::default(),
            collections: vec![
                Collection {
                    name: "collection_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    last_sync_epoch: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "from_collection_satu".to_string(), VarSource::Custom),
                        EnvVar::new("B".to_string(), "b_from_satu".to_string(), VarSource::Custom),
                    ],
                },
                Collection {
                    name: "collection_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    last_sync_epoch: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "from_collection_dua".to_string(), VarSource::Custom),
                        EnvVar::new("C".to_string(), "c_from_dua".to_string(), VarSource::Custom),
                    ],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        let effective = state.compute_effective_vars();
        let map: HashMap<_, _> = effective.into_iter().map(|v| (v.key.clone(), v)).collect();

        // Collection collection_satu wins over Collection collection_dua for key A
        assert_eq!(map["A"].value, "from_collection_satu");
        assert_eq!(map["A"].winning_owner, "collection_satu");
        assert_eq!(map["B"].value, "b_from_satu");
        assert_eq!(map["B"].winning_owner, "collection_satu");
        assert_eq!(map["C"].value, "c_from_dua");
        assert_eq!(map["C"].winning_owner, "collection_dua");
    }

    #[test]
    fn test_disabled_top_collection_falls_back_to_next_enabled() {
        let mut state = AppStateData {
            phase: PhaseConfig::default(),
            collections: vec![
                Collection {
                    name: "collection_satu".to_string(),
                    enabled: false,
                    phase_binding: None,
                    last_sync_epoch: None,
                    vars: vec![EnvVar::new("A".to_string(), "from_collection_satu".to_string(), VarSource::Custom)],
                },
                Collection {
                    name: "collection_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    last_sync_epoch: None,
                    vars: vec![EnvVar::new("A".to_string(), "from_collection_dua".to_string(), VarSource::Custom)],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        let effective = state.compute_effective_vars();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].value, "from_collection_dua");

        state.collections[1].enabled = false;
        let effective2 = state.compute_effective_vars();
        assert!(effective2.is_empty());
    }

    #[test]
    fn test_phase_var_ref_paths_and_reference_syntax() {
        assert_eq!(normalize_secret_path(""), "/");
        assert_eq!(normalize_secret_path("  /  "), "/");
        assert_eq!(normalize_secret_path("backend/payments/"), "/backend/payments");
        assert_eq!(normalize_secret_path("/backend//payments/"), "/backend/payments");

        let root_ref = PhaseVarRef {
            app_id: "app1".to_string(),
            app_name: "backend_api".to_string(),
            env_id: "env1".to_string(),
            env_name: "production".to_string(),
            path: "/".to_string(),
            secret_key: "SECRET_KEY".to_string(),
        };
        assert_eq!(root_ref.normalized_path(), "/");
        assert_eq!(root_ref.reference_syntax(), "${backend_api::production.SECRET_KEY}");

        let folder_ref = PhaseVarRef {
            app_id: "app1".to_string(),
            app_name: "backend_api".to_string(),
            env_id: "env1".to_string(),
            env_name: "production".to_string(),
            path: "backend/payments/".to_string(),
            secret_key: "STRIPE_KEY".to_string(),
        };
        assert_eq!(folder_ref.normalized_path(), "/backend/payments");
        assert_eq!(
            folder_ref.reference_syntax(),
            "${backend_api::production./backend/payments/STRIPE_KEY}"
        );

        let manual_var = EnvVar::new(
            "LOCAL_VAR".to_string(),
            "val".to_string(),
            VarSource::Custom,
        );
        assert!(!manual_var.is_phase_synced());

        let phase_var = EnvVar::with_phase_ref(
            "MY_STRIPE".to_string(),
            "sk_live_abc".to_string(),
            "Stripe comment".to_string(),
            Some(folder_ref),
        );
        assert!(phase_var.is_phase_synced());
        assert_eq!(phase_var.comment, "Stripe comment");
    }

    #[test]
    fn test_effective_vars_source_label_for_phase_ref_custom_var() {
        let mut state = AppStateData::default();
        state.collections[0].vars.push(EnvVar::new(
            "MANUAL_KEY".to_string(),
            "123".to_string(),
            VarSource::Custom,
        ));
        state.collections[0].vars.push(EnvVar::with_phase_ref(
            "ROOT_REF".to_string(),
            "abc".to_string(),
            "Root secret".to_string(),
            Some(PhaseVarRef {
                app_id: "app1".to_string(),
                app_name: "backend_api".to_string(),
                env_id: "env1".to_string(),
                env_name: "production".to_string(),
                path: "/".to_string(),
                secret_key: "ROOT_KEY".to_string(),
            }),
        ));
        state.collections[0].vars.push(EnvVar::with_phase_ref(
            "FOLDER_REF".to_string(),
            "xyz".to_string(),
            "Folder secret".to_string(),
            Some(PhaseVarRef {
                app_id: "app1".to_string(),
                app_name: "backend_api".to_string(),
                env_id: "env1".to_string(),
                env_name: "production".to_string(),
                path: "/backend/payments".to_string(),
                secret_key: "STRIPE_KEY".to_string(),
            }),
        ));

        let effective = state.compute_effective_vars();
        let manual = effective.iter().find(|v| v.key == "MANUAL_KEY").unwrap();
        let root_ref = effective.iter().find(|v| v.key == "ROOT_REF").unwrap();
        let folder_ref = effective.iter().find(|v| v.key == "FOLDER_REF").unwrap();

        assert_eq!(manual.source_label, "Manual");
        assert_eq!(root_ref.source_label, "Phase (backend_api/production)");
        assert_eq!(folder_ref.source_label, "Phase (backend_api/production/backend/payments)");
    }

    #[test]
    fn test_individual_variable_enable_disable_and_collection_override() {
        let binding = PhaseBinding {
            app_id: "app1".to_string(),
            app_name: "api".to_string(),
            env_id: "env1".to_string(),
            env_name: "prod".to_string(),
            export_all_paths: true,
        };

        let mut custom_top = Collection::new_custom("custom_top".to_string());
        let mut v_manual_disabled = EnvVar::new("SHARED".to_string(), "top_val".to_string(), VarSource::Custom);
        v_manual_disabled.enabled = false;
        let v_manual_enabled = EnvVar::new("TOP_ONLY".to_string(), "1".to_string(), VarSource::Custom);
        let mut v_phase_ref_disabled = EnvVar::with_phase_ref(
            "REF_KEY".to_string(),
            "ref_val".to_string(),
            String::new(),
            Some(PhaseVarRef {
                app_id: "app1".to_string(),
                app_name: "api".to_string(),
                env_id: "env1".to_string(),
                env_name: "prod".to_string(),
                path: "/".to_string(),
                secret_key: "REF_KEY".to_string(),
            }),
        );
        v_phase_ref_disabled.enabled = false;
        custom_top.vars = vec![v_manual_disabled, v_manual_enabled, v_phase_ref_disabled];

        let mut phase_coll = Collection::new_phase(
            "phase_prod".to_string(),
            binding.clone(),
            vec![
                ("SHARED".to_string(), "phase_val".to_string(), String::new()),
                ("PHASE_ON".to_string(), "yes".to_string(), String::new()),
                ("PHASE_OFF".to_string(), "no".to_string(), String::new()),
            ],
        );
        phase_coll.vars[2].enabled = false;

        let mut state = AppStateData {
            phase: PhaseConfig::default(),
            collections: vec![custom_top, phase_coll],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        // Enabled collections include only individually enabled vars; disabled SHARED in top falls back to phase_coll
        let eff = state.compute_effective_vars();
        let map: HashMap<_, _> = eff.iter().map(|v| (v.key.as_str(), v)).collect();
        assert_eq!(map.len(), 3);
        assert_eq!(map["TOP_ONLY"].value, "1");
        assert_eq!(map["SHARED"].value, "phase_val");
        assert_eq!(map["SHARED"].winning_owner, "phase_prod");
        assert_eq!(map["PHASE_ON"].value, "yes");
        assert!(!map.contains_key("REF_KEY"));
        assert!(!map.contains_key("PHASE_OFF"));

        // Disabling phase_prod disables ALL its variables regardless of individual var.enabled states
        state.collections[1].enabled = false;
        let eff_after_disable_phase = state.compute_effective_vars();
        assert_eq!(eff_after_disable_phase.len(), 1);
        assert_eq!(eff_after_disable_phase[0].key, "TOP_ONLY");

        // Re-enabling phase_prod restores only individually enabled variables (PHASE_OFF stays disabled)
        state.collections[1].enabled = true;
        // Resyncing phase collection preserves individual variable enabled states and defaults new vars to true
        state.collections[1].set_phase_vars(
            binding,
            vec![
                ("SHARED".to_string(), "phase_val_v2".to_string(), String::new()),
                ("PHASE_ON".to_string(), "yes_v2".to_string(), String::new()),
                ("PHASE_OFF".to_string(), "no_v2".to_string(), String::new()),
                ("PHASE_NEW".to_string(), "new_val".to_string(), String::new()),
            ],
        );
        assert!(state.collections[1].vars[0].enabled);
        assert!(state.collections[1].vars[1].enabled);
        assert!(!state.collections[1].vars[2].enabled);
        assert!(state.collections[1].vars[3].enabled);

        let eff_resynced = state.compute_effective_vars();
        let map2: HashMap<_, _> = eff_resynced.iter().map(|v| (v.key.as_str(), v)).collect();
        assert_eq!(map2.len(), 4);
        assert_eq!(map2["SHARED"].value, "phase_val_v2");
        assert_eq!(map2["PHASE_NEW"].value, "new_val");
        assert!(!map2.contains_key("PHASE_OFF"));
    }
}
