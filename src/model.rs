use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhaseConfig {
    pub host_mode: HostMode,
    pub custom_url: String,
    pub pat_token: String,
}

impl PhaseConfig {
    pub fn effective_host(&self) -> String {
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
        !self.pat_token.trim().is_empty()
            && (self.host_mode == HostMode::Cloud || !self.custom_url.trim().is_empty())
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
    pub source: VarSource,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveVar {
    pub key: String,
    pub value: String,
    pub winning_owner: String,
    pub source_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppStateData {
    pub phase: PhaseConfig,
    pub default_vars: Vec<EnvVar>,
    pub profiles: Vec<Profile>,
}

impl AppStateData {
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
        serde_json::from_slice(&decrypted).unwrap_or_default()
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
    /// 1. `default_vars` are always loaded as baseline.
    /// 2. Enabled profiles override `default_vars`.
    /// 3. Among enabled profiles, the profile highest in the list (smallest index, e.g. #1 at top) wins!
    pub fn compute_effective_vars(&self) -> Vec<EffectiveVar> {
        let mut map: HashMap<String, EffectiveVar> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        let mut upsert = |key: &str, value: &str, owner: String, source_label: String| {
            if !map.contains_key(key) {
                order.push(key.to_string());
            }
            map.insert(
                key.to_string(),
                EffectiveVar {
                    key: key.to_string(),
                    value: value.to_string(),
                    winning_owner: owner,
                    source_label,
                },
            );
        };

        // 1. Apply Default variables first (lowest precedence)
        for var in &self.default_vars {
            upsert(
                &var.key,
                &var.value,
                "Default".to_string(),
                var.source.label(),
            );
        }

        // 2. Apply enabled profiles from bottom to top so the topmost enabled profile overwrites lower ones
        for (idx, profile) in self.profiles.iter().enumerate().rev() {
            if !profile.enabled {
                continue;
            }
            let owner = format!("Profile #{}: {}", idx + 1, profile.name);
            for var in &profile.vars {
                upsert(&var.key, &var.value, owner.clone(), var.source.label());
            }
        }

        order
            .into_iter()
            .filter_map(|k| map.remove(&k))
            .collect()
    }

    /// Merges fetched Phase variables into a target Vec<EnvVar>.
    /// Preserves custom variables unless overwritten by a Phase variable with the same key,
    /// and replaces old Phase variables from previous syncs.
    pub fn merge_phase_vars(
        target: &mut Vec<EnvVar>,
        app_name: &str,
        env_name: &str,
        fetched: Vec<(String, String)>,
    ) {
        let fetched_keys: std::collections::HashSet<&str> =
            fetched.iter().map(|(k, _)| k.as_str()).collect();
        target.retain(|v| matches!(v.source, VarSource::Custom) && !fetched_keys.contains(v.key.as_str()));

        for (k, v) in fetched {
            target.push(EnvVar {
                key: k,
                value: v,
                source: VarSource::Phase {
                    app_name: app_name.to_string(),
                    env_name: env_name.to_string(),
                },
            });
        }
    }

    pub fn upsert_custom_var(target: &mut Vec<EnvVar>, key: String, value: String) {
        if let Some(existing) = target.iter_mut().find(|v| v.key == key) {
            existing.value = value;
            existing.source = VarSource::Custom;
        } else {
            target.push(EnvVar {
                key,
                value,
                source: VarSource::Custom,
            });
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
    fn test_encrypted_state_file_never_stores_plaintext_on_disk() {
        use std::time::{SystemTime, UNIX_EPOCH};

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
                host_mode: HostMode::Cloud,
                custom_url: String::new(),
                pat_token: "pss_user:v1:secret_pat_token_12345".to_string(),
            },
            default_vars: vec![EnvVar {
                key: plaintext_key.to_string(),
                value: plaintext_secret_1.to_string(),
                source: VarSource::Custom,
            }],
            profiles: vec![Profile {
                name: "prod_profile_secret".to_string(),
                enabled: true,
                phase_binding: None,
                vars: vec![EnvVar {
                    key: "API_TOKEN".to_string(),
                    value: plaintext_secret_2.to_string(),
                    source: VarSource::Phase {
                        app_name: "my-app".to_string(),
                        env_name: "production".to_string(),
                    },
                }],
            }],
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
        assert_eq!(loaded.default_vars.len(), 1);
        assert_eq!(loaded.default_vars[0].key, plaintext_key);
        assert_eq!(loaded.default_vars[0].value, plaintext_secret_1);
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].vars[0].value, plaintext_secret_2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_priority_top_profile_wins_over_lower_and_default() {
        let state = AppStateData {
            phase: PhaseConfig::default(),
            default_vars: vec![
                EnvVar {
                    key: "A".to_string(),
                    value: "from_default".to_string(),
                    source: VarSource::Custom,
                },
                EnvVar {
                    key: "DEFAULT_ONLY".to_string(),
                    value: "yes".to_string(),
                    source: VarSource::Custom,
                },
            ],
            profiles: vec![
                Profile {
                    name: "profile_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar {
                        key: "A".to_string(),
                        value: "from_profile_dua".to_string(),
                        source: VarSource::Custom,
                    }],
                },
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![
                        EnvVar {
                            key: "A".to_string(),
                            value: "from_profile_satu".to_string(),
                            source: VarSource::Custom,
                        },
                        EnvVar {
                            key: "B".to_string(),
                            value: "b_from_satu".to_string(),
                            source: VarSource::Custom,
                        },
                    ],
                },
            ],
        };

        let effective = state.compute_effective_vars();
        let map: HashMap<_, _> = effective.into_iter().map(|v| (v.key.clone(), v)).collect();

        assert_eq!(map["A"].value, "from_profile_dua");
        assert_eq!(map["A"].winning_owner, "Profile #1: profile_dua");
        assert_eq!(map["B"].value, "b_from_satu");
        assert_eq!(map["B"].winning_owner, "Profile #2: profile_satu");
        assert_eq!(map["DEFAULT_ONLY"].value, "yes");
        assert_eq!(map["DEFAULT_ONLY"].winning_owner, "Default");
    }

    #[test]
    fn test_disabled_top_profile_falls_back_to_next_enabled_or_default() {
        let mut state = AppStateData {
            phase: PhaseConfig::default(),
            default_vars: vec![EnvVar {
                key: "A".to_string(),
                value: "from_default".to_string(),
                source: VarSource::Custom,
            }],
            profiles: vec![
                Profile {
                    name: "profile_dua".to_string(),
                    enabled: false,
                    phase_binding: None,
                    vars: vec![EnvVar {
                        key: "A".to_string(),
                        value: "from_profile_dua".to_string(),
                        source: VarSource::Custom,
                    }],
                },
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar {
                        key: "A".to_string(),
                        value: "from_profile_satu".to_string(),
                        source: VarSource::Custom,
                    }],
                },
            ],
        };

        let effective = state.compute_effective_vars();
        assert_eq!(effective[0].value, "from_profile_satu");

        state.profiles[1].enabled = false;
        let effective2 = state.compute_effective_vars();
        assert_eq!(effective2[0].value, "from_default");
    }
}
