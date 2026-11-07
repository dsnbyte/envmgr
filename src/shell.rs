use crate::model::{is_valid_env_key, AppStateData, EffectiveVar};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BASHRC_START_MARKER: &str = "# >>> envmgr initialize >>>";
const BASHRC_END_MARKER: &str = "# <<< envmgr initialize <<<";

pub fn escape_shell_single_quote(val: &str) -> String {
    format!("'{}'", val.replace('\'', "'\\''"))
}

pub fn generate_env_sh_content(vars: &[EffectiveVar]) -> String {
    let mut lines = Vec::new();
    lines.push("# Generated dynamically by envmgr in memory".to_string());
    lines.push("if [ -n \"${_ENVMGR_KEYS:-}\" ]; then".to_string());
    lines.push("  for _envmgr_k in $_ENVMGR_KEYS; do".to_string());
    lines.push("    unset \"$_envmgr_k\"".to_string());
    lines.push("  done".to_string());
    lines.push("  unset _envmgr_k".to_string());
    lines.push("fi".to_string());

    let mut valid_keys = Vec::new();
    for v in vars {
        if is_valid_env_key(&v.key) {
            lines.push(format!(
                "export {}={}",
                v.key,
                escape_shell_single_quote(&v.value)
            ));
            valid_keys.push(v.key.as_str());
        }
    }

    lines.push(format!("_ENVMGR_KEYS=\"{}\"", valid_keys.join(" ")));
    lines.push(String::new());
    lines.join("\n")
}

pub fn bashrc_path() -> PathBuf {
    if let Ok(custom) = std::env::var("ENVMGR_BASHRC_PATH") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".bashrc")
}

fn envmgr_bin_expr() -> String {
    if let Ok(custom) = std::env::var("ENVMGR_BIN_PATH") {
        if !custom.trim().is_empty() {
            return format!("\"{}\"", custom.trim());
        }
    }
    "command envmgr".to_string()
}

pub fn build_bashrc_snippet() -> String {
    let bin = envmgr_bin_expr();
    format!(
        "{start}\n\
         if command -v envmgr >/dev/null 2>&1 || [ -n \"${{ENVMGR_BIN_PATH:-}}\" ]; then\n\
         \x20   eval \"$({bin} export 2>/dev/null)\"\n\
         fi\n\
         envmgr() {{\n\
         \x20   {bin} \"$@\"\n\
         \x20   local _envmgr_ec=$?\n\
         \x20   eval \"$({bin} export 2>/dev/null)\"\n\
         \x20   return $_envmgr_ec\n\
         }}\n\
         {end}",
        start = BASHRC_START_MARKER,
        bin = bin,
        end = BASHRC_END_MARKER
    )
}

pub fn ensure_bashrc_integration() -> Result<PathBuf, String> {
    let rc_path = bashrc_path();
    let snippet = build_bashrc_snippet();

    let existing = fs::read_to_string(&rc_path).unwrap_or_default();
    let updated = if let (Some(start_idx), Some(end_idx)) = (
        existing.find(BASHRC_START_MARKER),
        existing.find(BASHRC_END_MARKER),
    ) {
        if start_idx <= end_idx {
            let after_end = end_idx + BASHRC_END_MARKER.len();
            format!(
                "{}{}{}",
                &existing[..start_idx],
                snippet,
                &existing[after_end..]
            )
        } else {
            format!("{}\n\n{}\n", existing.trim_end(), snippet)
        }
    } else if existing.trim().is_empty() {
        format!("{}\n", snippet)
    } else {
        format!("{}\n\n{}\n", existing.trim_end(), snippet)
    };

    if updated != existing {
        if let Some(parent) = rc_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&rc_path, updated).map_err(|e| format!("Failed to update .bashrc: {}", e))?;
    }

    Ok(rc_path)
}

/// Applies the effective variables into the current process environment and verifies
/// that `~/.bashrc` and the export script evaluate cleanly in Bash.
pub fn reload_shell_environment(vars: &[EffectiveVar]) -> Result<(), String> {
    let rc_path = ensure_bashrc_integration()?;

    // Update current process environment variables
    if let Ok(prev_keys) = std::env::var("_ENVMGR_KEYS") {
        for k in prev_keys.split_whitespace() {
            if is_valid_env_key(k) {
                std::env::remove_var(k);
            }
        }
    }
    let mut valid_keys = Vec::new();
    for v in vars {
        if is_valid_env_key(&v.key) {
            std::env::set_var(&v.key, &v.value);
            valid_keys.push(v.key.as_str());
        }
    }
    std::env::set_var("_ENVMGR_KEYS", valid_keys.join(" "));

    // Verify .bashrc + runtime export evaluation in bash
    let export_script = generate_env_sh_content(vars);
    let check_cmd = format!(
        "[ -f \"{}\" ] && source \"{}\"; {}",
        rc_path.to_string_lossy(),
        rc_path.to_string_lossy(),
        export_script
    );
    let status = Command::new("bash")
        .arg("-c")
        .arg(&check_cmd)
        .status()
        .map_err(|e| format!("Failed to invoke bash to verify reload: {}", e))?;

    if !status.success() {
        return Err(format!("Bash reload exited with status {}", status));
    }

    Ok(())
}

pub fn apply_state_to_system(state: &AppStateData) -> Result<usize, String> {
    state.save()?;
    let effective = state.compute_effective_vars();
    let _ = ensure_bashrc_integration()?;
    Ok(effective.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_env_sh_and_source_in_bash() {
        let vars = vec![
            EffectiveVar {
                key: "APP_ENV".to_string(),
                value: "production".to_string(),
                winning_owner: "Profile #1: prod".to_string(),
                source_label: "Custom".to_string(),
            },
            EffectiveVar {
                key: "SPECIAL_CHARS".to_string(),
                value: "hello 'world' $HOME `date`".to_string(),
                winning_owner: "Default".to_string(),
                source_label: "Custom".to_string(),
            },
        ];

        let script = generate_env_sh_content(&vars);
        assert!(script.contains("export APP_ENV='production'"));

        let vars_after_disable = vec![EffectiveVar {
            key: "SPECIAL_CHARS".to_string(),
            value: "hello 'world' $HOME `date`".to_string(),
            winning_owner: "Default".to_string(),
            source_label: "Custom".to_string(),
        }];
        let script2 = generate_env_sh_content(&vars_after_disable);

        let test_cmd = format!(
            "{}\n[ \"$APP_ENV\" = \"production\" ] || exit 1\n[ \"$SPECIAL_CHARS\" = \"hello 'world' \\$HOME \\`date\\`\" ] || exit 2\n{}\n[ -z \"${{APP_ENV:-}}\" ] || exit 3\n",
            script, script2
        );

        let status = Command::new("bash")
            .arg("-c")
            .arg(&test_cmd)
            .status()
            .expect("bash should run");
        assert!(status.success());
    }

    #[test]
    fn test_end_to_end_bashrc_inclusion_and_encrypted_state_priority() {
        use crate::model::{EnvVar, PhaseConfig, Profile, VarSource};
        use std::time::{SystemTime, UNIX_EPOCH};

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("envmgr_test_{}", uniq));
        fs::create_dir_all(&temp_dir).unwrap();

        let bashrc_file = temp_dir.join(".bashrc");
        fs::write(
            &bashrc_file,
            "# Existing user bashrc\nexport EXISTING_VAR='kept'\n",
        )
        .unwrap();

        std::env::set_var("ENVMGR_CONFIG_DIR", &temp_dir);
        std::env::set_var("ENVMGR_BASHRC_PATH", &bashrc_file);

        let mut state = AppStateData {
            phase: PhaseConfig::default(),
            default_vars: vec![
                EnvVar {
                    key: "A".to_string(),
                    value: "val_default".to_string(),
                    source: VarSource::Custom,
                },
                EnvVar {
                    key: "BASE_VAR".to_string(),
                    value: "always_here".to_string(),
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
                        value: "val_profile_dua".to_string(),
                        source: VarSource::Custom,
                    }],
                },
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar {
                        key: "A".to_string(),
                        value: "val_profile_satu".to_string(),
                        source: VarSource::Custom,
                    }],
                },
            ],
        };

        apply_state_to_system(&state).unwrap();
        reload_shell_environment(&state.compute_effective_vars()).unwrap();

        assert!(temp_dir.join("state.enc").exists());

        // Check .bashrc never contains variable values in plaintext
        let bashrc_content = fs::read_to_string(&bashrc_file).unwrap();
        assert!(bashrc_content.contains("export EXISTING_VAR='kept'"));
        assert!(!bashrc_content.contains("val_profile_dua"));
        assert!(!bashrc_content.contains("val_profile_satu"));
        assert!(!bashrc_content.contains("val_default"));
        assert!(!bashrc_content.contains("always_here"));
        assert!(bashrc_content.contains("export 2>/dev/null"));

        // Verify loading from encrypted state.enc and evaluating in bash
        let loaded1 = AppStateData::load_from_dir(&temp_dir);
        let script1 = generate_env_sh_content(&loaded1.compute_effective_vars());
        let out = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "source \"{}\" && eval \"{}\" && printf \"%s|%s|%s\" \"$A\" \"$BASE_VAR\" \"$EXISTING_VAR\"",
                bashrc_file.display(),
                script1.replace('"', "\\\"").replace('$', "\\$").replace('`', "\\`")
            ))
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "val_profile_dua|always_here|kept"
        );

        // Toggle profile_dua OFF -> profile_satu should win
        state.profiles[0].enabled = false;
        state.save_to_dir(&temp_dir).unwrap();
        let loaded2 = AppStateData::load_from_dir(&temp_dir);
        let script2 = generate_env_sh_content(&loaded2.compute_effective_vars());

        let out2 = Command::new("bash")
            .arg("-c")
            .arg(format!("{}\nprintf \"%s\" \"$A\"", script2))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out2.stdout), "val_profile_satu");

        // Toggle profile_satu OFF -> Default should win
        state.profiles[1].enabled = false;
        state.save_to_dir(&temp_dir).unwrap();
        let loaded3 = AppStateData::load_from_dir(&temp_dir);
        let script3 = generate_env_sh_content(&loaded3.compute_effective_vars());

        let out3 = Command::new("bash")
            .arg("-c")
            .arg(format!("{}\nprintf \"%s\" \"$A\"", script3))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out3.stdout), "val_default");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
