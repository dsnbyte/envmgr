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

    lines.push(format!("export _ENVMGR_KEYS=\"{}\"", valid_keys.join(" ")));
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

#[cfg(test)]
pub fn build_bashrc_snippet() -> String {
    build_bashrc_snippet_with_options(true)
}

pub fn build_bashrc_snippet_with_options(prompt_hook: bool) -> String {
    let bin = envmgr_bin_expr();
    let prompt_section = if prompt_hook {
        format!(
            "\n_envmgr_prompt_hook() {{\n\
             \x20   local _sf=\"${{ENVMGR_CONFIG_DIR:-$HOME/.config/envmgr}}/state.enc\"\n\
             \x20   if [ -f \"$_sf\" ]; then\n\
             \x20       if [ ! -f \"${{_ENVMGR_SYNC_MARKER:-}}\" ] || [ \"$_sf\" -nt \"$_ENVMGR_SYNC_MARKER\" ]; then\n\
             \x20           _ENVMGR_SYNC_MARKER=\"${{XDG_RUNTIME_DIR:-/tmp}}/.envmgr_sync_${{UID:-$(id -u)}}_$$\"\n\
             \x20           touch \"$_ENVMGR_SYNC_MARKER\" 2>/dev/null\n\
             \x20           eval \"$({bin} export 2>/dev/null)\"\n\
             \x20       fi\n\
             \x20   fi\n\
             }}\n\
             if [[ \"$(declare -p PROMPT_COMMAND 2>/dev/null)\" == \"declare -a\"* ]]; then\n\
             \x20   case \" ${{PROMPT_COMMAND[*]}} \" in\n\
             \x20       *\" _envmgr_prompt_hook \"*) ;;\n\
             \x20       *) PROMPT_COMMAND+=(_envmgr_prompt_hook) ;;\n\
             \x20   esac\n\
             else\n\
             \x20   case \";${{PROMPT_COMMAND:-}};\" in\n\
             \x20       *\";_envmgr_prompt_hook;\"*) ;;\n\
             \x20       *) PROMPT_COMMAND=\"_envmgr_prompt_hook${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}\" ;;\n\
             \x20   esac\n\
             fi",
            bin = bin
        )
    } else {
        String::new()
    };

    format!(
        "{start}\n\
         if command -v envmgr >/dev/null 2>&1 || [ -n \"${{ENVMGR_BIN_PATH:-}}\" ]; then\n\
         \x20   eval \"$({bin} export 2>/dev/null)\"\n\
         fi\n\
         envmgr() {{\n\
         \x20   _ENVMGR_WRAPPER=1 {bin} \"$@\"\n\
         \x20   local _envmgr_ec=$?\n\
         \x20   eval \"$({bin} export 2>/dev/null)\"\n\
         \x20   _ENVMGR_SYNC_MARKER=\"${{XDG_RUNTIME_DIR:-/tmp}}/.envmgr_sync_${{UID:-$(id -u)}}_$$\"\n\
         \x20   touch \"$_ENVMGR_SYNC_MARKER\" 2>/dev/null\n\
         \x20   return $_envmgr_ec\n\
         }}\n\
         export -f envmgr 2>/dev/null{prompt_section}\n\
         {end}",
        start = BASHRC_START_MARKER,
        bin = bin,
        prompt_section = prompt_section,
        end = BASHRC_END_MARKER
    )
}

pub fn ensure_bashrc_integration() -> Result<PathBuf, String> {
    ensure_bashrc_integration_with_options(true)
}

pub fn ensure_bashrc_integration_with_options(prompt_hook: bool) -> Result<PathBuf, String> {
    let rc_path = bashrc_path();
    let snippet = build_bashrc_snippet_with_options(prompt_hook);

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
    let _ = ensure_bashrc_integration_with_options(state.settings.shell_prompt_hook)?;
    Ok(effective.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_env_sh_and_source_in_bash() {
        let vars = vec![
            EffectiveVar::new(
                "APP_ENV".to_string(),
                "production".to_string(),
                "prod".to_string(),
                "Custom".to_string(),
            ),
            EffectiveVar::new(
                "SPECIAL_CHARS".to_string(),
                "hello 'world' $HOME `date`".to_string(),
                "Default".to_string(),
                "Custom".to_string(),
            ),
        ];

        let script = generate_env_sh_content(&vars);
        assert!(script.contains("export APP_ENV='production'"));

        let vars_after_disable = vec![EffectiveVar::new(
            "SPECIAL_CHARS".to_string(),
            "hello 'world' $HOME `date`".to_string(),
            "Default".to_string(),
            "Custom".to_string(),
        )];
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
        use crate::model::{AppSettings, EnvVar, PhaseConfig, Profile, VarSource};
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
            profiles: vec![
                Profile {
                    name: "profile_dua".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "val_profile_dua".to_string(), VarSource::Custom),
                        EnvVar::new("BASE_VAR".to_string(), "always_here".to_string(), VarSource::Custom),
                    ],
                },
                Profile {
                    name: "profile_satu".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![EnvVar::new("A".to_string(), "val_profile_satu".to_string(), VarSource::Custom)],
                },
                Profile {
                    name: "default".to_string(),
                    enabled: true,
                    phase_binding: None,
                    vars: vec![
                        EnvVar::new("A".to_string(), "val_default".to_string(), VarSource::Custom),
                        EnvVar::new("BASE_VAR".to_string(), "always_here".to_string(), VarSource::Custom),
                    ],
                },
            ],
            settings: AppSettings::default(),
            last_phase_sync_epoch: 0,
        };

        apply_state_to_system(&state).unwrap();
        reload_shell_environment(&state.compute_effective_vars()).unwrap();

        assert!(temp_dir.join("state.enc").exists());

        let bashrc_content = fs::read_to_string(&bashrc_file).unwrap();
        assert!(bashrc_content.contains("export EXISTING_VAR='kept'"));
        assert!(!bashrc_content.contains("val_profile_dua"));
        assert!(!bashrc_content.contains("val_profile_satu"));
        assert!(!bashrc_content.contains("val_default"));
        assert!(!bashrc_content.contains("always_here"));
        assert!(bashrc_content.contains("export 2>/dev/null"));

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

    #[test]
    fn test_bashrc_snippet_includes_hook_and_exported_function() {
        let snippet = build_bashrc_snippet();
        assert!(snippet.contains("_ENVMGR_WRAPPER=1"));
        assert!(snippet.contains("export -f envmgr"));
        assert!(snippet.contains("_envmgr_prompt_hook"));
        assert!(snippet.contains("PROMPT_COMMAND"));
    }

    #[test]
    fn test_prompt_hook_sync_logic() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("envmgr_hook_test_{}", uniq));
        fs::create_dir_all(&temp_dir).unwrap();

        let state_file = temp_dir.join("state.enc");
        fs::write(&state_file, "initial").unwrap();

        let marker = temp_dir.join(".sync_marker");

        let bash_test = format!(
            r#"
            _ENVMGR_SYNC_MARKER="{marker}"
            _sf="{state_file}"
            eval_count=0

            _mock_export() {{
                eval_count=$((eval_count + 1))
            }}

            _envmgr_prompt_hook() {{
                if [ -f "$_sf" ]; then
                    if [ ! -f "${{_ENVMGR_SYNC_MARKER:-}}" ] || [ "$_sf" -nt "$_ENVMGR_SYNC_MARKER" ]; then
                        touch "$_ENVMGR_SYNC_MARKER" 2>/dev/null
                        _mock_export
                    fi
                fi
            }}

            _envmgr_prompt_hook
            [ "$eval_count" -eq 1 ] || exit 1

            _envmgr_prompt_hook
            [ "$eval_count" -eq 1 ] || exit 2

            sleep 0.05
            touch "$_sf"

            _envmgr_prompt_hook
            [ "$eval_count" -eq 2 ] || exit 3

            _envmgr_prompt_hook
            [ "$eval_count" -eq 2 ] || exit 4
            "#,
            marker = marker.display(),
            state_file = state_file.display()
        );

        let status = Command::new("bash")
            .arg("-c")
            .arg(&bash_test)
            .status()
            .expect("bash should execute");
        assert!(status.success());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
