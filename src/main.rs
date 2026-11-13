mod model;
mod phase;
mod shell;
mod tui;

use model::AppStateData;
use phase::{detect_phase_cli, sync_phase_collections};
use shell::{apply_state_to_system, generate_env_sh_content, reload_shell_environment};

fn print_help() {
    println!(
        "envmgr - Super lightweight Rust TUI environment manager with encrypted storage & Phase.dev\n\n\
         USAGE:\n\
         \x20 envmgr            Launch the interactive Terminal UI (TUI)\n\
         \x20 envmgr export     Decrypt active variables and print shell export statements to stdout\n\
         \x20 envmgr sync       Synchronize Phase.dev collections using configured Auth (CLI or API Token)\n\
         \x20 envmgr reload     Save encrypted state, ensure ~/.bashrc hook, and reload shell config\n\
         \x20 envmgr apply      Alias for `envmgr reload`\n\
         \x20 envmgr status     Show active collections, data sources, settings, and effective variables\n\
         \x20 envmgr --help     Show this help message"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = args.first() {
        match first.as_str() {
            "-h" | "--help" | "help" => {
                print_help();
                return;
            }
            "export" => {
                let state = AppStateData::load();
                let effective = state.compute_effective_vars();
                print!("{}", generate_env_sh_content(&effective));
                return;
            }
            "sync" => {
                let mut state = AppStateData::load();
                match sync_phase_collections(&mut state, None) {
                    Ok((coll_count, var_count)) => {
                        if let Err(e) = apply_state_to_system(&state) {
                            eprintln!("Error saving synced state: {}", e);
                            std::process::exit(1);
                        }
                        println!(
                            "Synchronized {} Phase.dev collection(s) ({} total variables) via {}.",
                            coll_count,
                            var_count,
                            state.phase.auth_method.label()
                        );
                    }
                    Err(e) => {
                        eprintln!("Phase.dev sync error: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            "apply" | "reload" => {
                let state = AppStateData::load();
                match apply_state_to_system(&state) {
                    Ok(count) => {
                        let effective = state.compute_effective_vars();
                        if let Err(e) = reload_shell_environment(&effective) {
                            eprintln!("Warning during shell verification: {}", e);
                        }
                        let is_wrapped = std::env::var("_ENVMGR_WRAPPER").is_ok();
                        if is_wrapped {
                            println!(
                                "Encrypted {} effective variable(s) in {} and reloaded active shell environment",
                                count,
                                AppStateData::state_file_path().display()
                            );
                        } else {
                            println!(
                                "Encrypted {} effective variable(s) in {}",
                                count,
                                AppStateData::state_file_path().display()
                            );
                            println!(
                                "\nNotice: Active shell session has not loaded the envmgr shell hook.\n\
                                 To apply variables to this active session, run:\n  \
                                   source ~/.bashrc\n\
                                 or:\n  \
                                   eval \"$(envmgr export)\""
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            "status" => {
                let state = AppStateData::load();
                let cli_status = detect_phase_cli();
                println!(
                    "Encrypted Store: {}",
                    AppStateData::state_file_path().display()
                );
                println!("Phase.dev Host : {}", state.phase.effective_host());
                println!(
                    "Phase.dev Auth : {} ({})",
                    state.phase.auth_method.label(),
                    if state.phase.is_configured() {
                        "Configured"
                    } else {
                        "Not Configured"
                    }
                );
                println!("Phase CLI      : {}", cli_status.summary_badge());
                if state.last_phase_sync_epoch > 0 {
                    let now = AppStateData::current_epoch_secs();
                    let relative = model::format_relative_sync_time(
                        Some(state.last_phase_sync_epoch),
                        now,
                        false,
                    );
                    println!("Last Phase Sync: {}", relative);
                }
                println!("Collections ({}) :", state.collections.len());
                for c in &state.collections {
                    let st = if c.enabled { "ON " } else { "OFF" };
                    println!(
                        "  [{}] {} ({} vars) [{}]",
                        st,
                        c.name,
                        c.vars.len(),
                        c.source_label()
                    );
                }
                let eff = state.compute_effective_vars();
                println!("\nEffective Variables ({}):", eff.len());
                for v in eff {
                    println!("  {} (from {} | {})", v.key, v.winning_owner, v.source_label);
                }
                return;
            }
            _ => {
                eprintln!(
                    "Unknown argument '{}'. Run `envmgr --help` for usage.",
                    first
                );
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = tui::run_tui() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
