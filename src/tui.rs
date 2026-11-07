use crate::model::{
    is_valid_env_key, AppStateData, EnvVar, HostMode, PhaseBinding, PhaseConfig, Profile,
    PHASE_CLOUD_HOST,
};
use crate::phase::{fetch_apps_and_envs, fetch_secrets_for_env, try_detect_local_phase_cli_host, PhaseAppInfo};
use crate::shell::{apply_state_to_system, reload_shell_environment};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Profiles,
    Vars,
    Effective,
}

#[derive(Debug, Clone)]
pub enum Modal {
    None,
    PhaseConnect {
        host_mode: HostMode,
        custom_url: String,
        pat_token: String,
        active_field: usize, // 0 = mode, 1 = custom_url (if SelfHosted) or pat_token, 2 = pat_token
        error: Option<String>,
    },
    NewProfile {
        name: String,
        pull_from_phase: bool,
        active_field: usize, // 0 = name, 1 = source toggle
        error: Option<String>,
    },
    PhasePicker {
        target_profile_idx: Option<usize>, // None = Default, Some(idx) = profile index
        new_profile_name: Option<String>,  // If creating a new profile
        apps: Vec<PhaseAppInfo>,
        selected_app: usize,
        selected_env: usize,
        selecting_env: bool,
        error: Option<String>,
    },
    VarEditor {
        is_edit: bool,
        original_index: Option<usize>,
        var_key: String,
        var_value: String,
        active_field: usize, // 0 = key, 1 = value
        error: Option<String>,
    },
    ConfirmDeleteProfile {
        profile_idx: usize,
        profile_name: String,
    },
    ConfirmDeleteVar {
        var_idx: usize,
        var_key: String,
    },
}

pub struct App {
    pub data: AppStateData,
    pub focus: FocusPane,
    /// 0 = Default, 1..=N = profiles[idx - 1]
    pub selected_target: usize,
    pub selected_var: usize,
    pub selected_effective: usize,
    pub show_values: bool,
    pub modal: Modal,
    pub status_message: String,
    pub is_error_status: bool,
    pub should_quit: bool,
    pub cached_apps: Vec<PhaseAppInfo>,
}

impl App {
    pub fn new(mut data: AppStateData) -> Self {
        // Pre-fill host from ~/.phase/config.json if not configured yet
        if !data.phase.is_configured() {
            if let Some((mode, url)) = try_detect_local_phase_cli_host() {
                data.phase.host_mode = mode;
                if !url.is_empty() {
                    data.phase.custom_url = url;
                }
            }
        }

        let mut app = Self {
            data,
            focus: FocusPane::Profiles,
            selected_target: 0,
            selected_var: 0,
            selected_effective: 0,
            show_values: false,
            modal: Modal::None,
            status_message: "Ready. Press [a] Add Var, [n] New Profile, [Space] Toggle, [r] Reload Shell, [c] Phase.dev.".to_string(),
            is_error_status: false,
            should_quit: false,
            cached_apps: Vec::new(),
        };

        // Ensure env.sh and .bashrc are initialized right away
        if let Err(e) = apply_state_to_system(&app.data) {
            app.set_error(e);
        }

        app
    }

    pub fn set_info(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.is_error_status = false;
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.is_error_status = true;
    }

    pub fn sync_to_system(&mut self, action_desc: &str) {
        match apply_state_to_system(&self.data) {
            Ok(count) => {
                let effective = self.data.compute_effective_vars();
                let _ = reload_shell_environment(&effective);
                self.set_info(format!(
                    "{} | Encrypted {} effective var(s) in state.enc & reloaded shell config",
                    action_desc, count
                ));
            }
            Err(e) => {
                self.set_error(format!("{} | Failed to sync state.enc: {}", action_desc, e));
            }
        }
    }

    pub fn reload_shell(&mut self) {
        match apply_state_to_system(&self.data) {
            Ok(count) => {
                let effective = self.data.compute_effective_vars();
                match reload_shell_environment(&effective) {
                    Ok(()) => {
                        self.set_info(format!(
                            "Reloaded .bashrc & shell environment ({} active variable(s) ready for session)",
                            count
                        ));
                    }
                    Err(e) => {
                        self.set_error(format!("Saved state.enc, but reload check failed: {}", e));
                    }
                }
            }
            Err(e) => {
                self.set_error(format!("Failed to save state before reload: {}", e));
            }
        }
    }

    pub fn current_vars(&self) -> &[EnvVar] {
        if self.selected_target == 0 {
            &self.data.default_vars
        } else if let Some(prof) = self.data.profiles.get(self.selected_target - 1) {
            &prof.vars
        } else {
            &[]
        }
    }

    pub fn current_vars_mut(&mut self) -> &mut Vec<EnvVar> {
        if self.selected_target == 0 {
            &mut self.data.default_vars
        } else {
            &mut self.data.profiles[self.selected_target - 1].vars
        }
    }

    pub fn current_target_title(&self) -> String {
        if self.selected_target == 0 {
            "Default (Always Loaded Baseline)".to_string()
        } else if let Some(prof) = self.data.profiles.get(self.selected_target - 1) {
            let state_str = if prof.enabled { "ON" } else { "OFF" };
            let phase_str = match &prof.phase_binding {
                Some(b) => format!(" | Phase: {}/{}", b.app_name, b.env_name),
                None => String::new(),
            };
            format!(
                "Profile #{}: {} [{}]{}",
                self.selected_target, prof.name, state_str, phase_str
            )
        } else {
            "Unknown".to_string()
        }
    }

    pub fn clamp_selections(&mut self) {
        let max_target = self.data.profiles.len(); // 0 is Default, 1..=len are profiles
        if self.selected_target > max_target {
            self.selected_target = max_target;
        }
        let vars_len = self.current_vars().len();
        if vars_len == 0 {
            self.selected_var = 0;
        } else if self.selected_var >= vars_len {
            self.selected_var = vars_len - 1;
        }
        let eff_len = self.data.compute_effective_vars().len();
        if eff_len == 0 {
            self.selected_effective = 0;
        } else if self.selected_effective >= eff_len {
            self.selected_effective = eff_len - 1;
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Global Ctrl+C quit
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        if !matches!(self.modal, Modal::None) {
            self.handle_modal_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    FocusPane::Profiles => FocusPane::Vars,
                    FocusPane::Vars => FocusPane::Effective,
                    FocusPane::Effective => FocusPane::Profiles,
                };
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    FocusPane::Profiles => FocusPane::Effective,
                    FocusPane::Vars => FocusPane::Profiles,
                    FocusPane::Effective => FocusPane::Vars,
                };
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.focus = FocusPane::Profiles;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if self.focus == FocusPane::Profiles {
                    self.focus = FocusPane::Vars;
                }
            }
            KeyCode::Char('v') => {
                self.show_values = !self.show_values;
                let state = if self.show_values { "shown" } else { "masked" };
                self.set_info(format!("Secret values are now {}.", state));
            }
            KeyCode::Char('c') => {
                self.modal = Modal::PhaseConnect {
                    host_mode: self.data.phase.host_mode,
                    custom_url: self.data.phase.custom_url.clone(),
                    pat_token: self.data.phase.pat_token.clone(),
                    active_field: 0,
                    error: None,
                };
            }
            KeyCode::Char('n') => {
                self.modal = Modal::NewProfile {
                    name: String::new(),
                    pull_from_phase: self.data.phase.is_configured(),
                    active_field: 0,
                    error: None,
                };
            }
            KeyCode::Char('a') => {
                self.modal = Modal::VarEditor {
                    is_edit: false,
                    original_index: None,
                    var_key: String::new(),
                    var_value: String::new(),
                    active_field: 0,
                    error: None,
                };
            }
            KeyCode::Char('p') => {
                let target_profile = if self.selected_target == 0 {
                    None
                } else {
                    Some(self.selected_target - 1)
                };
                self.open_phase_picker(target_profile, None);
            }
            KeyCode::Char('r') => {
                self.reload_shell();
            }
            _ => match self.focus {
                FocusPane::Profiles => self.handle_profiles_pane_key(key),
                FocusPane::Vars => self.handle_vars_pane_key(key),
                FocusPane::Effective => self.handle_effective_pane_key(key),
            },
        }
    }

    fn handle_profiles_pane_key(&mut self, key: KeyEvent) {
        let total_items = 1 + self.data.profiles.len(); // 0 = Default
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT)
                {
                    self.move_selected_profile_up();
                } else if self.selected_target > 0 {
                    self.selected_target -= 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT)
                {
                    self.move_selected_profile_down();
                } else if self.selected_target + 1 < total_items {
                    self.selected_target += 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Char('K') | KeyCode::Char('u') => {
                self.move_selected_profile_up();
            }
            KeyCode::Char('J') | KeyCode::Char('d') => {
                self.move_selected_profile_down();
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                if self.selected_target == 0 {
                    self.set_info("Default profile is always active by design.");
                } else if let Some(prof) = self.data.profiles.get_mut(self.selected_target - 1) {
                    prof.enabled = !prof.enabled;
                    let name = prof.name.clone();
                    let status = if prof.enabled { "ON" } else { "OFF" };
                    self.sync_to_system(&format!("Toggled profile '{}' {}", name, status));
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if self.selected_target == 0 {
                    self.set_error("Cannot delete Default profile.");
                } else if let Some(prof) = self.data.profiles.get(self.selected_target - 1) {
                    self.modal = Modal::ConfirmDeleteProfile {
                        profile_idx: self.selected_target - 1,
                        profile_name: prof.name.clone(),
                    };
                }
            }
            _ => {}
        }
    }

    fn move_selected_profile_up(&mut self) {
        if self.selected_target <= 1 {
            if self.selected_target == 1 {
                self.set_info("Profile is already at top priority (#1).");
            }
            return;
        }
        let idx = self.selected_target - 1;
        self.data.profiles.swap(idx, idx - 1);
        self.selected_target -= 1;
        let name = self.data.profiles[self.selected_target - 1].name.clone();
        self.sync_to_system(&format!(
            "Moved profile '{}' up to priority #{}",
            name, self.selected_target
        ));
    }

    fn move_selected_profile_down(&mut self) {
        if self.selected_target == 0 || self.selected_target >= self.data.profiles.len() {
            return;
        }
        let idx = self.selected_target - 1;
        self.data.profiles.swap(idx, idx + 1);
        self.selected_target += 1;
        let name = self.data.profiles[self.selected_target - 1].name.clone();
        self.sync_to_system(&format!(
            "Moved profile '{}' down to priority #{}",
            name, self.selected_target
        ));
    }

    fn handle_vars_pane_key(&mut self, key: KeyEvent) {
        let len = self.current_vars().len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_var > 0 {
                    self.selected_var -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_var + 1 < len {
                    self.selected_var += 1;
                }
            }
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(var) = self.current_vars().get(self.selected_var) {
                    self.modal = Modal::VarEditor {
                        is_edit: true,
                        original_index: Some(self.selected_var),
                        var_key: var.key.clone(),
                        var_value: var.value.clone(),
                        active_field: 1, // Focus value by default when editing
                        error: None,
                    };
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(var) = self.current_vars().get(self.selected_var) {
                    self.modal = Modal::ConfirmDeleteVar {
                        var_idx: self.selected_var,
                        var_key: var.key.clone(),
                    };
                }
            }
            _ => {}
        }
    }

    fn handle_effective_pane_key(&mut self, key: KeyEvent) {
        let len = self.data.compute_effective_vars().len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_effective > 0 {
                    self.selected_effective -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_effective + 1 < len {
                    self.selected_effective += 1;
                }
            }
            _ => {}
        }
    }

    fn open_phase_picker(
        &mut self,
        target_profile_idx: Option<usize>,
        new_profile_name: Option<String>,
    ) {
        if !self.data.phase.is_configured() {
            self.modal = Modal::PhaseConnect {
                host_mode: self.data.phase.host_mode,
                custom_url: self.data.phase.custom_url.clone(),
                pat_token: self.data.phase.pat_token.clone(),
                active_field: 0,
                error: Some("Please configure Phase.dev connection first.".to_string()),
            };
            return;
        }

        match fetch_apps_and_envs(&self.data.phase) {
            Ok(apps) => {
                if apps.is_empty() {
                    self.set_error("Connected to Phase.dev, but no Apps were found for this PAT.");
                    return;
                }
                self.cached_apps = apps.clone();
                self.modal = Modal::PhasePicker {
                    target_profile_idx,
                    new_profile_name,
                    apps,
                    selected_app: 0,
                    selected_env: 0,
                    selecting_env: false,
                    error: None,
                };
            }
            Err(e) => {
                self.set_error(format!("Phase.dev error: {}", e));
                self.modal = Modal::PhaseConnect {
                    host_mode: self.data.phase.host_mode,
                    custom_url: self.data.phase.custom_url.clone(),
                    pat_token: self.data.phase.pat_token.clone(),
                    active_field: 0,
                    error: Some(e),
                };
            }
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => {}
            Modal::PhaseConnect {
                mut host_mode,
                mut custom_url,
                mut pat_token,
                mut active_field,
                mut error,
            } => {
                let max_fields = match host_mode {
                    HostMode::Cloud => 2,      // 0 = Mode, 1 = PAT
                    HostMode::SelfHosted => 3, // 0 = Mode, 1 = URL, 2 = PAT
                };

                match key.code {
                    KeyCode::Esc => {
                        self.set_info("Closed Phase.dev setup.");
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        active_field = (active_field + 1) % max_fields;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        active_field = (active_field + max_fields - 1) % max_fields;
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                        if active_field == 0 =>
                    {
                        host_mode = match host_mode {
                            HostMode::Cloud => HostMode::SelfHosted,
                            HostMode::SelfHosted => HostMode::Cloud,
                        };
                        error = None;
                    }
                    KeyCode::Backspace => {
                        if host_mode == HostMode::SelfHosted && active_field == 1 {
                            custom_url.pop();
                        } else if (host_mode == HostMode::Cloud && active_field == 1)
                            || (host_mode == HostMode::SelfHosted && active_field == 2)
                        {
                            pat_token.pop();
                        }
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if host_mode == HostMode::SelfHosted && active_field == 1 {
                            custom_url.clear();
                        } else if (host_mode == HostMode::Cloud && active_field == 1)
                            || (host_mode == HostMode::SelfHosted && active_field == 2)
                        {
                            pat_token.clear();
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if host_mode == HostMode::SelfHosted && active_field == 1 {
                            custom_url.push(c);
                            error = None;
                        } else if (host_mode == HostMode::Cloud && active_field == 1)
                            || (host_mode == HostMode::SelfHosted && active_field == 2)
                        {
                            pat_token.push(c);
                            error = None;
                        }
                    }
                    KeyCode::Enter => {
                        if host_mode == HostMode::SelfHosted && custom_url.trim().is_empty() {
                            error = Some("Self-hosted URL cannot be empty.".to_string());
                        } else if pat_token.trim().is_empty() {
                            error = Some("Personal Access Token (PAT) cannot be empty.".to_string());
                        } else {
                            let new_cfg = PhaseConfig {
                                host_mode,
                                custom_url: custom_url.trim().to_string(),
                                pat_token: pat_token.trim().to_string(),
                            };
                            match fetch_apps_and_envs(&new_cfg) {
                                Ok(apps) => {
                                    let app_count = apps.len();
                                    self.cached_apps = apps;
                                    self.data.phase = new_cfg;
                                    let _ = self.data.save();
                                    self.set_info(format!(
                                        "Connected to Phase.dev ({})! Found {} app(s).",
                                        self.data.phase.effective_host(),
                                        app_count
                                    ));
                                    return;
                                }
                                Err(e) => {
                                    // Allow saving with Ctrl+S if offline, otherwise show validation error
                                    error = Some(format!(
                                        "{} (Press Ctrl+S to save without testing)",
                                        e
                                    ));
                                }
                            }
                        }
                    }
                    _ => {}
                }

                // Allow Ctrl+S to force save config without online verification
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('s')
                {
                    self.data.phase = PhaseConfig {
                        host_mode,
                        custom_url: custom_url.trim().to_string(),
                        pat_token: pat_token.trim().to_string(),
                    };
                    let _ = self.data.save();
                    self.set_info(format!(
                        "Saved Phase.dev config ({})",
                        self.data.phase.effective_host()
                    ));
                    return;
                }

                self.modal = Modal::PhaseConnect {
                    host_mode,
                    custom_url,
                    pat_token,
                    active_field,
                    error,
                };
            }

            Modal::NewProfile {
                mut name,
                mut pull_from_phase,
                mut active_field,
                mut error,
            } => {
                match key.code {
                    KeyCode::Esc => {
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down | KeyCode::Up | KeyCode::BackTab => {
                        active_field = 1 - active_field;
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                        if active_field == 1 =>
                    {
                        pull_from_phase = !pull_from_phase;
                    }
                    KeyCode::Backspace if active_field == 0 => {
                        name.pop();
                        error = None;
                    }
                    KeyCode::Char(c)
                        if active_field == 0
                            && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        name.push(c);
                        error = None;
                    }
                    KeyCode::Enter => {
                        let trimmed = name.trim().to_string();
                        if trimmed.is_empty() {
                            error = Some("Profile name cannot be empty.".to_string());
                        } else if self
                            .data
                            .profiles
                            .iter()
                            .any(|p| p.name.eq_ignore_ascii_case(&trimmed))
                        {
                            error = Some(format!("Profile '{}' already exists.", trimmed));
                        } else if pull_from_phase {
                            self.open_phase_picker(None, Some(trimmed));
                            return;
                        } else {
                            // Insert at top of profile list so new profile is #1 or at end
                            self.data.profiles.insert(
                                0,
                                Profile {
                                    name: trimmed.clone(),
                                    enabled: true,
                                    phase_binding: None,
                                    vars: Vec::new(),
                                },
                            );
                            self.selected_target = 1;
                            self.selected_var = 0;
                            self.sync_to_system(&format!(
                                "Created custom profile '{}' at priority #1",
                                trimmed
                            ));
                            return;
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::NewProfile {
                    name,
                    pull_from_phase,
                    active_field,
                    error,
                };
            }

            Modal::PhasePicker {
                target_profile_idx,
                new_profile_name,
                apps,
                mut selected_app,
                mut selected_env,
                mut selecting_env,
                mut error,
            } => {
                let env_count = apps
                    .get(selected_app)
                    .map(|a| a.environments.len())
                    .unwrap_or(0);

                match key.code {
                    KeyCode::Esc => {
                        if selecting_env {
                            selecting_env = false;
                        } else {
                            return;
                        }
                    }
                    KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                        if env_count > 0 {
                            selecting_env = !selecting_env;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if !selecting_env {
                            if selected_app > 0 {
                                selected_app -= 1;
                                selected_env = 0;
                            }
                        } else if selected_env > 0 {
                            selected_env -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !selecting_env {
                            if selected_app + 1 < apps.len() {
                                selected_app += 1;
                                selected_env = 0;
                            }
                        } else if selected_env + 1 < env_count {
                            selected_env += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if !selecting_env {
                            if env_count == 0 {
                                error = Some("Selected App has no environments.".to_string());
                            } else {
                                selecting_env = true;
                            }
                        } else if let Some(app) = apps.get(selected_app) {
                            if let Some(env) = app.environments.get(selected_env) {
                                match fetch_secrets_for_env(&self.data.phase, &app.id, &env.id) {
                                    Ok(fetched_pairs) => {
                                        let fetched_len = fetched_pairs.len();
                                        let binding = PhaseBinding {
                                            app_id: app.id.clone(),
                                            app_name: app.name.clone(),
                                            env_id: env.id.clone(),
                                            env_name: env.name.clone(),
                                        };

                                        if let Some(prof_name) = new_profile_name {
                                            let mut vars = Vec::new();
                                            AppStateData::merge_phase_vars(
                                                &mut vars,
                                                &app.name,
                                                &env.name,
                                                fetched_pairs,
                                            );
                                            self.data.profiles.insert(
                                                0,
                                                Profile {
                                                    name: prof_name.clone(),
                                                    enabled: true,
                                                    phase_binding: Some(binding),
                                                    vars,
                                                },
                                            );
                                            self.selected_target = 1;
                                            self.selected_var = 0;
                                            self.sync_to_system(&format!(
                                                "Created profile '{}' with {} var(s) from Phase ({}/{})",
                                                prof_name, fetched_len, app.name, env.name
                                            ));
                                        } else if let Some(idx) = target_profile_idx {
                                            if let Some(prof) = self.data.profiles.get_mut(idx) {
                                                prof.phase_binding = Some(binding);
                                                AppStateData::merge_phase_vars(
                                                    &mut prof.vars,
                                                    &app.name,
                                                    &env.name,
                                                    fetched_pairs,
                                                );
                                                let pname = prof.name.clone();
                                                self.sync_to_system(&format!(
                                                    "Pulled {} var(s) from Phase ({}/{}) into '{}'",
                                                    fetched_len, app.name, env.name, pname
                                                ));
                                            }
                                        } else {
                                            AppStateData::merge_phase_vars(
                                                &mut self.data.default_vars,
                                                &app.name,
                                                &env.name,
                                                fetched_pairs,
                                            );
                                            self.sync_to_system(&format!(
                                                "Pulled {} var(s) from Phase ({}/{}) into Default",
                                                fetched_len, app.name, env.name
                                            ));
                                        }
                                        self.clamp_selections();
                                        return;
                                    }
                                    Err(e) => {
                                        error = Some(e);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::PhasePicker {
                    target_profile_idx,
                    new_profile_name,
                    apps,
                    selected_app,
                    selected_env,
                    selecting_env,
                    error,
                };
            }

            Modal::VarEditor {
                is_edit,
                original_index,
                mut var_key,
                mut var_value,
                mut active_field,
                mut error,
            } => {
                match key.code {
                    KeyCode::Esc => {
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down | KeyCode::Up | KeyCode::BackTab => {
                        active_field = 1 - active_field;
                    }
                    KeyCode::Backspace => {
                        if active_field == 0 {
                            var_key.pop();
                        } else {
                            var_value.pop();
                        }
                        error = None;
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if active_field == 0 {
                            var_key.clear();
                        } else {
                            var_value.clear();
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if active_field == 0 {
                            var_key.push(c);
                        } else {
                            var_value.push(c);
                        }
                        error = None;
                    }
                    KeyCode::Enter => {
                        let k = var_key.trim().to_string();
                        if !is_valid_env_key(&k) {
                            error = Some(
                                "Invalid variable name. Use letters, digits, '_' (cannot start with digit)."
                                    .to_string(),
                            );
                        } else {
                            let vars = self.current_vars_mut();
                            if is_edit {
                                if let Some(idx) = original_index {
                                    if let Some(v) = vars.get_mut(idx) {
                                        v.key = k.clone();
                                        v.value = var_value.clone();
                                    }
                                }
                            } else {
                                AppStateData::upsert_custom_var(vars, k.clone(), var_value.clone());
                            }
                            self.clamp_selections();
                            let target_name = if self.selected_target == 0 {
                                "Default".to_string()
                            } else {
                                self.data.profiles[self.selected_target - 1].name.clone()
                            };
                            self.sync_to_system(&format!(
                                "Saved variable '{}' in '{}'",
                                k, target_name
                            ));
                            return;
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::VarEditor {
                    is_edit,
                    original_index,
                    var_key,
                    var_value,
                    active_field,
                    error,
                };
            }

            Modal::ConfirmDeleteProfile {
                profile_idx,
                profile_name,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if profile_idx < self.data.profiles.len() {
                        self.data.profiles.remove(profile_idx);
                        self.clamp_selections();
                        self.sync_to_system(&format!("Deleted profile '{}'", profile_name));
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => {
                    self.modal = Modal::ConfirmDeleteProfile {
                        profile_idx,
                        profile_name,
                    };
                }
            },

            Modal::ConfirmDeleteVar { var_idx, var_key } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let vars = self.current_vars_mut();
                    if var_idx < vars.len() {
                        vars.remove(var_idx);
                        self.clamp_selections();
                        self.sync_to_system(&format!("Deleted variable '{}'", var_key));
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => {
                    self.modal = Modal::ConfirmDeleteVar { var_idx, var_key };
                }
            },
        }
    }

    pub fn draw(&self, frame: &mut Frame) {
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Top header
                Constraint::Min(12),   // Main body
                Constraint::Length(3), // Bottom keybindings & status
            ])
            .split(frame.area());

        self.draw_header(frame, root_chunks[0]);
        self.draw_body(frame, root_chunks[1]);
        self.draw_footer(frame, root_chunks[2]);

        if !matches!(self.modal, Modal::None) {
            self.draw_modal(frame, frame.area());
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let phase_status = if self.data.phase.is_configured() {
            let mode_str = match self.data.phase.host_mode {
                HostMode::Cloud => format!("Cloud ({})", PHASE_CLOUD_HOST),
                HostMode::SelfHosted => format!("Self-Hosted ({})", self.data.phase.effective_host()),
            };
            Span::styled(
                format!(" Connected: {} ", mode_str),
                Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                " Optional / Offline ([c] Connect) ",
                Style::default().fg(Color::Gray),
            )
        };

        let state_path = AppStateData::state_file_path();
        let line = Line::from(vec![
            Span::styled(
                " envmgr ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("| Phase.dev: "),
            phase_status,
            Span::raw(" | Encrypted Store: "),
            Span::styled(
                state_path.to_string_lossy().into_owned(),
                Style::default().fg(Color::Gray),
            ),
        ]);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Environment & Phase.dev Manager ");
        frame.render_widget(Paragraph::new(line).block(block), area);
    }

    fn draw_body(&self, frame: &mut Frame, area: Rect) {
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
            .split(area);

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(main_chunks[1]);

        self.draw_profiles_pane(frame, main_chunks[0]);
        self.draw_vars_pane(frame, right_chunks[0]);
        self.draw_effective_pane(frame, right_chunks[1]);
    }

    fn draw_profiles_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == FocusPane::Profiles;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let mut items: Vec<ListItem> = Vec::with_capacity(1 + self.data.profiles.len());

        // Item 0: Default
        let default_line = Line::from(vec![
            Span::styled("[★] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(
                "Default",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" ({} vars, base)", self.data.default_vars.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        items.push(ListItem::new(default_line));

        // Profiles 1..=N (Top wins priority)
        for (idx, prof) in self.data.profiles.iter().enumerate() {
            let check = if prof.enabled { "[✓] " } else { "[ ] " };
            let check_style = if prof.enabled {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let name_style = if prof.enabled {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let badge = match &prof.phase_binding {
                Some(b) => format!(" [Phase:{}/{}]", b.app_name, b.env_name),
                None => " [Custom]".to_string(),
            };

            let line = Line::from(vec![
                Span::styled(check, check_style),
                Span::styled(
                    format!("#{} ", idx + 1),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(&prof.name, name_style),
                Span::styled(
                    format!(" ({}v){}", prof.vars.len(), badge),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }

        let title = " 1. Default & Profiles (Top #1 Wins Priority) ";
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .title(title),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(35, 55, 85))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        state.select(Some(self.selected_target));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_vars_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == FocusPane::Vars;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let vars = self.current_vars();
        let rows: Vec<Row> = vars
            .iter()
            .map(|v| {
                let val_display = if self.show_values {
                    v.value.clone()
                } else if v.value.is_empty() {
                    "<empty>".to_string()
                } else {
                    "••••••••".to_string()
                };
                Row::new(vec![v.key.clone(), val_display, v.source.label()])
            })
            .collect();

        let header = Row::new(vec!["KEY", "VALUE ([v] show/hide)", "SOURCE"])
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(35),
                Constraint::Percentage(38),
                Constraint::Percentage(27),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(format!(" 2. Variables in {} ", self.current_target_title())),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(35, 55, 85))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut state = TableState::default();
        if !vars.is_empty() {
            state.select(Some(self.selected_var));
        }
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_effective_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == FocusPane::Effective;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let effective = self.data.compute_effective_vars();
        let rows: Vec<Row> = effective
            .iter()
            .map(|ev| {
                let val_display = if self.show_values {
                    ev.value.clone()
                } else if ev.value.is_empty() {
                    "<empty>".to_string()
                } else {
                    "••••••••".to_string()
                };
                Row::new(vec![
                    ev.key.clone(),
                    val_display,
                    ev.winning_owner.clone(),
                    ev.source_label.clone(),
                ])
            })
            .collect();

        let header = Row::new(vec!["EXPORTED KEY", "EFFECTIVE VALUE", "WINNING PROFILE", "ORIGIN"])
            .style(
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            );

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(28),
                Constraint::Percentage(30),
                Constraint::Percentage(24),
                Constraint::Percentage(18),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(format!(
                    " 3. Active System Environment ({} encrypted in state.enc, injected at runtime) ",
                    effective.len()
                )),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(35, 55, 85))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut state = TableState::default();
        if !effective.is_empty() {
            state.select(Some(self.selected_effective));
        }
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let status_style = if self.is_error_status {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };

        let text = vec![
            Line::from(vec![
                Span::styled(
                    "[Space]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Toggle ON/OFF  "),
                Span::styled(
                    "[K/J or u/d]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Move Priority Up/Down  "),
                Span::styled(
                    "[n]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" New Profile  "),
                Span::styled(
                    "[a]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Add Custom Var  "),
                Span::styled(
                    "[e]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Edit  "),
                Span::styled(
                    "[x]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Delete  "),
                Span::styled(
                    "[p]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Pull Phase.dev  "),
                Span::styled(
                    "[c]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Phase Auth  "),
                Span::styled(
                    "[v]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Show/Hide  "),
                Span::styled(
                    "[r]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Reload Shell  "),
                Span::styled(
                    "[q]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Quit"),
            ]),
            Line::from(Span::styled(&self.status_message, status_style)),
        ];

        let p = Paragraph::new(text);
        frame.render_widget(p, area);
    }

    fn draw_modal(&self, frame: &mut Frame, area: Rect) {
        match &self.modal {
            Modal::None => {}
            Modal::PhaseConnect {
                host_mode,
                custom_url,
                pat_token,
                active_field,
                error,
            } => {
                let popup = centered_rect(70, 55, area);
                frame.render_widget(Clear, popup);

                let mode_str = match host_mode {
                    HostMode::Cloud => {
                        format!("◄ Cloud (Official: {}) ►", PHASE_CLOUD_HOST)
                    }
                    HostMode::SelfHosted => "◄ Self-Hosted (Custom URL) ►".to_string(),
                };

                let f0_style = field_style(*active_field == 0);
                let mut lines = vec![
                    Line::from(Span::styled(
                        "Connect to Phase.dev using Personal Access Token (PAT)",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("1. Server Mode (Space/Left/Right): ", Style::default().fg(Color::Yellow)),
                        Span::styled(mode_str, f0_style),
                    ]),
                    Line::from(""),
                ];

                if *host_mode == HostMode::SelfHosted {
                    let f1_style = field_style(*active_field == 1);
                    lines.push(Line::from(Span::styled(
                        "2. Self-Hosted Console URL (e.g. https://phase.yourdomain.com):",
                        Style::default().fg(Color::Yellow),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!(" > {}█", custom_url),
                        f1_style,
                    )));
                    lines.push(Line::from(""));
                }

                let pat_idx = if *host_mode == HostMode::Cloud { 1 } else { 2 };
                let f_pat_style = field_style(*active_field == pat_idx);
                let masked_pat = if pat_token.len() > 18 {
                    format!("{}...{}", &pat_token[..14], &pat_token[pat_token.len() - 4..])
                } else {
                    pat_token.clone()
                };

                lines.push(Line::from(Span::styled(
                    format!("{}. Phase PAT / Service Token (pss_user:v1:... or pss_service:v2:...):", pat_idx + 1),
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(Span::styled(
                    format!(" > {}█", masked_pat),
                    f_pat_style,
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "[Tab/Up/Down] Switch Field  |  [Enter] Verify & Connect  |  [Ctrl+S] Save Offline  |  [Esc] Close",
                    Style::default().fg(Color::Gray),
                )));

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("Error: {}", err),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Phase.dev Connection Setup ");
                frame.render_widget(
                    Paragraph::new(lines).wrap(Wrap { trim: false }).block(block),
                    popup,
                );
            }

            Modal::NewProfile {
                name,
                pull_from_phase,
                active_field,
                error,
            } => {
                let popup = centered_rect(60, 45, area);
                frame.render_widget(Clear, popup);

                let src_str = if *pull_from_phase {
                    "◄ Pull from Phase.dev (Select App & Env) ►"
                } else {
                    "◄ Custom Profile (Manual Variables) ►"
                };

                let mut lines = vec![
                    Line::from(Span::styled(
                        "Create New Environment Profile",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "1. Profile Name:",
                        Style::default().fg(Color::Yellow),
                    )),
                    Line::from(Span::styled(
                        format!(" > {}█", name),
                        field_style(*active_field == 0),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "2. Initial Variable Source (Space/Left/Right):",
                        Style::default().fg(Color::Yellow),
                    )),
                    Line::from(Span::styled(
                        format!("   {}", src_str),
                        field_style(*active_field == 1),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "(Note: You can always add custom manual variables [a] or pull from Phase [p] later)",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "[Tab] Switch Field  |  [Enter] Continue  |  [Esc] Cancel",
                        Style::default().fg(Color::Gray),
                    )),
                ];

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("Error: {}", err),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" New Profile ");
                frame.render_widget(
                    Paragraph::new(lines).wrap(Wrap { trim: false }).block(block),
                    popup,
                );
            }

            Modal::PhasePicker {
                apps,
                selected_app,
                selected_env,
                selecting_env,
                error,
                ..
            } => {
                let popup = centered_rect(72, 60, area);
                frame.render_widget(Clear, popup);

                let inner = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(8),
                        Constraint::Length(3),
                    ])
                    .split(popup);

                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(inner[0]);

                let app_items: Vec<ListItem> = apps
                    .iter()
                    .map(|a| {
                        ListItem::new(format!("{} ({} envs)", a.name, a.environments.len()))
                    })
                    .collect();

                let app_border = if !*selecting_env {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let app_list = List::new(app_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(app_border)
                            .title(" 1. Select Phase App "),
                    )
                    .highlight_style(
                        Style::default()
                            .bg(Color::Rgb(35, 55, 85))
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("▶ ");
                let mut app_state = ListState::default();
                app_state.select(Some(*selected_app));
                frame.render_stateful_widget(app_list, cols[0], &mut app_state);

                let env_items: Vec<ListItem> = apps
                    .get(*selected_app)
                    .map(|a| {
                        a.environments
                            .iter()
                            .map(|e| ListItem::new(e.name.clone()))
                            .collect()
                    })
                    .unwrap_or_default();

                let env_border = if *selecting_env {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let env_list = List::new(env_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(env_border)
                            .title(" 2. Select Environment "),
                    )
                    .highlight_style(
                        Style::default()
                            .bg(Color::Rgb(35, 55, 85))
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("▶ ");
                let mut env_state = ListState::default();
                env_state.select(Some(*selected_env));
                frame.render_stateful_widget(env_list, cols[1], &mut env_state);

                let footer_msg = if let Some(err) = error {
                    Line::from(Span::styled(
                        format!("Error: {}", err),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ))
                } else {
                    Line::from(Span::styled(
                        "[Up/Down] Navigate  |  [Tab/Enter] Switch App -> Env  |  [Enter on Env] Pull Secrets  |  [Esc] Cancel",
                        Style::default().fg(Color::Gray),
                    ))
                };

                frame.render_widget(
                    Paragraph::new(footer_msg).block(Block::default().borders(Borders::ALL)),
                    inner[1],
                );
            }

            Modal::VarEditor {
                is_edit,
                var_key,
                var_value,
                active_field,
                error,
                ..
            } => {
                let popup = centered_rect(60, 42, area);
                frame.render_widget(Clear, popup);

                let title = if *is_edit {
                    " Edit Environment Variable "
                } else {
                    " Add Custom Environment Variable "
                };

                let mut lines = vec![
                    Line::from(Span::styled(
                        format!("Target: {}", self.current_target_title()),
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "1. Variable Name (KEY):",
                        Style::default().fg(Color::Yellow),
                    )),
                    Line::from(Span::styled(
                        format!(" > {}█", var_key),
                        field_style(*active_field == 0),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "2. Variable Value (VALUE):",
                        Style::default().fg(Color::Yellow),
                    )),
                    Line::from(Span::styled(
                        format!(" > {}█", var_value),
                        field_style(*active_field == 1),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "[Tab/Up/Down] Switch Field  |  [Enter] Save & Export  |  [Esc] Cancel",
                        Style::default().fg(Color::Gray),
                    )),
                ];

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("Error: {}", err),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(title);
                frame.render_widget(
                    Paragraph::new(lines).wrap(Wrap { trim: false }).block(block),
                    popup,
                );
            }

            Modal::ConfirmDeleteProfile { profile_name, .. } => {
                let popup = centered_rect(50, 25, area);
                frame.render_widget(Clear, popup);
                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Delete profile '{}'?", profile_name),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from("Press [y / Enter] to confirm, or [n / Esc] to cancel."),
                ];
                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(" Confirm Delete Profile ");
                frame.render_widget(Paragraph::new(lines).block(block), popup);
            }

            Modal::ConfirmDeleteVar { var_key, .. } => {
                let popup = centered_rect(50, 25, area);
                frame.render_widget(Clear, popup);
                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Delete variable '{}'?", var_key),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from("Press [y / Enter] to confirm, or [n / Esc] to cancel."),
                ];
                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(" Confirm Delete Variable ");
                frame.render_widget(Paragraph::new(lines).block(block), popup);
            }
        }
    }
    pub fn handle_paste(&mut self, pasted: &str) {
        let clean = pasted.trim_matches(|c| c == '\r' || c == '\n');
        match &mut self.modal {
            Modal::PhaseConnect {
                host_mode,
                custom_url,
                pat_token,
                active_field,
                error,
            } => {
                if *host_mode == HostMode::SelfHosted && *active_field == 1 {
                    custom_url.push_str(clean);
                    *error = None;
                } else if (*host_mode == HostMode::Cloud && *active_field == 1)
                    || (*host_mode == HostMode::SelfHosted && *active_field == 2)
                {
                    pat_token.push_str(clean);
                    *error = None;
                }
            }
            Modal::NewProfile {
                name,
                active_field,
                error,
                ..
            } => {
                if *active_field == 0 {
                    name.push_str(clean);
                    *error = None;
                }
            }
            Modal::VarEditor {
                var_key,
                var_value,
                active_field,
                error,
                ..
            } => {
                if *active_field == 0 {
                    var_key.push_str(clean);
                } else {
                    var_value.push_str(clean);
                }
                *error = None;
            }
            _ => {}
        }
    }
}

fn field_style(active: bool) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn run_tui() -> Result<(), String> {
    let data = AppStateData::load();
    let mut app = App::new(data);

    crossterm::terminal::enable_raw_mode()
        .map_err(|e| format!("Failed to enable terminal raw mode: {}", e))?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableBracketedPaste
    )
    .map_err(|e| format!("Failed to enter alternate screen: {}", e))?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal =
        ratatui::Terminal::new(backend).map_err(|e| format!("Failed to init terminal: {}", e))?;

    let res = (|| -> Result<(), String> {
        loop {
            terminal
                .draw(|f| app.draw(f))
                .map_err(|e| format!("Draw error: {}", e))?;

            if app.should_quit {
                break;
            }

            if event::poll(std::time::Duration::from_millis(250))
                .map_err(|e| format!("Event poll error: {}", e))?
            {
                match event::read().map_err(|e| format!("Event read error: {}", e))? {
                    Event::Key(key) => app.handle_key(key),
                    Event::Paste(text) => app.handle_paste(&text),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    let _ = crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableBracketedPaste,
        crossterm::terminal::LeaveAlternateScreen
    );
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = terminal.show_cursor();

    // Ensure state is applied on exit
    let _ = apply_state_to_system(&app.data);

    res
}
