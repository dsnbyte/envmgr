use crate::model::{
    is_valid_env_key, AppSettings, AppStateData, EnvVar, HostMode, PhaseAuthMethod, PhaseBinding,
    PhaseConfig, Profile, PHASE_CLOUD_HOST,
};
use crate::phase::{
    detect_phase_cli_detailed, fetch_apps_and_envs, fetch_secrets_for_env, sync_phase_profiles,
    try_detect_local_phase_cli_host, PhaseAppInfo, PhaseCliStatus,
};
use crate::shell::{apply_state_to_system, reload_shell_environment};
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Row,
        Table, TableState, Wrap,
    },
    Frame,
};
use std::time::{Duration, Instant};

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
        auth_method: PhaseAuthMethod,
        host_mode: HostMode,
        custom_url: String,
        pat_token: String,
        cli_status: PhaseCliStatus,
        active_field: usize,
        pending_new_profile: Option<String>,
        error: Option<String>,
    },
    NewProfile {
        name: String,
        pull_from_phase: bool,
        active_field: usize, // 0 = name, 1 = data source
        error: Option<String>,
    },
    PhasePicker {
        target_profile_idx: Option<usize>,
        new_profile_name: Option<String>,
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
    EditProfile {
        profile_idx: usize,
        name: String,
        error: Option<String>,
    },
    Settings {
        draft: AppSettings,
        active_field: usize, // 0..5
        error: Option<String>,
    },
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextAction {
    ToggleProfile,
    Edit,
    Delete,
    MoveUp,
    MoveDown,
    NewProfile,
    AddVar,
    PhaseSync,
    PhaseRebind,
    ToggleMask,
    ReloadShell,
}

#[derive(Debug, Clone)]
pub struct ContextMenuItem {
    pub label: String,
    pub shortcut: &'static str,
    pub action: ContextAction,
    pub is_danger: bool,
}

#[derive(Debug, Clone)]
pub struct ContextMenu {
    pub x: u16,
    pub y: u16,
    pub title: String,
    pub items: Vec<ContextMenuItem>,
    pub selected: usize,
}

impl ContextMenu {
    pub fn rect(&self, area: Rect) -> Rect {
        let content_width = self
            .items
            .iter()
            .map(|item| item.label.len() + item.shortcut.len() + 7)
            .max()
            .unwrap_or(24)
            .max(self.title.len() + 4) as u16;
        let width = content_width.clamp(26, 40).min(area.width.saturating_sub(2));
        let height = (self.items.len() as u16 + 2).min(area.height.saturating_sub(1));
        let x = self.x.min(area.width.saturating_sub(width));
        let y = self.y.min(area.height.saturating_sub(height));
        Rect::new(x, y, width, height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSyncTarget {
    Profile(usize),
    All,
}

pub struct App {
    pub data: AppStateData,
    pub focus: FocusPane,
    pub selected_profile: usize,
    pub selected_var: usize,
    pub selected_effective: usize,
    pub show_values: bool,
    pub modal: Modal,
    pub context_menu: Option<ContextMenu>,
    pub status_message: String,
    pub is_error_status: bool,
    pub status_message_time: Option<Instant>,
    pub should_quit: bool,
    pub cached_apps: Vec<PhaseAppInfo>,
    pub last_area: Rect,
    pub pending_phase_sync: Option<PendingSyncTarget>,
    pub input_cursor: usize,
}

impl App {
    pub fn new(mut data: AppStateData) -> Self {
        data.phase.auto_detect_cli();

        if !data.phase.is_configured() {
            if let Some((mode, url)) = try_detect_local_phase_cli_host() {
                data.phase.host_mode = mode;
                if !url.is_empty() && data.phase.custom_url.is_empty() {
                    data.phase.custom_url = url;
                }
            }
        }

        let show_values = !data.settings.mask_secrets_by_default;

        let mut app = Self {
            data,
            focus: FocusPane::Profiles,
            selected_profile: 0,
            selected_var: 0,
            selected_effective: 0,
            show_values,
            modal: Modal::None,
            context_menu: None,
            status_message: String::new(),
            is_error_status: false,
            status_message_time: None,
            should_quit: false,
            cached_apps: Vec::new(),
            last_area: Rect::default(),
            pending_phase_sync: None,
            input_cursor: 0,
        };

        if !cfg!(test) {
            if let Err(e) = apply_state_to_system(&app.data) {
                app.set_error(e);
            }
        }

        app
    }

    pub fn set_info(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.is_error_status = false;
        self.status_message_time = Some(Instant::now());
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.is_error_status = true;
        self.status_message_time = None;
    }

    pub fn clear_expired_status(&mut self) {
        if !self.is_error_status && !self.status_message.is_empty() {
            if let Some(time) = self.status_message_time {
                if time.elapsed() >= Duration::from_secs(5) {
                    self.status_message.clear();
                    self.status_message_time = None;
                }
            }
        }
    }

    pub fn sync_to_system(&mut self, action_desc: &str) {
        if cfg!(test) {
            self.set_info(action_desc);
            return;
        }
        match apply_state_to_system(&self.data) {
            Ok(_) => {
                let effective = self.data.compute_effective_vars();
                let _ = reload_shell_environment(&effective);
                self.set_info(action_desc);
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
                            "Synced state.enc & shell environment ({} active variable(s) ready across sessions)",
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

    pub fn current_profile(&self) -> Option<&Profile> {
        self.data.profiles.get(self.selected_profile)
    }

    pub fn current_profile_mut(&mut self) -> Option<&mut Profile> {
        self.data.profiles.get_mut(self.selected_profile)
    }

    pub fn current_vars(&self) -> &[EnvVar] {
        if let Some(prof) = self.current_profile() {
            &prof.vars
        } else {
            &[]
        }
    }

    pub fn current_target_title(&self) -> String {
        if let Some(prof) = self.current_profile() {
            let state_str = if prof.enabled { "ON" } else { "OFF" };
            let phase_str = match &prof.phase_binding {
                Some(b) => format!(" | Phase: {}/{}", b.app_name, b.env_name),
                None => String::new(),
            };
            format!("Profile: {} [{}]{}", prof.name, state_str, phase_str)
        } else {
            "No Profile Selected".to_string()
        }
    }

    pub fn clamp_selections(&mut self) {
        if self.data.profiles.is_empty() {
            self.selected_profile = 0;
        } else if self.selected_profile >= self.data.profiles.len() {
            self.selected_profile = self.data.profiles.len() - 1;
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

    pub fn open_phase_connect_modal(&mut self, pending_new_profile: Option<String>, error: Option<String>) {
        let cli_status = detect_phase_cli_detailed();
        let auth_method = if self.data.phase.pat_token.trim().is_empty() && cli_status.installed {
            PhaseAuthMethod::Cli
        } else {
            self.data.phase.auth_method
        };
        self.input_cursor = 0;
        self.modal = Modal::PhaseConnect {
            auth_method,
            host_mode: self.data.phase.host_mode,
            custom_url: self.data.phase.custom_url.clone(),
            pat_token: self.data.phase.pat_token.clone(),
            cli_status,
            active_field: 0,
            pending_new_profile,
            error,
        };
    }

    pub fn open_settings_modal(&mut self) {
        let draft = self.data.settings.clone();
        self.modal = Modal::Settings {
            draft,
            active_field: 0,
            error: None,
        };
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        if self.context_menu.is_some() {
            self.handle_context_menu_key(key);
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
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.modal = Modal::Help;
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
                self.open_phase_connect_modal(None, None);
            }
            KeyCode::Char('s') => {
                self.open_settings_modal();
            }
            KeyCode::Char('n') => {
                self.modal = Modal::NewProfile {
                    name: String::new(),
                    pull_from_phase: false,
                    active_field: 0,
                    error: None,
                };
            }
            KeyCode::Char('a') => {
                let Some(prof) = self.current_profile() else {
                    self.set_error("No profile available. Create a profile first with [n].");
                    return;
                };
                if prof.is_phase() {
                    let pname = prof.name.clone();
                    self.set_error(format!(
                        "Profile '{}' uses Phase.dev synchronization. Sources cannot be mixed (create a Custom profile with [n]).",
                        pname
                    ));
                } else {
                    self.modal = Modal::VarEditor {
                        is_edit: false,
                        original_index: None,
                        var_key: String::new(),
                        var_value: String::new(),
                        active_field: 0,
                        error: None,
                    };
                }
            }
            KeyCode::Char('e') => {
                self.handle_edit_action();
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                self.handle_delete_action();
            }
            KeyCode::Char('p') => {
                self.handle_phase_sync_action(false);
            }
            KeyCode::Char('P') => {
                self.handle_phase_sync_action(true);
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

    fn handle_phase_sync_action(&mut self, force_rebind_picker: bool) {
        let Some(prof) = self.current_profile() else {
            self.set_error("No profile available. Press [n] to create a Phase.dev profile.");
            return;
        };

        if prof.is_phase() {
            let idx = self.selected_profile;
            if force_rebind_picker {
                self.open_phase_picker(Some(idx), None);
                return;
            }
            if !self.data.phase.is_configured() {
                self.open_phase_connect_modal(
                    None,
                    Some("Configure Phase.dev authentication to sync this profile.".to_string()),
                );
                return;
            }
            self.set_info("Phase.dev sync in progress...");
            self.pending_phase_sync = Some(PendingSyncTarget::Profile(idx));
        } else {
            // Selected profile is a Custom profile: never mix Phase vars into it.
            // If other Phase profiles exist, sync all Phase profiles; otherwise inform the user.
            let has_any_phase = self.data.profiles.iter().any(|p| p.is_phase());
            if has_any_phase {
                if !self.data.phase.is_configured() {
                    self.open_phase_connect_modal(
                        None,
                        Some("Configure Phase.dev authentication to sync Phase profiles.".to_string()),
                    );
                    return;
                }
                self.set_info("Phase.dev sync in progress...");
                self.pending_phase_sync = Some(PendingSyncTarget::All);
            } else {
                let pname = prof.name.clone();
                self.set_error(format!(
                    "Profile '{}' uses a Custom environment (sources cannot be mixed). Create a Phase.dev profile with [n].",
                    pname
                ));
            }
        }
    }

    pub fn perform_pending_sync(&mut self) -> bool {
        let Some(target) = self.pending_phase_sync.take() else {
            return false;
        };

        match target {
            PendingSyncTarget::Profile(idx) => {
                if idx >= self.data.profiles.len() {
                    return true;
                }
                match sync_phase_profiles(&mut self.data, Some(idx)) {
                    Ok((_, vars_count)) => {
                        self.clamp_selections();
                        let pname = self.data.profiles[idx].name.clone();
                        self.sync_to_system(&format!(
                            "Phase.dev sync succeeded for '{}' ({} vars)",
                            pname, vars_count
                        ));
                    }
                    Err(e) => {
                        self.set_error(format!("Phase.dev sync failed: {}", e));
                    }
                }
            }
            PendingSyncTarget::All => {
                let prof_names: Vec<String> = self
                    .data
                    .profiles
                    .iter()
                    .filter(|p| p.is_phase())
                    .map(|p| p.name.clone())
                    .collect();
                let prof_desc = if prof_names.len() == 1 {
                    format!("'{}'", prof_names[0])
                } else {
                    format!("{} profiles", prof_names.len())
                };

                match sync_phase_profiles(&mut self.data, None) {
                    Ok((_, vars_count)) => {
                        self.clamp_selections();
                        self.sync_to_system(&format!(
                            "Phase.dev sync succeeded for {} ({} vars)",
                            prof_desc, vars_count
                        ));
                    }
                    Err(e) => {
                        self.set_error(format!("Phase.dev sync failed: {}", e));
                    }
                }
            }
        }
        true
    }

    fn handle_edit_action(&mut self) {
        match self.focus {
            FocusPane::Profiles => {
                self.open_edit_profile();
            }
            FocusPane::Vars => {
                self.open_edit_var();
            }
            FocusPane::Effective => {
                self.open_edit_effective_var();
            }
        }
    }

    fn open_edit_profile(&mut self) {
        if let Some(prof) = self.current_profile() {
            let n = prof.name.clone();
            self.input_cursor = n.chars().count();
            self.modal = Modal::EditProfile {
                profile_idx: self.selected_profile,
                name: n,
                error: None,
            };
        } else {
            self.set_info("No profile selected to edit.");
        }
    }

    fn open_edit_var(&mut self) {
        let Some(prof) = self.current_profile() else {
            self.set_info("No profile selected.");
            return;
        };
        if prof.is_phase() {
            let pname = prof.name.clone();
            self.set_error(format!(
                "Profile '{}' is synced with Phase.dev. Variables cannot be edited manually (press [p] to sync).",
                pname
            ));
            return;
        }
        if let Some(var) = self.current_vars().get(self.selected_var).cloned() {
            self.input_cursor = var.value.chars().count();
            self.modal = Modal::VarEditor {
                is_edit: true,
                original_index: Some(self.selected_var),
                var_key: var.key,
                var_value: var.value,
                active_field: 1,
                error: None,
            };
        } else {
            self.set_info("No variable selected to edit.");
        }
    }

    fn open_edit_effective_var(&mut self) {
        let eff = self.data.compute_effective_vars();
        if let Some(ev) = eff.get(self.selected_effective) {
            for (p_idx, prof) in self.data.profiles.iter().enumerate() {
                if !prof.enabled {
                    continue;
                }
                if let Some(v_idx) = prof.vars.iter().position(|v| v.key == ev.key) {
                    if prof.is_phase() {
                        let pname = prof.name.clone();
                        let vkey = ev.key.clone();
                        self.set_error(format!(
                            "Variable '{}' belongs to Phase.dev profile '{}' and cannot be edited manually.",
                            vkey, pname
                        ));
                        return;
                    }
                    self.selected_profile = p_idx;
                    self.selected_var = v_idx;
                    self.focus = FocusPane::Vars;
                    let key = prof.vars[v_idx].key.clone();
                    let val = prof.vars[v_idx].value.clone();
                    self.input_cursor = val.chars().count();
                    self.modal = Modal::VarEditor {
                        is_edit: true,
                        original_index: Some(v_idx),
                        var_key: key,
                        var_value: val,
                        active_field: 1,
                        error: None,
                    };
                    return;
                }
            }
        }
        self.set_info("No effective variable selected to edit.");
    }

    fn handle_delete_action(&mut self) {
        match self.focus {
            FocusPane::Profiles => {
                if let Some(prof) = self.current_profile() {
                    self.modal = Modal::ConfirmDeleteProfile {
                        profile_idx: self.selected_profile,
                        profile_name: prof.name.clone(),
                    };
                }
            }
            FocusPane::Vars => {
                let Some(prof) = self.current_profile() else {
                    return;
                };
                if prof.is_phase() {
                    let pname = prof.name.clone();
                    self.set_error(format!(
                        "Profile '{}' is synced with Phase.dev. Manage variables in Phase.dev and press [p] to sync.",
                        pname
                    ));
                    return;
                }
                if let Some(var) = self.current_vars().get(self.selected_var) {
                    self.modal = Modal::ConfirmDeleteVar {
                        var_idx: self.selected_var,
                        var_key: var.key.clone(),
                    };
                }
            }
            FocusPane::Effective => {
                self.open_delete_effective_var();
            }
        }
    }

    fn open_delete_effective_var(&mut self) {
        let eff = self.data.compute_effective_vars();
        if let Some(ev) = eff.get(self.selected_effective) {
            for (p_idx, prof) in self.data.profiles.iter().enumerate() {
                if !prof.enabled {
                    continue;
                }
                if let Some(v_idx) = prof.vars.iter().position(|v| v.key == ev.key) {
                    if prof.is_phase() {
                        let pname = prof.name.clone();
                        let vkey = ev.key.clone();
                        self.set_error(format!(
                            "Variable '{}' belongs to Phase.dev profile '{}' and cannot be deleted manually.",
                            vkey, pname
                        ));
                        return;
                    }
                    self.selected_profile = p_idx;
                    self.selected_var = v_idx;
                    self.focus = FocusPane::Vars;
                    self.modal = Modal::ConfirmDeleteVar {
                        var_idx: v_idx,
                        var_key: ev.key.clone(),
                    };
                    return;
                }
            }
        }
        self.set_info("No effective variable selected to delete.");
    }

    fn open_new_profile_modal(&mut self) {
        self.input_cursor = 0;
        self.modal = Modal::NewProfile {
            name: String::new(),
            pull_from_phase: false,
            active_field: 0,
            error: None,
        };
    }

    fn open_add_var_modal(&mut self) {
        let Some(prof) = self.current_profile() else {
            self.set_error("No profile available. Create a profile first with [n].");
            return;
        };
        if prof.is_phase() {
            let pname = prof.name.clone();
            self.set_error(format!(
                "Profile '{}' uses Phase.dev synchronization. Sources cannot be mixed (create a Custom profile with [n]).",
                pname
            ));
        } else {
            self.input_cursor = 0;
            self.modal = Modal::VarEditor {
                is_edit: false,
                original_index: None,
                var_key: String::new(),
                var_value: String::new(),
                active_field: 0,
                error: None,
            };
        }
    }

    fn toggle_current_profile(&mut self) {
        if let Some(prof) = self.current_profile_mut() {
            prof.enabled = !prof.enabled;
            let name = prof.name.clone();
            let status = if prof.enabled { "ON" } else { "OFF" };
            self.sync_to_system(&format!("Toggled profile '{}' {}", name, status));
        }
    }

    fn toggle_mask_values(&mut self) {
        self.show_values = !self.show_values;
        let state = if self.show_values { "shown" } else { "masked" };
        self.set_info(format!("Secret values are now {}.", state));
    }

    pub fn execute_context_action(&mut self, action: ContextAction) {
        match action {
            ContextAction::ToggleProfile => self.toggle_current_profile(),
            ContextAction::Edit => self.handle_edit_action(),
            ContextAction::Delete => self.handle_delete_action(),
            ContextAction::MoveUp => self.move_selected_profile_up(),
            ContextAction::MoveDown => self.move_selected_profile_down(),
            ContextAction::NewProfile => self.open_new_profile_modal(),
            ContextAction::AddVar => self.open_add_var_modal(),
            ContextAction::PhaseSync => self.handle_phase_sync_action(false),
            ContextAction::PhaseRebind => self.handle_phase_sync_action(true),
            ContextAction::ToggleMask => self.toggle_mask_values(),
            ContextAction::ReloadShell => self.reload_shell(),
        }
    }

    pub fn open_context_menu_for_pane(&mut self, pane: FocusPane, x: u16, y: u16) {
        let mut items = Vec::new();
        let title = match pane {
            FocusPane::Profiles => {
                if let Some(prof) = self.current_profile() {
                    let toggle_label = if prof.enabled {
                        "Disable Profile"
                    } else {
                        "Enable Profile"
                    };
                    items.push(ContextMenuItem {
                        label: "Edit Profile".to_string(),
                        shortcut: "e",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: toggle_label.to_string(),
                        shortcut: "Space",
                        action: ContextAction::ToggleProfile,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Move Priority Up".to_string(),
                        shortcut: "u",
                        action: ContextAction::MoveUp,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Move Priority Down".to_string(),
                        shortcut: "d",
                        action: ContextAction::MoveDown,
                        is_danger: false,
                    });
                    if prof.is_phase() {
                        items.push(ContextMenuItem {
                            label: "Sync Phase.dev".to_string(),
                            shortcut: "p",
                            action: ContextAction::PhaseSync,
                            is_danger: false,
                        });
                        items.push(ContextMenuItem {
                            label: "Change Phase App/Env".to_string(),
                            shortcut: "P",
                            action: ContextAction::PhaseRebind,
                            is_danger: false,
                        });
                    } else {
                        items.push(ContextMenuItem {
                            label: "Add Variable".to_string(),
                            shortcut: "a",
                            action: ContextAction::AddVar,
                            is_danger: false,
                        });
                    }
                    items.push(ContextMenuItem {
                        label: "New Profile".to_string(),
                        shortcut: "n",
                        action: ContextAction::NewProfile,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Profile".to_string(),
                        shortcut: "x",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                } else {
                    items.push(ContextMenuItem {
                        label: "New Profile".to_string(),
                        shortcut: "n",
                        action: ContextAction::NewProfile,
                        is_danger: false,
                    });
                }
                " Profile Actions ".to_string()
            }
            FocusPane::Vars => {
                let has_vars = !self.current_vars().is_empty();
                let is_phase = self
                    .current_profile()
                    .map(|p| p.is_phase())
                    .unwrap_or(false);
                if has_vars {
                    items.push(ContextMenuItem {
                        label: "Edit Variable".to_string(),
                        shortcut: "e",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Variable".to_string(),
                        shortcut: "x",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                }
                if is_phase {
                    items.push(ContextMenuItem {
                        label: "Sync Phase.dev".to_string(),
                        shortcut: "p",
                        action: ContextAction::PhaseSync,
                        is_danger: false,
                    });
                } else {
                    items.push(ContextMenuItem {
                        label: "Add Variable".to_string(),
                        shortcut: "a",
                        action: ContextAction::AddVar,
                        is_danger: false,
                    });
                }
                items.push(ContextMenuItem {
                    label: if self.show_values {
                        "Mask Secret Values".to_string()
                    } else {
                        "Show Secret Values".to_string()
                    },
                    shortcut: "v",
                    action: ContextAction::ToggleMask,
                    is_danger: false,
                });
                " Variable Actions ".to_string()
            }
            FocusPane::Effective => {
                if !self.data.compute_effective_vars().is_empty() {
                    items.push(ContextMenuItem {
                        label: "Edit Variable".to_string(),
                        shortcut: "e",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Variable".to_string(),
                        shortcut: "x",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                }
                items.push(ContextMenuItem {
                    label: if self.show_values {
                        "Mask Secret Values".to_string()
                    } else {
                        "Show Secret Values".to_string()
                    },
                    shortcut: "v",
                    action: ContextAction::ToggleMask,
                    is_danger: false,
                });
                items.push(ContextMenuItem {
                    label: "Reload Shell Env".to_string(),
                    shortcut: "r",
                    action: ContextAction::ReloadShell,
                    is_danger: false,
                });
                " Effective Env Actions ".to_string()
            }
        };

        if !items.is_empty() {
            self.context_menu = Some(ContextMenu {
                x,
                y,
                title,
                items,
                selected: 0,
            });
        }
    }

    fn handle_context_menu_key(&mut self, key: KeyEvent) {
        let Some(mut menu) = self.context_menu.take() else {
            return;
        };
        let len = menu.items.len();
        if len == 0 {
            return;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {}
            KeyCode::Up | KeyCode::Char('k') => {
                menu.selected = (menu.selected + len - 1) % len;
                self.context_menu = Some(menu);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                menu.selected = (menu.selected + 1) % len;
                self.context_menu = Some(menu);
            }
            KeyCode::Enter => {
                let action = menu.items[menu.selected].action;
                self.execute_context_action(action);
            }
            KeyCode::Char('e') => self.execute_context_action(ContextAction::Edit),
            KeyCode::Char('x') | KeyCode::Delete => {
                self.execute_context_action(ContextAction::Delete)
            }
            KeyCode::Char(' ') => self.execute_context_action(ContextAction::ToggleProfile),
            KeyCode::Char('u') => self.execute_context_action(ContextAction::MoveUp),
            KeyCode::Char('d') => self.execute_context_action(ContextAction::MoveDown),
            KeyCode::Char('n') => self.execute_context_action(ContextAction::NewProfile),
            KeyCode::Char('a') => self.execute_context_action(ContextAction::AddVar),
            KeyCode::Char('p') => self.execute_context_action(ContextAction::PhaseSync),
            KeyCode::Char('P') => self.execute_context_action(ContextAction::PhaseRebind),
            KeyCode::Char('v') => self.execute_context_action(ContextAction::ToggleMask),
            KeyCode::Char('r') => self.execute_context_action(ContextAction::ReloadShell),
            _ => {
                self.context_menu = Some(menu);
            }
        }
    }

    fn handle_profiles_pane_key(&mut self, key: KeyEvent) {
        let total_items = self.data.profiles.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_profile > 0 {
                    self.selected_profile -= 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_profile + 1 < total_items {
                    self.selected_profile += 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Char('u') => {
                self.move_selected_profile_up();
            }
            KeyCode::Char('d') => {
                self.move_selected_profile_down();
            }
            KeyCode::Char(' ') => {
                if let Some(prof) = self.current_profile_mut() {
                    prof.enabled = !prof.enabled;
                    let name = prof.name.clone();
                    let status = if prof.enabled { "ON" } else { "OFF" };
                    self.sync_to_system(&format!("Toggled profile '{}' {}", name, status));
                }
            }
            KeyCode::Enter => {
                self.open_edit_profile();
            }
            _ => {}
        }
    }

    fn move_selected_profile_up(&mut self) {
        if self.selected_profile == 0 {
            if !self.data.profiles.is_empty() {
                self.set_info("Profile is already at top priority.");
            }
            return;
        }
        self.data
            .profiles
            .swap(self.selected_profile, self.selected_profile - 1);
        self.selected_profile -= 1;
        let name = self.data.profiles[self.selected_profile].name.clone();
        self.sync_to_system(&format!("Moved profile '{}' up", name));
    }

    fn move_selected_profile_down(&mut self) {
        if self.data.profiles.is_empty() || self.selected_profile + 1 >= self.data.profiles.len() {
            return;
        }
        self.data
            .profiles
            .swap(self.selected_profile, self.selected_profile + 1);
        self.selected_profile += 1;
        let name = self.data.profiles[self.selected_profile].name.clone();
        self.sync_to_system(&format!("Moved profile '{}' down", name));
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
            KeyCode::Enter => {
                self.open_edit_var();
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
            KeyCode::Enter => {
                self.open_edit_effective_var();
            }
            _ => {}
        }
    }

    fn open_phase_picker(
        &mut self,
        target_profile_idx: Option<usize>,
        new_profile_name: Option<String>,
    ) {
        if let Some(idx) = target_profile_idx {
            if let Some(prof) = self.data.profiles.get(idx) {
                if prof.is_custom() {
                    let pname = prof.name.clone();
                    self.set_error(format!(
                        "Profile '{}' is a Custom profile; sources cannot be mixed.",
                        pname
                    ));
                    return;
                }
            }
        }

        if !self.data.phase.is_configured() {
            self.open_phase_connect_modal(
                new_profile_name,
                Some("Please configure Phase.dev authentication first.".to_string()),
            );
            return;
        }

        match fetch_apps_and_envs(&self.data.phase) {
            Ok(apps) => {
                if apps.is_empty() {
                    self.set_error("Connected to Phase.dev, but no Apps were found.");
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
                self.open_phase_connect_modal(new_profile_name, Some(e));
            }
        }
    }

    fn insert_new_profile(&mut self, profile: Profile) {
        if self.data.settings.insert_new_profile_at_top {
            self.data.profiles.insert(0, profile);
            self.selected_profile = 0;
        } else {
            self.data.profiles.push(profile);
            self.selected_profile = self.data.profiles.len().saturating_sub(1);
        }
        self.selected_var = 0;
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => {}
            Modal::PhaseConnect {
                mut auth_method,
                mut host_mode,
                mut custom_url,
                mut pat_token,
                mut cli_status,
                mut active_field,
                pending_new_profile,
                mut error,
            } => {
                // Fields:
                // When auth_method == Cli: 1 field (0 = Auth Method)
                // When auth_method == Token & Cloud: 2 fields (0 = Auth Method, 1 = Server Mode, 2 = PAT) -> 3 fields
                // When auth_method == Token & SelfHosted: 4 fields (0 = Auth Method, 1 = Server Mode, 2 = URL, 3 = PAT)
                let max_fields = match auth_method {
                    PhaseAuthMethod::Cli => 1,
                    PhaseAuthMethod::Token => match host_mode {
                        HostMode::Cloud => 3,
                        HostMode::SelfHosted => 4,
                    },
                };

                let pat_field_idx = if host_mode == HostMode::Cloud { 2 } else { 3 };

                match key.code {
                    KeyCode::Esc => {
                        self.set_info("Closed Phase.dev setup.");
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        active_field = (active_field + 1) % max_fields;
                        self.input_cursor = if host_mode == HostMode::SelfHosted && active_field == 2 {
                            custom_url.chars().count()
                        } else if active_field == pat_field_idx {
                            pat_token.chars().count()
                        } else {
                            0
                        };
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        active_field = (active_field + max_fields - 1) % max_fields;
                        self.input_cursor = if host_mode == HostMode::SelfHosted && active_field == 2 {
                            custom_url.chars().count()
                        } else if active_field == pat_field_idx {
                            pat_token.chars().count()
                        } else {
                            0
                        };
                    }
                    KeyCode::Char('r') if auth_method == PhaseAuthMethod::Cli => {
                        cli_status = detect_phase_cli_detailed();
                        error = None;
                    }
                    KeyCode::Left if auth_method == PhaseAuthMethod::Token && (active_field == 2 || active_field == pat_field_idx) => {
                        self.input_cursor = self.input_cursor.saturating_sub(1);
                        error = None;
                    }
                    KeyCode::Right if auth_method == PhaseAuthMethod::Token && (active_field == 2 || active_field == pat_field_idx) => {
                        let len = if active_field == 2 { custom_url.chars().count() } else { pat_token.chars().count() };
                        self.input_cursor = (self.input_cursor + 1).min(len);
                        error = None;
                    }
                    KeyCode::Home | KeyCode::Char('a')
                        if auth_method == PhaseAuthMethod::Token
                            && (active_field == 2 || active_field == pat_field_idx)
                            && (key.code == KeyCode::Home || key.modifiers.contains(KeyModifiers::CONTROL)) =>
                    {
                        self.input_cursor = 0;
                    }
                    KeyCode::End | KeyCode::Char('e')
                        if auth_method == PhaseAuthMethod::Token
                            && (active_field == 2 || active_field == pat_field_idx)
                            && (key.code == KeyCode::End || key.modifiers.contains(KeyModifiers::CONTROL)) =>
                    {
                        let len = if active_field == 2 { custom_url.chars().count() } else { pat_token.chars().count() };
                        self.input_cursor = len;
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                        if active_field == 0 =>
                    {
                        auth_method = match auth_method {
                            PhaseAuthMethod::Cli => PhaseAuthMethod::Token,
                            PhaseAuthMethod::Token => PhaseAuthMethod::Cli,
                        };
                        if auth_method == PhaseAuthMethod::Cli {
                            cli_status = detect_phase_cli_detailed();
                        }
                        active_field = 0;
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                        if auth_method == PhaseAuthMethod::Token && active_field == 1 =>
                    {
                        host_mode = match host_mode {
                            HostMode::Cloud => HostMode::SelfHosted,
                            HostMode::SelfHosted => HostMode::Cloud,
                        };
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Backspace if auth_method == PhaseAuthMethod::Token => {
                        if self.input_cursor > 0 {
                            if host_mode == HostMode::SelfHosted && active_field == 2 {
                                remove_char_at(&mut custom_url, self.input_cursor - 1);
                            } else if active_field == pat_field_idx {
                                remove_char_at(&mut pat_token, self.input_cursor - 1);
                            }
                            self.input_cursor -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Delete if auth_method == PhaseAuthMethod::Token => {
                        if host_mode == HostMode::SelfHosted && active_field == 2 {
                            remove_char_at(&mut custom_url, self.input_cursor);
                        } else if active_field == pat_field_idx {
                            remove_char_at(&mut pat_token, self.input_cursor);
                        }
                        error = None;
                    }
                    KeyCode::Char('u')
                        if auth_method == PhaseAuthMethod::Token
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        if host_mode == HostMode::SelfHosted && active_field == 2 {
                            custom_url.clear();
                        } else if active_field == pat_field_idx {
                            pat_token.clear();
                        }
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Char(c)
                        if auth_method == PhaseAuthMethod::Token
                            && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        if host_mode == HostMode::SelfHosted && active_field == 2 {
                            insert_char_at(&mut custom_url, self.input_cursor, c);
                            self.input_cursor += 1;
                            error = None;
                        } else if active_field == pat_field_idx {
                            insert_char_at(&mut pat_token, self.input_cursor, c);
                            self.input_cursor += 1;
                            error = None;
                        }
                    }
                    KeyCode::Enter => {
                        if auth_method == PhaseAuthMethod::Cli {
                            cli_status = detect_phase_cli_detailed();
                            if !cli_status.installed {
                                error = Some(
                                    "Phase CLI (`phase`) is not installed or not in PATH.".to_string(),
                                );
                            } else {
                                let new_cfg = PhaseConfig {
                                    auth_method: PhaseAuthMethod::Cli,
                                    host_mode,
                                    custom_url: custom_url.trim().to_string(),
                                    pat_token: pat_token.trim().to_string(),
                                };
                                match fetch_apps_and_envs(&new_cfg) {
                                    Ok(apps) => {
                                        let app_count = apps.len();
                                        self.cached_apps = apps.clone();
                                        self.data.phase = new_cfg;
                                        let _ = self.data.save();
                                        if let Some(prof_name) = pending_new_profile {
                                            self.modal = Modal::PhasePicker {
                                                target_profile_idx: None,
                                                new_profile_name: Some(prof_name),
                                                apps,
                                                selected_app: 0,
                                                selected_env: 0,
                                                selecting_env: false,
                                                error: None,
                                            };
                                            return;
                                        }
                                        self.set_info(format!(
                                            "Connected to Phase.dev via CLI ({})! Found {} app(s).",
                                            self.data.phase.effective_host(),
                                            app_count
                                        ));
                                        return;
                                    }
                                    Err(e) => {
                                        error = Some(format!(
                                            "{} (Ensure `phase auth` is logged in, or press Ctrl+S to save)",
                                            e
                                        ));
                                    }
                                }
                            }
                        } else if host_mode == HostMode::SelfHosted && custom_url.trim().is_empty()
                        {
                            error = Some("Self-hosted URL cannot be empty.".to_string());
                        } else if pat_token.trim().is_empty() {
                            error =
                                Some("Personal Access Token (PAT) cannot be empty.".to_string());
                        } else {
                            let new_cfg = PhaseConfig {
                                auth_method: PhaseAuthMethod::Token,
                                host_mode,
                                custom_url: custom_url.trim().to_string(),
                                pat_token: pat_token.trim().to_string(),
                            };
                            match fetch_apps_and_envs(&new_cfg) {
                                Ok(apps) => {
                                    let app_count = apps.len();
                                    self.cached_apps = apps.clone();
                                    self.data.phase = new_cfg;
                                    let _ = self.data.save();
                                    if let Some(prof_name) = pending_new_profile {
                                        self.modal = Modal::PhasePicker {
                                            target_profile_idx: None,
                                            new_profile_name: Some(prof_name),
                                            apps,
                                            selected_app: 0,
                                            selected_env: 0,
                                            selecting_env: false,
                                            error: None,
                                        };
                                        return;
                                    }
                                    self.set_info(format!(
                                        "Connected to Phase.dev via API Token ({})! Found {} app(s).",
                                        self.data.phase.effective_host(),
                                        app_count
                                    ));
                                    return;
                                }
                                Err(e) => {
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

                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('s')
                {
                    self.data.phase = PhaseConfig {
                        auth_method,
                        host_mode,
                        custom_url: custom_url.trim().to_string(),
                        pat_token: pat_token.trim().to_string(),
                    };
                    let _ = self.data.save();
                    self.set_info(format!(
                        "Saved Phase.dev config ({}: {})",
                        self.data.phase.auth_method.label(),
                        self.data.phase.effective_host()
                    ));
                    return;
                }

                self.modal = Modal::PhaseConnect {
                    auth_method,
                    host_mode,
                    custom_url,
                    pat_token,
                    cli_status,
                    active_field,
                    pending_new_profile,
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
                        self.input_cursor = if active_field == 0 { name.chars().count() } else { 0 };
                    }
                    KeyCode::Left if active_field == 0 => {
                        self.input_cursor = self.input_cursor.saturating_sub(1);
                        error = None;
                    }
                    KeyCode::Right if active_field == 0 => {
                        self.input_cursor = (self.input_cursor + 1).min(name.chars().count());
                        error = None;
                    }
                    KeyCode::Home | KeyCode::Char('a')
                        if active_field == 0 && (key.code == KeyCode::Home || key.modifiers.contains(KeyModifiers::CONTROL)) =>
                    {
                        self.input_cursor = 0;
                    }
                    KeyCode::End | KeyCode::Char('e')
                        if active_field == 0 && (key.code == KeyCode::End || key.modifiers.contains(KeyModifiers::CONTROL)) =>
                    {
                        self.input_cursor = name.chars().count();
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                        if active_field == 1 =>
                    {
                        pull_from_phase = !pull_from_phase;
                        error = None;
                    }
                    KeyCode::Backspace if active_field == 0 => {
                        if self.input_cursor > 0 {
                            remove_char_at(&mut name, self.input_cursor - 1);
                            self.input_cursor -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Delete if active_field == 0 => {
                        remove_char_at(&mut name, self.input_cursor);
                        error = None;
                    }
                    KeyCode::Char('u')
                        if active_field == 0
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        name.clear();
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Char(c)
                        if active_field == 0
                            && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        insert_char_at(&mut name, self.input_cursor, c);
                        self.input_cursor += 1;
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
                            self.insert_new_profile(Profile::new_custom(trimmed.clone()));
                            self.sync_to_system(&format!(
                                "Created custom profile '{}'",
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
                                let export_all = self.data.settings.phase_export_all_paths;
                                match fetch_secrets_for_env(
                                    &self.data.phase,
                                    &app.id,
                                    &env.id,
                                    Some(&env.name),
                                    export_all,
                                ) {
                                    Ok(fetched_pairs) => {
                                        let fetched_len = fetched_pairs.len();
                                        let binding = PhaseBinding {
                                            app_id: app.id.clone(),
                                            app_name: app.name.clone(),
                                            env_id: env.id.clone(),
                                            env_name: env.name.clone(),
                                        };
                                        self.data.last_phase_sync_epoch =
                                            AppStateData::current_epoch_secs();

                                        if let Some(prof_name) = new_profile_name {
                                            let new_prof = Profile::new_phase(
                                                prof_name.clone(),
                                                binding,
                                                fetched_pairs,
                                            );
                                            self.insert_new_profile(new_prof);
                                            self.sync_to_system(&format!(
                                                "Created Phase.dev profile '{}' with {} var(s) ({}/{})",
                                                prof_name, fetched_len, app.name, env.name
                                            ));
                                        } else if let Some(idx) = target_profile_idx {
                                            if let Some(prof) = self.data.profiles.get_mut(idx) {
                                                prof.set_phase_vars(binding, fetched_pairs);
                                                let pname = prof.name.clone();
                                                self.sync_to_system(&format!(
                                                    "Synced {} var(s) from Phase ({}/{}) into '{}'",
                                                    fetched_len, app.name, env.name, pname
                                                ));
                                            }
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
                        self.input_cursor = if active_field == 0 { var_key.chars().count() } else { var_value.chars().count() };
                    }
                    KeyCode::Left => {
                        self.input_cursor = self.input_cursor.saturating_sub(1);
                        error = None;
                    }
                    KeyCode::Right => {
                        let len = if active_field == 0 { var_key.chars().count() } else { var_value.chars().count() };
                        self.input_cursor = (self.input_cursor + 1).min(len);
                        error = None;
                    }
                    KeyCode::Home | KeyCode::Char('a')
                        if key.code == KeyCode::Home || key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        self.input_cursor = 0;
                    }
                    KeyCode::End | KeyCode::Char('e')
                        if key.code == KeyCode::End || key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        let len = if active_field == 0 { var_key.chars().count() } else { var_value.chars().count() };
                        self.input_cursor = len;
                    }
                    KeyCode::Backspace => {
                        if self.input_cursor > 0 {
                            if active_field == 0 {
                                remove_char_at(&mut var_key, self.input_cursor - 1);
                            } else {
                                remove_char_at(&mut var_value, self.input_cursor - 1);
                            }
                            self.input_cursor -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Delete => {
                        if active_field == 0 {
                            remove_char_at(&mut var_key, self.input_cursor);
                        } else {
                            remove_char_at(&mut var_value, self.input_cursor);
                        }
                        error = None;
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if active_field == 0 {
                            var_key.clear();
                        } else {
                            var_value.clear();
                        }
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if active_field == 0 {
                            insert_char_at(&mut var_key, self.input_cursor, c);
                        } else {
                            insert_char_at(&mut var_value, self.input_cursor, c);
                        }
                        self.input_cursor += 1;
                        error = None;
                    }
                    KeyCode::Enter => {
                        let k = var_key.trim().to_string();
                        if !is_valid_env_key(&k) {
                            error = Some(
                                "Invalid variable name. Use letters, digits, '_' (cannot start with digit)."
                                    .to_string(),
                            );
                        } else if let Some(prof) = self.current_profile_mut() {
                            if prof.is_phase() {
                                error = Some(
                                    "Cannot modify variables manually in a Phase.dev profile."
                                        .to_string(),
                                );
                            } else {
                                if is_edit {
                                    if let Some(idx) = original_index {
                                        if let Some(v) = prof.vars.get_mut(idx) {
                                            v.key = k.clone();
                                            v.set_value(var_value.clone());
                                        }
                                    }
                                } else {
                                    let _ = prof.upsert_custom_var(k.clone(), var_value.clone());
                                }
                                self.clamp_selections();
                                let target_name = self.current_target_title();
                                self.sync_to_system(&format!(
                                    "Saved variable '{}' in {}",
                                    k, target_name
                                ));
                                return;
                            }
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
                    if let Some(prof) = self.current_profile_mut() {
                        if prof.is_custom() && var_idx < prof.vars.len() {
                            prof.vars.remove(var_idx);
                            self.clamp_selections();
                            self.sync_to_system(&format!("Deleted variable '{}'", var_key));
                        }
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => {
                    self.modal = Modal::ConfirmDeleteVar { var_idx, var_key };
                }
            },

            Modal::EditProfile {
                profile_idx,
                mut name,
                mut error,
            } => {
                match key.code {
                    KeyCode::Esc => {
                        return;
                    }
                    KeyCode::Left => {
                        self.input_cursor = self.input_cursor.saturating_sub(1);
                        error = None;
                    }
                    KeyCode::Right => {
                        self.input_cursor = (self.input_cursor + 1).min(name.chars().count());
                        error = None;
                    }
                    KeyCode::Home | KeyCode::Char('a')
                        if key.code == KeyCode::Home || key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        self.input_cursor = 0;
                    }
                    KeyCode::End | KeyCode::Char('e')
                        if key.code == KeyCode::End || key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        self.input_cursor = name.chars().count();
                    }
                    KeyCode::Backspace => {
                        if self.input_cursor > 0 {
                            remove_char_at(&mut name, self.input_cursor - 1);
                            self.input_cursor -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Delete => {
                        remove_char_at(&mut name, self.input_cursor);
                        error = None;
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        name.clear();
                        self.input_cursor = 0;
                        error = None;
                    }
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(prof) = self.data.profiles.get(profile_idx) {
                            if prof.is_phase() {
                                self.open_phase_picker(Some(profile_idx), None);
                                return;
                            }
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        insert_char_at(&mut name, self.input_cursor, c);
                        self.input_cursor += 1;
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
                            .enumerate()
                            .any(|(i, p)| i != profile_idx && p.name.eq_ignore_ascii_case(&trimmed))
                        {
                            error = Some(format!("Profile '{}' already exists.", trimmed));
                        } else {
                            if let Some(prof) = self.data.profiles.get_mut(profile_idx) {
                                let old_name = prof.name.clone();
                                prof.name = trimmed.clone();
                                self.sync_to_system(&format!(
                                    "Renamed profile '{}' to '{}'",
                                    old_name, trimmed
                                ));
                            }
                            return;
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::EditProfile {
                    profile_idx,
                    name,
                    error,
                };
            }

            Modal::Settings {
                mut draft,
                mut active_field,
                mut error,
            } => {
                const TOTAL_SETTINGS_FIELDS: usize = 5;

                match key.code {
                    KeyCode::Esc => {
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        active_field = (active_field + 1) % TOTAL_SETTINGS_FIELDS;
                        error = None;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        active_field =
                            (active_field + TOTAL_SETTINGS_FIELDS - 1) % TOTAL_SETTINGS_FIELDS;
                        error = None;
                    }
                    KeyCode::Char(' ')
                    | KeyCode::Left
                    | KeyCode::Right => {
                        error = None;
                        match active_field {
                            0 => {
                                draft.sync_only_enabled_profiles =
                                    !draft.sync_only_enabled_profiles;
                            }
                            1 => {
                                draft.phase_export_all_paths = !draft.phase_export_all_paths;
                            }
                            2 => {
                                draft.mask_secrets_by_default = !draft.mask_secrets_by_default;
                            }
                            3 => {
                                draft.insert_new_profile_at_top =
                                    !draft.insert_new_profile_at_top;
                            }
                            4 => {
                                draft.shell_prompt_hook = !draft.shell_prompt_hook;
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Enter => {
                        self.data.settings = draft;
                        self.sync_to_system("Saved application Settings");
                        self.modal = Modal::None;
                        return;
                    }
                    _ => {}
                }

                self.modal = Modal::Settings {
                    draft,
                    active_field,
                    error,
                };
            }

            Modal::Help => match key.code {
                KeyCode::Esc
                | KeyCode::Char('?')
                | KeyCode::Char('q')
                | KeyCode::Enter
                | KeyCode::Char(' ')
                | KeyCode::F(1) => {}
                _ => {
                    self.modal = Modal::Help;
                }
            },
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        self.clear_expired_status();
        self.last_area = frame.area();
        let (header_rect, profiles_rect, vars_rect, effective_rect, status_bar_rect) =
            compute_layout_chunks(frame.area());

        self.draw_header(frame, header_rect);
        self.draw_profiles_pane(frame, profiles_rect);
        self.draw_vars_pane(frame, vars_rect);
        self.draw_effective_pane(frame, effective_rect);
        self.draw_footer(frame, status_bar_rect);

        if self.context_menu.is_some() {
            self.draw_context_menu(frame, frame.area());
        }

        if !matches!(self.modal, Modal::None) {
            self.draw_modal(frame, frame.area());
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(65, 85, 115)));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let title_span = Span::styled(
            " Environtment Variables Manager ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        if inner.width >= 86 {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(34), Constraint::Length(52)])
                .split(inner);

            frame.render_widget(
                Paragraph::new(Line::from(title_span)).alignment(Alignment::Left),
                cols[0],
            );

            let btn_style = Style::default()
                .fg(Color::Cyan)
                .bg(Color::Rgb(25, 38, 58))
                .add_modifier(Modifier::BOLD);
            let sep = Span::raw(" ");
            let mask_label = if self.show_values {
                " [Hide] "
            } else {
                " [Show] "
            };

            let toolbar = Line::from(vec![
                Span::styled(" [+Profile] ", btn_style),
                sep.clone(),
                Span::styled(" [+Var] ", btn_style),
                sep.clone(),
                Span::styled(" [Sync] ", btn_style),
                sep.clone(),
                Span::styled(mask_label, btn_style),
                sep,
                Span::styled(" [Settings] ", btn_style),
            ]);
            frame.render_widget(
                Paragraph::new(toolbar).alignment(Alignment::Right),
                cols[1],
            );
        } else {
            frame.render_widget(
                Paragraph::new(Line::from(title_span)).alignment(Alignment::Center),
                inner,
            );
        }
    }

    fn draw_profiles_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == FocusPane::Profiles;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let mut items: Vec<ListItem> = Vec::with_capacity(self.data.profiles.len());

        for prof in &self.data.profiles {
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
                Span::styled(&prof.name, name_style),
                Span::styled(
                    badge,
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }

        if items.is_empty() {
            items.push(ListItem::new(Line::from(Span::styled(
                "No profiles. Click [+Profile] or press [n] to create one.",
                Style::default().fg(Color::DarkGray),
            ))));
        }

        let title = if area.width >= 34 {
            " Profiles (Top Wins Priority) "
        } else {
            " Profiles (Top Wins) "
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(title),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(35, 55, 85))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        if !self.data.profiles.is_empty() {
            state.select(Some(self.selected_profile));
        }
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
                let val_display = v.masked_display(self.show_values);
                Row::new(vec![v.key.clone(), val_display])
            })
            .collect();

        let header = Row::new(vec!["KEY", "VALUE"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let title = if let Some(prof) = self.current_profile() {
            let count = vars.len();
            let var_word = if count == 1 { "variable" } else { "variables" };
            if prof.is_phase() {
                let now = AppStateData::current_epoch_secs();
                let sync_epoch = prof
                    .last_sync_epoch
                    .filter(|&e| e > 0)
                    .or_else(|| (self.data.last_phase_sync_epoch > 0).then_some(self.data.last_phase_sync_epoch));
                let compact = area.width < 55;
                let sync_time = crate::model::format_relative_sync_time(sync_epoch, now, compact);
                if area.width >= 55 {
                    format!(
                        " {} {} in {} profile • Last sync: {} ",
                        count, var_word, prof.name, sync_time
                    )
                } else if area.width >= 40 {
                    format!(" {} {} in {} • Last sync: {} ", count, var_word, prof.name, sync_time)
                } else {
                    format!(" {} vars • Sync: {} ", count, sync_time)
                }
            } else {
                format!(" {} {} in {} profile ", count, var_word, prof.name)
            }
        } else {
            " 0 variables in profile ".to_string()
        };

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(40),
                Constraint::Percentage(60),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .padding(Padding::new(1, 1, 1, 0))
                .title(title),
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
        let (header, constraints, rows): (Row, Vec<Constraint>, Vec<Row>) = if area.width >= 55 {
            (
                Row::new(vec!["EXPORTED KEY", "EFFECTIVE VALUE", "PROFILE", "SOURCE"]).style(
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                vec![
                    Constraint::Percentage(28),
                    Constraint::Percentage(30),
                    Constraint::Percentage(10),
                    Constraint::Percentage(32),
                ],
                effective
                    .iter()
                    .map(|ev| {
                        let val_display = ev.masked_display(self.show_values);
                        Row::new(vec![
                            ev.key.clone(),
                            val_display,
                            ev.winning_owner.clone(),
                            ev.source_label.clone(),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                Row::new(vec!["KEY", "VAL", "PROFILE", "SOURCE"]).style(
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                vec![
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(7),
                    Constraint::Length(6),
                ],
                effective
                    .iter()
                    .map(|ev| {
                        let val_display = ev.masked_display(self.show_values);
                        Row::new(vec![
                            ev.key.clone(),
                            val_display,
                            ev.winning_owner.clone(),
                            ev.source_label.clone(),
                        ])
                    })
                    .collect(),
            )
        };

        let table = Table::new(rows, constraints)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .padding(Padding::new(1, 1, 1, 0))
                .title(" Active System Environment "),
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
        let status_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(16), Constraint::Length(16)])
            .split(area);

        let phase_status = if self.data.phase.is_configured() {
            let auth_tag = self.data.phase.auth_method.label();
            let host = self.data.phase.effective_host();
            if (self.status_message.is_empty() && area.width >= 110) || area.width >= 145 {
                Span::raw(format!("Connected ({}: {})", auth_tag, host))
            } else {
                Span::raw(format!("Connected ({})", auth_tag))
            }
        } else if (self.status_message.is_empty() && area.width >= 110) || area.width >= 145 {
            Span::raw("Optional / Offline ([c] Connect)")
        } else {
            Span::raw("Offline ([c] Connect)")
        };

        let mut spans = vec![
            Span::styled(
                " Phase.dev: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            phase_status,
        ];

        if !self.status_message.is_empty() {
            let msg_style = if self.is_error_status {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            };
            spans.push(Span::raw(" | "));
            spans.push(Span::styled(&self.status_message, msg_style));
        }

        let status_line = Line::from(spans);

        let bg_style = Style::default()
            .bg(Color::Rgb(25, 35, 50))
            .fg(Color::White);

        frame.render_widget(
            Paragraph::new(status_line).style(bg_style),
            status_chunks[0],
        );

        let help_indicator = Line::from(vec![
            Span::styled(
                " ? ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " Shortcuts ",
                Style::default()
                    .fg(Color::Cyan)
                    .bg(Color::Rgb(35, 50, 72))
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(help_indicator)
                .alignment(Alignment::Right)
                .style(bg_style),
            status_chunks[1],
        );
    }

    fn draw_context_menu(&self, frame: &mut Frame, area: Rect) {
        let Some(menu) = &self.context_menu else {
            return;
        };
        let popup = menu.rect(area);
        frame.render_widget(Clear, popup);

        let inner_width = popup.width.saturating_sub(2) as usize;
        let items: Vec<ListItem> = menu
            .items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let is_sel = idx == menu.selected;
                let shortcut_str = format!("[{}]", item.shortcut);
                let pad = inner_width
                    .saturating_sub(item.label.len() + shortcut_str.len() + 3)
                    .max(1);
                let spaces = " ".repeat(pad);

                let (fg_label, fg_key, row_bg) = if is_sel {
                    if item.is_danger {
                        (Color::White, Color::Yellow, Color::Rgb(120, 35, 45))
                    } else {
                        (Color::White, Color::Cyan, Color::Rgb(40, 68, 105))
                    }
                } else if item.is_danger {
                    (Color::LightRed, Color::DarkGray, Color::Rgb(20, 26, 38))
                } else {
                    (Color::White, Color::DarkGray, Color::Rgb(20, 26, 38))
                };

                let prefix = if is_sel { "▸ " } else { "  " };
                let line = Line::from(vec![
                    Span::styled(
                        format!("{}{}", prefix, item.label),
                        Style::default()
                            .fg(fg_label)
                            .bg(row_bg)
                            .add_modifier(if is_sel {
                                Modifier::BOLD
                            } else {
                                Modifier::empty()
                            }),
                    ),
                    Span::styled(spaces, Style::default().bg(row_bg)),
                    Span::styled(
                        format!("{} ", shortcut_str),
                        Style::default().fg(fg_key).bg(row_bg),
                    ),
                ]);
                ListItem::new(line).style(Style::default().bg(row_bg))
            })
            .collect();

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Rgb(20, 26, 38)))
            .title(Span::styled(
                &menu.title,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));

        frame.render_widget(List::new(items).block(block), popup);
    }

    fn draw_modal(&self, frame: &mut Frame, area: Rect) {
        match &self.modal {
            Modal::None => {}
            Modal::PhaseConnect {
                auth_method,
                host_mode,
                custom_url,
                pat_token,
                cli_status,
                active_field,
                error,
                ..
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Phase.dev Authentication Setup ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let mut lines = vec![
                    Line::from(Span::styled(
                        "Configure Phase.dev Authentication",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                ];

                lines.extend(modern_vertical_radio_options(
                    "1. Authentication Method:",
                    &[
                        ("cli", "Phase CLI (Auto-detected from local machine)"),
                        ("token", "API Token (Personal Access Token / Service Token)"),
                    ],
                    if *auth_method == PhaseAuthMethod::Cli { 0 } else { 1 },
                    *active_field == 0,
                ));
                lines.push(Line::from(""));

                if *auth_method == PhaseAuthMethod::Cli {
                    let cli_badge_color = if cli_status.installed && cli_status.logged_in {
                        Color::Green
                    } else if cli_status.installed {
                        Color::Yellow
                    } else {
                        Color::Red
                    };
                    let bin_str = cli_status.binary_path.as_deref().unwrap_or("not found in PATH");
                    let host_str = cli_status.host.as_deref().unwrap_or(PHASE_CLOUD_HOST);
                    let org_str = cli_status.organization.as_deref().unwrap_or("N/A");

                    lines.push(Line::from(vec![
                        Span::styled("   CLI Detection : ", Style::default().fg(Color::DarkGray)),
                        Span::styled(cli_status.summary_badge(), Style::default().fg(cli_badge_color)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("   Binary Path   : ", Style::default().fg(Color::DarkGray)),
                        Span::styled(bin_str, Style::default().fg(Color::White)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("   Phase Host    : ", Style::default().fg(Color::DarkGray)),
                        Span::styled(host_str, Style::default().fg(Color::White)),
                        Span::styled(format!(" (Org: {})", org_str), Style::default().fg(Color::DarkGray)),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Native CLI uses `phase apps` & secrets export.",
                        Style::default().fg(Color::DarkGray),
                    )));
                } else {
                    lines.extend(modern_vertical_radio_options(
                        "2. Server Mode:",
                        &[
                            ("cloud", "Official Cloud (https://console.phase.dev)"),
                            ("self_hosted", "Self-Hosted Console (Custom URL)"),
                        ],
                        if *host_mode == HostMode::Cloud { 0 } else { 1 },
                        *active_field == 1,
                    ));
                    lines.push(Line::from(""));

                    if *host_mode == HostMode::SelfHosted {
                        lines.extend(modern_input_lines(
                            "3. Self-Hosted URL:",
                            custom_url,
                            "https://phase.yourdomain.com",
                            *active_field == 2,
                            36,
                            self.input_cursor,
                        ));
                        lines.push(Line::from(""));
                    }

                    let pat_idx = if *host_mode == HostMode::Cloud { 2 } else { 3 };
                    let masked_pat = if pat_token.len() > 18 {
                        format!("{}...{}", &pat_token[..14], &pat_token[pat_token.len() - 4..])
                    } else {
                        pat_token.clone()
                    };

                    lines.extend(modern_input_lines(
                        "Phase API Token (pss_user:... / pss_service:...):",
                        &masked_pat,
                        "Enter or paste PAT token",
                        *active_field == pat_idx,
                        36,
                        self.input_cursor,
                    ));
                }

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                }

                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::NewProfile {
                name,
                pull_from_phase,
                active_field,
                error,
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" New Profile ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let mut lines = vec![
                    Line::from(Span::styled(
                        "Create New Environment Profile",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                ];

                lines.extend(modern_input_lines(
                    "1. Profile Name:",
                    name,
                    "e.g. staging, prod, test",
                    *active_field == 0,
                    36,
                    self.input_cursor,
                ));
                lines.push(Line::from(""));
                lines.extend(modern_vertical_radio_options(
                    "2. Profile Data Source:",
                    &[
                        ("custom", "Custom Environment (Manual Variables)"),
                        ("phase", "Phase.dev Synchronization (Select App & Env)"),
                    ],
                    if *pull_from_phase { 1 } else { 0 },
                    *active_field == 1,
                ));

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                }

                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::PhasePicker {
                apps,
                selected_app,
                selected_env,
                selecting_env,
                error,
                ..
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Phase.dev Synchronization ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(6), Constraint::Length(1)])
                    .split(inner);

                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(chunks[0]);

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
                            .border_type(BorderType::Rounded)
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

                let env_title = if let Some(err) = error {
                    format!(" 2. Env [Error: {}] ", err)
                } else {
                    " 2. Select Environment ".to_string()
                };

                let env_list = List::new(env_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(env_border)
                            .title(env_title),
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

                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::VarEditor {
                is_edit,
                var_key,
                var_value,
                active_field,
                error,
                ..
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let title = if *is_edit {
                    " Edit Custom Environment Variable "
                } else {
                    " Add Custom Environment Variable "
                };

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(title);
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let mut lines = vec![
                    Line::from(Span::styled(
                        format!("Target: {}", self.current_target_title()),
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                ];

                lines.extend(modern_input_lines(
                    "1. Variable Name (KEY):",
                    var_key,
                    "e.g. API_KEY, DATABASE_URL",
                    *active_field == 0,
                    36,
                    self.input_cursor,
                ));
                lines.push(Line::from(""));
                lines.extend(modern_input_lines(
                    "2. Variable Value (VALUE):",
                    var_value,
                    "enter secret or value...",
                    *active_field == 1,
                    36,
                    self.input_cursor,
                ));

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                }

                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::ConfirmDeleteProfile { profile_name, .. } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Red))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Confirm Delete Profile ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Delete profile '{}' and all its variables?", profile_name),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "This action cannot be undone.",
                        Style::default().fg(Color::DarkGray),
                    )),
                ];
                frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::ConfirmDeleteVar { var_key, .. } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Red))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Confirm Delete Variable ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Delete variable '{}'?", var_key),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "This action cannot be undone.",
                        Style::default().fg(Color::DarkGray),
                    )),
                ];
                frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::EditProfile {
                profile_idx,
                name,
                error,
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let is_phase = self
                    .data
                    .profiles
                    .get(*profile_idx)
                    .map(|p| p.is_phase())
                    .unwrap_or(false);
                let src_label = self
                    .data
                    .profiles
                    .get(*profile_idx)
                    .map(|p| p.source_label())
                    .unwrap_or_else(|| "Custom".to_string());

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Edit Profile ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("Data Source: ", Style::default().fg(Color::Gray)),
                        Span::styled(src_label, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(""),
                ];

                lines.extend(modern_input_lines(
                    "Rename Profile:",
                    name,
                    "enter profile name",
                    true,
                    36,
                    self.input_cursor,
                ));

                if is_phase {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Press [Ctrl+P] to change Phase App / Env binding.",
                        Style::default().fg(Color::DarkGray),
                    )));
                }

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                }

                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::Settings {
                draft,
                active_field,
                error,
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Settings ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let active_pill = Style::default()
                    .fg(Color::Cyan)
                    .bg(Color::Rgb(25, 38, 58))
                    .add_modifier(Modifier::BOLD);
                let inactive_pill = Style::default()
                    .fg(Color::DarkGray)
                    .bg(Color::Rgb(20, 24, 32));

                let make_pfx = |f_idx: usize| {
                    if *active_field == f_idx {
                        ("▸ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    } else {
                        ("  ", Style::default().fg(Color::Yellow))
                    }
                };

                let (pfx0, s0) = make_pfx(0);
                let (pfx1, s1) = make_pfx(1);
                let (pfx2, s2) = make_pfx(2);
                let (pfx3, s3) = make_pfx(3);
                let (pfx4, s4) = make_pfx(4);

                let mut lines = vec![
                    Line::from(Span::styled(
                        "Application & Synchronization Settings",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(pfx0, s0),
                        Span::styled("1. Phase Sync Profile Scope       : ", s0),
                        Span::styled(if draft.sync_only_enabled_profiles { " [● Enabled Only] " } else { " [○ Enabled Only] " }, if draft.sync_only_enabled_profiles { active_pill } else { inactive_pill }),
                        Span::raw(" "),
                        Span::styled(if !draft.sync_only_enabled_profiles { " [● All Phase] " } else { " [○ All Phase] " }, if !draft.sync_only_enabled_profiles { active_pill } else { inactive_pill }),
                    ]),
                    Line::from(vec![
                        Span::styled(pfx1, s1),
                        Span::styled("2. Phase Secret Path Scope       : ", s1),
                        Span::styled(if draft.phase_export_all_paths { " [● All Paths] " } else { " [○ All Paths] " }, if draft.phase_export_all_paths { active_pill } else { inactive_pill }),
                        Span::raw(" "),
                        Span::styled(if !draft.phase_export_all_paths { " [● Root (/) Only] " } else { " [○ Root (/) Only] " }, if !draft.phase_export_all_paths { active_pill } else { inactive_pill }),
                    ]),
                    Line::from(vec![
                        Span::styled(pfx2, s2),
                        Span::styled("3. Mask Secret Values on Startup : ", s2),
                        Span::styled(if draft.mask_secrets_by_default { " [● ON ] " } else { " [○ ON ] " }, if draft.mask_secrets_by_default { active_pill } else { inactive_pill }),
                        Span::raw(" "),
                        Span::styled(if !draft.mask_secrets_by_default { " [● OFF] " } else { " [○ OFF] " }, if !draft.mask_secrets_by_default { active_pill } else { inactive_pill }),
                    ]),
                    Line::from(vec![
                        Span::styled(pfx3, s3),
                        Span::styled("4. New Profile Default Placement : ", s3),
                        Span::styled(if draft.insert_new_profile_at_top { " [● Top Priority #1] " } else { " [○ Top Priority #1] " }, if draft.insert_new_profile_at_top { active_pill } else { inactive_pill }),
                        Span::raw(" "),
                        Span::styled(if !draft.insert_new_profile_at_top { " [● Bottom of List] " } else { " [○ Bottom of List] " }, if !draft.insert_new_profile_at_top { active_pill } else { inactive_pill }),
                    ]),
                    Line::from(vec![
                        Span::styled(pfx4, s4),
                        Span::styled("5. Shell Prompt Auto-Reload Hook : ", s4),
                        Span::styled(if draft.shell_prompt_hook { " [● ON ] " } else { " [○ ON ] " }, if draft.shell_prompt_hook { active_pill } else { inactive_pill }),
                        Span::raw(" "),
                        Span::styled(if !draft.shell_prompt_hook { " [● OFF] " } else { " [○ OFF] " }, if !draft.shell_prompt_hook { active_pill } else { inactive_pill }),
                    ]),
                ];

                if let Some(err) = error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                }

                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }

            Modal::Help => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" ? Keyboard Shortcuts & Help ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let key_style = Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let sec_style = Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD);
                let desc_style = Style::default().fg(Color::White);

                let lines = vec![
                    Line::from(Span::styled(
                        "Keyboard Shortcuts & Mouse Controls",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled("Mouse Actions", sec_style)),
                    Line::from(vec![
                        Span::styled("  Left Click         ", key_style),
                        Span::styled("Focus pane, select item, toggle [✓] profile, or click buttons", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  Right Click        ", key_style),
                        Span::styled("Select item & open Context Menu (Edit, Delete, Toggle, etc.)", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  Scroll Wheel       ", key_style),
                        Span::styled("Scroll items in the hovered pane or context menu", desc_style),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled("Profile & Variable Actions", sec_style)),
                    Line::from(vec![
                        Span::styled("  [Space]            ", key_style),
                        Span::styled("Toggle selected profile ON / OFF", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [u / d]            ", key_style),
                        Span::styled("Move Priority up / down (top profile wins)", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [n]                ", key_style),
                        Span::styled("Create a New Profile (Custom or Phase.dev)", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [a]                ", key_style),
                        Span::styled("Add a custom environment variable", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [e / Enter]        ", key_style),
                        Span::styled("Edit selected profile or variable", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [x / Delete]       ", key_style),
                        Span::styled("Delete selected profile or variable", desc_style),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled("Phase.dev, View & System", sec_style)),
                    Line::from(vec![
                        Span::styled("  [p / P]            ", key_style),
                        Span::styled("Sync Phase.dev secrets / Rebind Phase App & Env", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [c]                ", key_style),
                        Span::styled("Configure Phase.dev authentication (CLI / Token)", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [v]                ", key_style),
                        Span::styled("Show / Hide (mask) secret values", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [s]                ", key_style),
                        Span::styled("Open application Settings", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [r]                ", key_style),
                        Span::styled("Save encrypted state & reload shell environment", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Tab / Shift+Tab]  ", key_style),
                        Span::styled("Cycle focus between Profiles, Variables, and Effective panes", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [?] / [q]          ", key_style),
                        Span::styled("Toggle this help popup / Quit application", desc_style),
                    ]),
                ];

                frame.render_widget(
                    Paragraph::new(lines).wrap(Wrap { trim: false }),
                    chunks[0],
                );
                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[1], btns);
                }
            }
        }
    }

    fn profile_index_at_row(&self, profiles_rect: Rect, row: u16) -> Option<usize> {
        let item_start_y = profiles_rect.y.saturating_add(2);
        let item_end_y = profiles_rect
            .y
            .saturating_add(profiles_rect.height.saturating_sub(1));
        if row < item_start_y || row >= item_end_y || self.data.profiles.is_empty() {
            return None;
        }
        let visible_rows = (item_end_y - item_start_y) as usize;
        let offset = if visible_rows > 0 && self.selected_profile >= visible_rows {
            self.selected_profile + 1 - visible_rows
        } else {
            0
        };
        let idx = offset + (row - item_start_y) as usize;
        (idx < self.data.profiles.len()).then_some(idx)
    }

    fn var_index_at_row(&self, vars_rect: Rect, row: u16) -> Option<usize> {
        let item_start_y = vars_rect.y.saturating_add(3);
        let item_end_y = vars_rect
            .y
            .saturating_add(vars_rect.height.saturating_sub(1));
        let vars_len = self.current_vars().len();
        if row < item_start_y || row >= item_end_y || vars_len == 0 {
            return None;
        }
        let visible_rows = (item_end_y - item_start_y) as usize;
        let offset = if visible_rows > 0 && self.selected_var >= visible_rows {
            self.selected_var + 1 - visible_rows
        } else {
            0
        };
        let idx = offset + (row - item_start_y) as usize;
        (idx < vars_len).then_some(idx)
    }

    fn effective_index_at_row(&self, effective_rect: Rect, row: u16) -> Option<usize> {
        let item_start_y = effective_rect.y.saturating_add(3);
        let item_end_y = effective_rect
            .y
            .saturating_add(effective_rect.height.saturating_sub(1));
        let eff_len = self.data.compute_effective_vars().len();
        if row < item_start_y || row >= item_end_y || eff_len == 0 {
            return None;
        }
        let visible_rows = (item_end_y - item_start_y) as usize;
        let offset = if visible_rows > 0 && self.selected_effective >= visible_rows {
            self.selected_effective + 1 - visible_rows
        } else {
            0
        };
        let idx = offset + (row - item_start_y) as usize;
        (idx < eff_len).then_some(idx)
    }

    fn scroll_pane_up(&mut self, pane: FocusPane) {
        match pane {
            FocusPane::Profiles => {
                if self.selected_profile > 0 {
                    self.selected_profile -= 1;
                    self.selected_var = 0;
                }
            }
            FocusPane::Vars => {
                if self.selected_var > 0 {
                    self.selected_var -= 1;
                }
            }
            FocusPane::Effective => {
                if self.selected_effective > 0 {
                    self.selected_effective -= 1;
                }
            }
        }
    }

    fn scroll_pane_down(&mut self, pane: FocusPane) {
        match pane {
            FocusPane::Profiles => {
                if self.selected_profile + 1 < self.data.profiles.len() {
                    self.selected_profile += 1;
                    self.selected_var = 0;
                }
            }
            FocusPane::Vars => {
                if self.selected_var + 1 < self.current_vars().len() {
                    self.selected_var += 1;
                }
            }
            FocusPane::Effective => {
                let len = self.data.compute_effective_vars().len();
                if self.selected_effective + 1 < len {
                    self.selected_effective += 1;
                }
            }
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        let area = if self.last_area.width > 0 && self.last_area.height > 0 {
            self.last_area
        } else if let Ok((w, h)) = crossterm::terminal::size() {
            Rect::new(0, 0, w, h)
        } else {
            return;
        };

        // 1. Handle active Context Menu interactions first
        if let Some(mut menu) = self.context_menu.take() {
            let popup = menu.rect(area);
            let inner_top = popup.y.saturating_add(1);
            let inner_bottom = popup.y.saturating_add(popup.height.saturating_sub(1));
            let in_menu_rows = rect_contains(popup, mouse.column, mouse.row)
                && mouse.row >= inner_top
                && mouse.row < inner_bottom;

            match mouse.kind {
                MouseEventKind::Moved => {
                    if in_menu_rows {
                        let idx = (mouse.row - inner_top) as usize;
                        if idx < menu.items.len() {
                            menu.selected = idx;
                        }
                    }
                    self.context_menu = Some(menu);
                    return;
                }
                MouseEventKind::ScrollUp => {
                    if !menu.items.is_empty() {
                        menu.selected = (menu.selected + menu.items.len() - 1) % menu.items.len();
                    }
                    self.context_menu = Some(menu);
                    return;
                }
                MouseEventKind::ScrollDown => {
                    if !menu.items.is_empty() {
                        menu.selected = (menu.selected + 1) % menu.items.len();
                    }
                    self.context_menu = Some(menu);
                    return;
                }
                MouseEventKind::Down(MouseButton::Left) => {
                    if in_menu_rows {
                        let idx = (mouse.row - inner_top) as usize;
                        if let Some(action) = menu.items.get(idx).map(|i| i.action) {
                            self.execute_context_action(action);
                        }
                    }
                    return;
                }
                MouseEventKind::Down(MouseButton::Right) => {
                    // Close current context menu and fall through to open a new one at the cursor
                }
                _ => {
                    self.context_menu = Some(menu);
                    return;
                }
            }
        }

        // 2. If a modal is open, handle modal mouse clicks without altering background focus
        if !matches!(self.modal, Modal::None) {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                let popup = get_modal_rect(&self.modal, area);
                if !rect_contains(popup, mouse.column, mouse.row) {
                    self.modal = Modal::None;
                    return;
                }
                self.handle_modal_mouse_click(popup, mouse.column, mouse.row);
            }
            return;
        }

        let (header_rect, profiles_rect, vars_rect, effective_rect, status_bar_rect) =
            compute_layout_chunks(area);

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // Status bar click handling
                if rect_contains(status_bar_rect, mouse.column, mouse.row) {
                    let help_start_x = status_bar_rect
                        .x
                        .saturating_add(status_bar_rect.width.saturating_sub(16));
                    if mouse.column >= help_start_x {
                        self.modal = Modal::Help;
                    } else if mouse.column < status_bar_rect.x.saturating_add(44) {
                        self.open_phase_connect_modal(None, None);
                    } else {
                        self.open_settings_modal();
                    }
                    return;
                }

                // Header toolbar buttons click handling
                if rect_contains(header_rect, mouse.column, mouse.row) {
                    let inner_w = header_rect.width.saturating_sub(2);
                    if inner_w >= 86 && mouse.row == header_rect.y + 1 {
                        let right_edge = header_rect.x + header_rect.width - 1;
                        let offset_from_right = right_edge.saturating_sub(mouse.column);
                        // Toolbar layout from right edge:
                        // " [+Profile]  [+Var]  [Sync]  [Show]  [Settings] " (total 52 chars)
                        if offset_from_right < 13 {
                            self.open_settings_modal();
                        } else if offset_from_right < 22 {
                            self.toggle_mask_values();
                        } else if offset_from_right < 31 {
                            self.handle_phase_sync_action(false);
                        } else if offset_from_right < 40 {
                            self.open_add_var_modal();
                        } else if offset_from_right < 53 {
                            self.open_new_profile_modal();
                        }
                    }
                    return;
                }

                // Panes & items left-click handling
                if rect_contains(profiles_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Profiles;
                    if let Some(idx) = self.profile_index_at_row(profiles_rect, mouse.row) {
                        if self.selected_profile != idx {
                            self.selected_profile = idx;
                            self.selected_var = 0;
                        }
                        let check_start = profiles_rect.x.saturating_add(4);
                        let check_end = profiles_rect.x.saturating_add(7);
                        if mouse.column >= check_start && mouse.column < check_end {
                            self.toggle_current_profile();
                        }
                    }
                } else if rect_contains(vars_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Vars;
                    if let Some(idx) = self.var_index_at_row(vars_rect, mouse.row) {
                        self.selected_var = idx;
                    }
                } else if rect_contains(effective_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Effective;
                    if let Some(idx) = self.effective_index_at_row(effective_rect, mouse.row) {
                        self.selected_effective = idx;
                    }
                }
            }

            MouseEventKind::Down(MouseButton::Right) => {
                if rect_contains(profiles_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Profiles;
                    if let Some(idx) = self.profile_index_at_row(profiles_rect, mouse.row) {
                        if self.selected_profile != idx {
                            self.selected_profile = idx;
                            self.selected_var = 0;
                        }
                    }
                    self.open_context_menu_for_pane(
                        FocusPane::Profiles,
                        mouse.column,
                        mouse.row,
                    );
                } else if rect_contains(vars_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Vars;
                    if let Some(idx) = self.var_index_at_row(vars_rect, mouse.row) {
                        self.selected_var = idx;
                    }
                    self.open_context_menu_for_pane(FocusPane::Vars, mouse.column, mouse.row);
                } else if rect_contains(effective_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Effective;
                    if let Some(idx) = self.effective_index_at_row(effective_rect, mouse.row) {
                        self.selected_effective = idx;
                    }
                    self.open_context_menu_for_pane(
                        FocusPane::Effective,
                        mouse.column,
                        mouse.row,
                    );
                }
            }

            MouseEventKind::ScrollUp => {
                let target_pane = if rect_contains(profiles_rect, mouse.column, mouse.row) {
                    FocusPane::Profiles
                } else if rect_contains(vars_rect, mouse.column, mouse.row) {
                    FocusPane::Vars
                } else if rect_contains(effective_rect, mouse.column, mouse.row) {
                    FocusPane::Effective
                } else {
                    self.focus
                };
                self.scroll_pane_up(target_pane);
            }

            MouseEventKind::ScrollDown => {
                let target_pane = if rect_contains(profiles_rect, mouse.column, mouse.row) {
                    FocusPane::Profiles
                } else if rect_contains(vars_rect, mouse.column, mouse.row) {
                    FocusPane::Vars
                } else if rect_contains(effective_rect, mouse.column, mouse.row) {
                    FocusPane::Effective
                } else {
                    self.focus
                };
                self.scroll_pane_down(target_pane);
            }

            _ => {}
        }
    }

    pub fn handle_paste(&mut self, pasted: &str) {
        let clean = pasted.trim_matches(|c| c == '\r' || c == '\n');
        match &mut self.modal {
            Modal::PhaseConnect {
                auth_method,
                host_mode,
                custom_url,
                pat_token,
                active_field,
                error,
                ..
            } => {
                if *auth_method == PhaseAuthMethod::Token {
                    let pat_idx = if *host_mode == HostMode::Cloud { 2 } else { 3 };
                    if *host_mode == HostMode::SelfHosted && *active_field == 2 {
                        for c in clean.chars() {
                            insert_char_at(custom_url, self.input_cursor, c);
                            self.input_cursor += 1;
                        }
                        *error = None;
                    } else if *active_field == pat_idx {
                        for c in clean.chars() {
                            insert_char_at(pat_token, self.input_cursor, c);
                            self.input_cursor += 1;
                        }
                        *error = None;
                    }
                }
            }
            Modal::NewProfile {
                name,
                active_field,
                error,
                ..
            } => {
                if *active_field == 0 {
                    for c in clean.chars() {
                        insert_char_at(name, self.input_cursor, c);
                        self.input_cursor += 1;
                    }
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
                    for c in clean.chars() {
                        insert_char_at(var_key, self.input_cursor, c);
                        self.input_cursor += 1;
                    }
                } else {
                    for c in clean.chars() {
                        insert_char_at(var_value, self.input_cursor, c);
                        self.input_cursor += 1;
                    }
                }
                *error = None;
            }
            Modal::EditProfile { name, error, .. } => {
                for c in clean.chars() {
                    insert_char_at(name, self.input_cursor, c);
                    self.input_cursor += 1;
                }
                *error = None;
            }
            Modal::Settings { .. } => {}
            _ => {}
        }
    }

    fn handle_modal_mouse_click(&mut self, popup: Rect, col: u16, row: u16) {
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(block_inner);

        let btn_chunk = chunks[1];

        if let Some(btns) = get_modal_buttons(&self.modal) {
            let total_len = if btns.cancel.is_empty() {
                btns.primary.len()
            } else {
                btns.primary.len() + 3 + btns.cancel.len()
            };
            let start_x = btn_chunk.x + (btn_chunk.width.saturating_sub(total_len as u16)) / 2;
            let primary_end = start_x + btns.primary.len() as u16;
            let cancel_start = primary_end + 3;
            let cancel_end = cancel_start + btns.cancel.len() as u16;

            if row == btn_chunk.y {
                if col >= start_x && col < primary_end {
                    if matches!(self.modal, Modal::Help) {
                        self.modal = Modal::None;
                    } else {
                        self.handle_modal_key(KeyEvent::from(KeyCode::Enter));
                    }
                    return;
                }
                if !btns.cancel.is_empty() && col >= cancel_start && col < cancel_end {
                    self.handle_modal_key(KeyEvent::from(KeyCode::Esc));
                    return;
                }
            }
        }

        match &mut self.modal {
            Modal::NewProfile {
                active_field,
                pull_from_phase,
                name,
                ..
            } => {
                if row >= block_inner.y + 2 && row <= block_inner.y + 3 {
                    *active_field = 0;
                    if col >= block_inner.x + 6 {
                        self.input_cursor = ((col - (block_inner.x + 6)) as usize).min(name.chars().count());
                    } else {
                        self.input_cursor = name.chars().count();
                    }
                } else if row == block_inner.y + 5 {
                    *active_field = 1;
                } else if row == block_inner.y + 6 {
                    *active_field = 1;
                    *pull_from_phase = false;
                } else if row == block_inner.y + 7 {
                    *active_field = 1;
                    *pull_from_phase = true;
                }
            }
            Modal::VarEditor { active_field, var_key, var_value, .. } => {
                if row >= block_inner.y + 2 && row <= block_inner.y + 3 {
                    *active_field = 0;
                    if col >= block_inner.x + 6 {
                        self.input_cursor = ((col - (block_inner.x + 6)) as usize).min(var_key.chars().count());
                    } else {
                        self.input_cursor = var_key.chars().count();
                    }
                } else if row >= block_inner.y + 5 && row <= block_inner.y + 6 {
                    *active_field = 1;
                    if col >= block_inner.x + 6 {
                        self.input_cursor = ((col - (block_inner.x + 6)) as usize).min(var_value.chars().count());
                    } else {
                        self.input_cursor = var_value.chars().count();
                    }
                }
            }
            Modal::EditProfile { name, .. } => {
                if col >= block_inner.x + 6 {
                    self.input_cursor = ((col - (block_inner.x + 6)) as usize).min(name.chars().count());
                } else {
                    self.input_cursor = name.chars().count();
                }
            }
            Modal::Settings {
                active_field,
                draft,
                ..
            } => {
                let start_row = block_inner.y + 2;
                if row >= start_row && row < start_row + 5 {
                    let idx = (row - start_row) as usize;
                    *active_field = idx;
                    if col >= block_inner.x + 36 {
                        match idx {
                            0 => {
                                draft.sync_only_enabled_profiles =
                                    !draft.sync_only_enabled_profiles
                            }
                            1 => draft.phase_export_all_paths = !draft.phase_export_all_paths,
                            2 => draft.mask_secrets_by_default = !draft.mask_secrets_by_default,
                            3 => {
                                draft.insert_new_profile_at_top =
                                    !draft.insert_new_profile_at_top
                            }
                            4 => draft.shell_prompt_hook = !draft.shell_prompt_hook,
                            _ => {}
                        }
                    }
                }
            }
            Modal::PhasePicker {
                selected_app,
                selected_env,
                selecting_env,
                apps,
                ..
            } => {
                let list_start_y = block_inner.y + 1;
                let list_end_y = btn_chunk.y.saturating_sub(1);
                if row >= list_start_y && row < list_end_y {
                    let offset = (row - list_start_y) as usize;
                    let mid_x = block_inner.x + block_inner.width / 2;
                    if col < mid_x {
                        if offset < apps.len() {
                            *selected_app = offset;
                            *selected_env = 0;
                            *selecting_env = false;
                        }
                    } else if let Some(app) = apps.get(*selected_app) {
                        if offset < app.environments.len() {
                            *selected_env = offset;
                            *selecting_env = true;
                        }
                    }
                }
            }
            Modal::PhaseConnect {
                active_field,
                auth_method,
                host_mode,
                ..
            } => {
                if row == block_inner.y + 2 {
                    *active_field = 0;
                } else if row == block_inner.y + 3 {
                    *active_field = 0;
                    *auth_method = PhaseAuthMethod::Cli;
                } else if row == block_inner.y + 4 {
                    *active_field = 0;
                    *auth_method = PhaseAuthMethod::Token;
                } else if *auth_method == PhaseAuthMethod::Token {
                    if row == block_inner.y + 6 {
                        *active_field = 1;
                    } else if row == block_inner.y + 7 {
                        *active_field = 1;
                        *host_mode = HostMode::Cloud;
                    } else if row == block_inner.y + 8 {
                        *active_field = 1;
                        *host_mode = HostMode::SelfHosted;
                    } else if *host_mode == HostMode::SelfHosted
                        && (row >= block_inner.y + 10 && row <= block_inner.y + 11)
                    {
                        *active_field = 2;
                    } else if row >= block_inner.y + 12 {
                        let pat_idx = if *host_mode == HostMode::Cloud { 2 } else { 3 };
                        *active_field = pat_idx;
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn compact_modal_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(4)).max(24);
    let h = height.min(area.height.saturating_sub(2)).max(6);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

pub fn get_modal_rect(modal: &Modal, area: Rect) -> Rect {
    match modal {
        Modal::None => Rect::default(),
        Modal::ConfirmDeleteProfile { .. } | Modal::ConfirmDeleteVar { .. } => {
            compact_modal_rect(54, 9, area)
        }
        Modal::EditProfile { .. } => compact_modal_rect(58, 12, area),
        Modal::NewProfile { .. } => compact_modal_rect(64, 14, area),
        Modal::VarEditor { .. } => compact_modal_rect(64, 14, area),
        Modal::Settings { .. } => compact_modal_rect(70, 16, area),
        Modal::PhaseConnect { .. } => compact_modal_rect(70, 20, area),
        Modal::PhasePicker { .. } => compact_modal_rect(70, 18, area),
        Modal::Help => compact_modal_rect(74, 24, area),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModalButtons {
    pub primary: &'static str,
    pub cancel: &'static str,
    pub is_danger: bool,
}

pub fn get_modal_buttons(modal: &Modal) -> Option<ModalButtons> {
    match modal {
        Modal::None => None,
        Modal::NewProfile { .. } => Some(ModalButtons {
            primary: " [Create] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::VarEditor { .. } => Some(ModalButtons {
            primary: " [Save] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::EditProfile { .. } => Some(ModalButtons {
            primary: " [Save] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::ConfirmDeleteProfile { .. } | Modal::ConfirmDeleteVar { .. } => Some(ModalButtons {
            primary: " [Delete] ",
            cancel: " [Cancel] ",
            is_danger: true,
        }),
        Modal::Settings { .. } => Some(ModalButtons {
            primary: " [Save] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::PhaseConnect { .. } => Some(ModalButtons {
            primary: " [Connect] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::PhasePicker { .. } => Some(ModalButtons {
            primary: " [Select] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::Help => Some(ModalButtons {
            primary: " [Close] ",
            cancel: "",
            is_danger: false,
        }),
    }
}

pub fn render_modal_buttons(frame: &mut Frame, area: Rect, buttons: ModalButtons) {
    let btn_style = if buttons.is_danger {
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(140, 35, 45))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .bg(Color::Rgb(25, 38, 58))
            .add_modifier(Modifier::BOLD)
    };

    let cancel_style = Style::default()
        .fg(Color::Gray)
        .bg(Color::Rgb(35, 42, 54))
        .add_modifier(Modifier::BOLD);

    let mut spans = vec![Span::styled(buttons.primary, btn_style)];
    if !buttons.cancel.is_empty() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(buttons.cancel, cancel_style));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)).alignment(Alignment::Center), area);
}

fn insert_char_at(s: &mut String, idx: usize, c: char) {
    let char_indices: Vec<(usize, char)> = s.char_indices().collect();
    if idx >= char_indices.len() {
        s.push(c);
    } else {
        let byte_pos = char_indices[idx].0;
        s.insert(byte_pos, c);
    }
}

fn remove_char_at(s: &mut String, idx: usize) -> bool {
    let char_indices: Vec<(usize, char)> = s.char_indices().collect();
    if idx < char_indices.len() {
        let byte_pos = char_indices[idx].0;
        s.remove(byte_pos);
        true
    } else {
        false
    }
}

fn modern_input_lines(
    label: &str,
    value: &str,
    placeholder: &str,
    is_active: bool,
    box_width: usize,
    cursor_pos: usize,
) -> Vec<Line<'static>> {
    let active_bracket = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let inactive_bracket = Style::default().fg(Color::DarkGray);

    let active_bg = Color::Rgb(22, 34, 52);
    let inactive_bg = Color::Rgb(18, 22, 30);

    let (label_style, prefix_style) = if is_active {
        (
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            Style::default().fg(Color::Yellow),
            Style::default().fg(Color::DarkGray),
        )
    };

    let prefix = if is_active { "▸ " } else { "  " };
    let bg = if is_active { active_bg } else { inactive_bg };
    let bracket_style = if is_active { active_bracket } else { inactive_bracket };

    let mut content_spans = Vec::new();
    let chars: Vec<char> = value.chars().collect();
    let cursor = cursor_pos.min(chars.len());

    if chars.is_empty() {
        if is_active {
            content_spans.push(Span::styled(
                "█",
                Style::default().fg(Color::Cyan).bg(bg).add_modifier(Modifier::BOLD),
            ));
            let pad_len = box_width.saturating_sub(1);
            if !placeholder.is_empty() && pad_len > 1 {
                let shown_ph = if placeholder.len() > pad_len - 1 {
                    &placeholder[..pad_len - 1]
                } else {
                    placeholder
                };
                content_spans.push(Span::styled(
                    shown_ph.to_string(),
                    Style::default().fg(Color::DarkGray).bg(bg),
                ));
                let rem = pad_len.saturating_sub(shown_ph.len());
                if rem > 0 {
                    content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
                }
            } else if pad_len > 0 {
                content_spans.push(Span::styled(" ".repeat(pad_len), Style::default().bg(bg)));
            }
        } else {
            let shown_ph = if placeholder.len() > box_width {
                &placeholder[..box_width]
            } else {
                placeholder
            };
            content_spans.push(Span::styled(
                shown_ph.to_string(),
                Style::default().fg(Color::DarkGray).bg(bg),
            ));
            let rem = box_width.saturating_sub(shown_ph.len());
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        }
    } else if is_active {
        if cursor < chars.len() {
            let before: String = chars[..cursor].iter().collect();
            if !before.is_empty() {
                content_spans.push(Span::styled(
                    before,
                    Style::default().fg(Color::White).bg(bg).add_modifier(Modifier::BOLD),
                ));
            }
            let cursor_char = chars[cursor];
            content_spans.push(Span::styled(
                cursor_char.to_string(),
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
            ));
            let after: String = chars[cursor + 1..].iter().collect();
            if !after.is_empty() {
                content_spans.push(Span::styled(
                    after,
                    Style::default().fg(Color::White).bg(bg).add_modifier(Modifier::BOLD),
                ));
            }
            let rem = box_width.saturating_sub(chars.len());
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        } else {
            content_spans.push(Span::styled(
                value.to_string(),
                Style::default().fg(Color::White).bg(bg).add_modifier(Modifier::BOLD),
            ));
            content_spans.push(Span::styled(
                "█",
                Style::default().fg(Color::Cyan).bg(bg).add_modifier(Modifier::BOLD),
            ));
            let rem = box_width.saturating_sub(chars.len() + 1);
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        }
    } else {
        content_spans.push(Span::styled(
            value.to_string(),
            Style::default().fg(Color::White).bg(bg),
        ));
        let rem = box_width.saturating_sub(chars.len());
        if rem > 0 {
            content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
        }
    }

    let mut line2_spans = vec![
        Span::raw("    "),
        Span::styled("[ ", bracket_style),
    ];
    line2_spans.extend(content_spans);
    line2_spans.push(Span::styled(" ]", bracket_style));

    vec![
        Line::from(vec![
            Span::styled(prefix, prefix_style),
            Span::styled(label.to_string(), label_style),
        ]),
        Line::from(line2_spans),
    ]
}

fn modern_vertical_radio_options(
    label: &str,
    options: &[(&'static str, &'static str)],
    selected_idx: usize,
    is_active: bool,
) -> Vec<Line<'static>> {
    let (label_style, prefix_style) = if is_active {
        (
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            Style::default().fg(Color::Yellow),
            Style::default().fg(Color::DarkGray),
        )
    };

    let prefix = if is_active { "▸ " } else { "  " };

    let active_radio_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let inactive_radio_style = Style::default().fg(Color::DarkGray);

    let active_text_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let inactive_text_style = Style::default().fg(Color::Gray);

    let mut lines = vec![Line::from(vec![
        Span::styled(prefix, prefix_style),
        Span::styled(label.to_string(), label_style),
    ])];

    for (idx, (_id, opt_label)) in options.iter().enumerate() {
        let is_sel = idx == selected_idx;
        let radio_marker = if is_sel { "(●) " } else { "(○) " };
        let (marker_style, text_style) = if is_sel {
            (active_radio_style, active_text_style)
        } else {
            (inactive_radio_style, inactive_text_style)
        };

        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(radio_marker, marker_style),
            Span::styled((*opt_label).to_string(), text_style),
        ]));
    }

    lines
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    x >= rect.x
        && x < rect.x.saturating_add(rect.width)
        && y >= rect.y
        && y < rect.y.saturating_add(rect.height)
}

pub fn compute_layout_chunks(area: Rect) -> (Rect, Rect, Rect, Rect, Rect) {
    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top header
            Constraint::Min(12),   // Main body
            Constraint::Length(1), // Bottom status bar
        ])
        .split(area);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(24), Constraint::Percentage(76)])
        .split(root_chunks[1]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(main_chunks[1]);

    (
        root_chunks[0],
        main_chunks[0],
        right_chunks[0],
        right_chunks[1],
        root_chunks[2],
    )
}

#[cfg(test)]
pub fn compute_pane_areas(area: Rect) -> (Rect, Rect, Rect) {
    let (_, profiles, vars, effective, _) = compute_layout_chunks(area);
    (profiles, vars, effective)
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
        crossterm::event::EnableBracketedPaste,
        crossterm::event::EnableMouseCapture
    )
    .map_err(|e| format!("Failed to enter alternate screen: {}", e))?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal =
        ratatui::Terminal::new(backend).map_err(|e| format!("Failed to init terminal: {}", e))?;

    let res = (|| -> Result<(), String> {
        loop {
            app.clear_expired_status();

            terminal
                .draw(|f| app.draw(f))
                .map_err(|e| format!("Draw error: {}", e))?;

            if app.should_quit {
                break;
            }

            if app.pending_phase_sync.is_some() {
                app.perform_pending_sync();
                continue;
            }

            if event::poll(std::time::Duration::from_millis(250))
                .map_err(|e| format!("Event poll error: {}", e))?
            {
                match event::read().map_err(|e| format!("Event read error: {}", e))? {
                    Event::Key(key) => app.handle_key(key),
                    Event::Paste(text) => app.handle_paste(&text),
                    Event::Mouse(mouse) => app.handle_mouse(mouse),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    let _ = crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableMouseCapture,
        crossterm::event::DisableBracketedPaste,
        crossterm::terminal::LeaveAlternateScreen
    );
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = terminal.show_cursor();

    let _ = apply_state_to_system(&app.data);

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VarSource;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn make_test_app() -> App {
        let mut data = AppStateData::default();
        data.profiles[0].vars.push(EnvVar::new(
            "API_KEY".to_string(),
            "sk-123456789xyz".to_string(),
            VarSource::Custom,
        ));
        App {
            data,
            focus: FocusPane::Profiles,
            selected_profile: 0,
            selected_var: 0,
            selected_effective: 0,
            show_values: false,
            modal: Modal::None,
            context_menu: None,
            status_message: String::new(),
            is_error_status: false,
            status_message_time: None,
            should_quit: false,
            cached_apps: Vec::new(),
            last_area: Rect::default(),
            pending_phase_sync: None,
            input_cursor: 0,
        }
    }

    #[test]
    fn test_default_profile_can_be_edited_renamed_toggled_deleted() {
        let mut app = make_test_app();
        assert_eq!(app.data.profiles[0].name, "default");
        assert!(app.data.profiles[0].enabled);

        // 1. Toggle OFF
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(!app.data.profiles[0].enabled);

        // 2. Toggle ON
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(app.data.profiles[0].enabled);

        // 3. Edit (Rename) via 'e'
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        match &app.modal {
            Modal::EditProfile {
                profile_idx, name, ..
            } => {
                assert_eq!(*profile_idx, 0);
                assert_eq!(name, "default");
            }
            _ => panic!("Expected Modal::EditProfile"),
        }

        // Type new name: Ctrl+u to clear, type "staging", Enter
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for c in "staging".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::None));
        assert_eq!(app.data.profiles[0].name, "staging");

        // 4. Delete via 'x'
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(app.modal, Modal::ConfirmDeleteProfile { .. }));
        app.handle_key(KeyEvent::from(KeyCode::Char('y')));
        assert!(app.data.profiles.is_empty());
    }

    #[test]
    fn test_move_priority_shortcut_u_d() {
        let mut app = make_test_app();
        app.data.profiles.push(Profile {
            name: "second_profile".to_string(),
            enabled: true,
            phase_binding: None,
            last_sync_epoch: None,
            vars: Vec::new(),
        });
        assert_eq!(app.data.profiles[0].name, "default");
        assert_eq!(app.data.profiles[1].name, "second_profile");

        app.selected_profile = 1;

        app.handle_key(KeyEvent::from(KeyCode::Char('u')));
        assert_eq!(app.data.profiles[0].name, "second_profile");
        assert_eq!(app.data.profiles[1].name, "default");
        assert_eq!(app.selected_profile, 0);

        app.handle_key(KeyEvent::from(KeyCode::Char('d')));
        assert_eq!(app.data.profiles[0].name, "default");
        assert_eq!(app.data.profiles[1].name, "second_profile");
        assert_eq!(app.selected_profile, 1);

        app.handle_key(KeyEvent::from(KeyCode::Char('K')));
        assert_eq!(app.data.profiles[1].name, "second_profile");
        app.handle_key(KeyEvent::from(KeyCode::Char('J')));
        assert_eq!(app.data.profiles[1].name, "second_profile");
    }

    #[test]
    fn test_edit_action_works_across_panes() {
        let mut app = make_test_app();

        app.focus = FocusPane::Profiles;
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        assert!(matches!(app.modal, Modal::EditProfile { .. }));
        app.modal = Modal::None;

        app.focus = FocusPane::Vars;
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        match &app.modal {
            Modal::VarEditor {
                is_edit,
                var_key,
                var_value,
                ..
            } => {
                assert!(*is_edit);
                assert_eq!(var_key, "API_KEY");
                assert_eq!(var_value, "sk-123456789xyz");
            }
            _ => panic!("Expected Modal::VarEditor"),
        }
        app.modal = Modal::None;

        app.focus = FocusPane::Effective;
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        match &app.modal {
            Modal::VarEditor {
                is_edit, var_key, ..
            } => {
                assert!(*is_edit);
                assert_eq!(var_key, "API_KEY");
            }
            _ => panic!("Expected Modal::VarEditor from Effective pane"),
        }
    }

    #[test]
    fn test_phase_profile_disallows_manual_var_mixing() {
        let mut app = make_test_app();
        app.data.profiles.insert(
            0,
            Profile::new_phase(
                "phase_prod".to_string(),
                PhaseBinding {
                    app_id: "app1".to_string(),
                    app_name: "MyService".to_string(),
                    env_id: "env1".to_string(),
                    env_name: "Production".to_string(),
                },
                vec![("PHASE_SECRET".to_string(), "val123456".to_string())],
            ),
        );
        app.selected_profile = 0;

        // Pressing 'a' on a Phase profile must NOT open VarEditor
        app.handle_key(KeyEvent::from(KeyCode::Char('a')));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);

        // Pressing 'e' on Vars pane of a Phase profile must NOT open VarEditor
        app.focus = FocusPane::Vars;
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);

        // Pressing 'x' on Vars pane of a Phase profile must NOT open ConfirmDeleteVar
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);
    }

    #[test]
    fn test_settings_modal_toggle_options() {
        let mut app = make_test_app();
        assert!(app.data.settings.sync_only_enabled_profiles);

        // Open settings with 's'
        app.handle_key(KeyEvent::from(KeyCode::Char('s')));
        assert!(matches!(app.modal, Modal::Settings { .. }));

        // Field 0: toggle sync_only_enabled_profiles with Space
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        // Save with Enter
        app.handle_key(KeyEvent::from(KeyCode::Enter));

        assert!(matches!(app.modal, Modal::None));
        assert!(!app.data.settings.sync_only_enabled_profiles);
    }

    #[test]
    fn test_vars_panel_title_shows_last_sync_only_for_phase_profiles() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Initially, selected profile is 'default' (Custom profile)
        assert!(app.data.profiles[0].is_custom());
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("1 variable in default profile"));
        assert!(!content.contains("Last sync"));

        // 2. Add and select a Phase profile
        let phase_prof = Profile::new_phase(
            "phase_prod".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "MyService".to_string(),
                env_id: "env1".to_string(),
                env_name: "Production".to_string(),
            },
            vec![("PHASE_KEY".to_string(), "val".to_string())],
        );
        app.data.profiles.push(phase_prof);
        app.selected_profile = 1;
        assert!(app.data.profiles[1].is_phase());

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content2: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content2.contains("1 variable in phase_prod profile"));
        assert!(content2.contains("Last sync: just now"));

        // 3. Switch back to custom profile (index 0)
        app.selected_profile = 0;
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content3: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content3.contains("1 variable in default profile"));
        assert!(!content3.contains("Last sync"));
    }

    #[test]
    fn test_ui_titles_padding_and_masked_keys() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("Profiles (Top Wins"));
        assert!(!content.contains("1. Default & Profiles"));
        assert!(!content.contains("Profiles (Top #1 Wins Priority)"));
        assert!(content.contains("1 variable in default"));
        assert!(!content.contains("Variables in Profile:"));
        assert!(!content.contains("Variables in profile"));
        assert!(!content.contains("(1v)"));
        assert!(!content.contains("Profile #1"));
        assert!(!content.contains("2. Variables in"));
        assert!(content.contains("Active System Environment"));
        assert!(!content.contains("3. Active System Environment"));
        assert!(!content.contains("encrypted in state.enc"));
        // Full shortcut list is removed from the bottom; `? Shortcuts` indicator is shown instead
        assert!(!content.contains("[u/d] Move Priority"));
        assert!(!content.contains("[Space] Toggle"));
        assert!(content.contains("?"));
        assert!(content.contains("Shortcuts"));
        assert!(!content.contains("[K/J"));
        assert!(content.contains("PROFILE"));
        assert!(!content.contains("WINNING PROFILE"));
        assert!(content.contains("PROFILE"));
        assert!(!content.contains("WINNING PROFILE"));
        assert!(!content.contains("Ready"));
        assert!(content.contains("Environtment Variables Manager"));
        assert!(content.contains("[Settings]"));
        assert!(!content.contains("Environment & Phase.dev Manager"));
        assert!(!content.contains("Store:"));
        assert!(!content.contains("VALUE ([v] show/hide)"));
        assert!(content.contains("VALUE"));
        assert!(content.contains("SOURCE"));
        assert!(!content.contains("ORIGIN"));
        assert!(content.contains("Phase.dev:"));
    }

    #[test]
    fn test_help_popup_via_question_mark_and_status_bar_click() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Press '?' to open help popup
        app.handle_key(KeyEvent::from(KeyCode::Char('?')));
        assert!(matches!(app.modal, Modal::Help));

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("Keyboard Shortcuts & Mouse Controls"));
        assert!(content.contains("Move Priority"));
        assert!(content.contains("Right Click"));

        // Close with '?' or Esc
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(app.modal, Modal::None));

        // 2. Click the `? Shortcuts` indicator in the status bar at the bottom-right
        let (_, _, _, _, status_bar_rect) = compute_layout_chunks(app.last_area);
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: status_bar_rect.x + status_bar_rect.width - 3,
            row: status_bar_rect.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(app.modal, Modal::Help));

        // Click anywhere to close the help popup
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 10,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(app.modal, Modal::None));
    }

    #[test]
    fn test_mouse_click_and_right_click_items_and_context_menu() {
        let mut app = make_test_app();
        app.data.profiles[0].vars.push(EnvVar::new(
            "SECOND_KEY".to_string(),
            "val-987654321".to_string(),
            VarSource::Custom,
        ));
        app.data.profiles.push(Profile::new_custom("staging".to_string()));
        app.last_area = Rect::new(0, 0, 120, 30);

        let (profiles_rect, vars_rect, _) = compute_pane_areas(app.last_area);

        // 1. Left-click the second profile ("staging" at row profiles_rect.y + 3)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: profiles_rect.x + 8,
            row: profiles_rect.y + 3,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Profiles);
        assert_eq!(app.selected_profile, 1);

        // 2. Left-click back on the first profile ("default" at row profiles_rect.y + 2)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: profiles_rect.x + 8,
            row: profiles_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.selected_profile, 0);

        // 3. Left-click the second variable ("SECOND_KEY" at row vars_rect.y + 4)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 5,
            row: vars_rect.y + 4,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Vars);
        assert_eq!(app.selected_var, 1);

        // 4. Right-click on the first variable ("API_KEY" at row vars_rect.y + 3)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Right),
            column: vars_rect.x + 6,
            row: vars_rect.y + 3,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Vars);
        assert_eq!(app.selected_var, 0);
        assert!(app.context_menu.is_some());

        // Render and verify Context Menu shows Edit and Delete actions
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(content.contains("Edit Variable"));
        assert!(content.contains("Delete Variable"));

        // 5. Click "Edit Variable" (first item in context menu at menu_rect.y + 1)
        let menu_rect = app.context_menu.as_ref().unwrap().rect(app.last_area);
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: menu_rect.x + 3,
            row: menu_rect.y + 1,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.context_menu.is_none());
        match &app.modal {
            Modal::VarEditor {
                is_edit, var_key, ..
            } => {
                assert!(*is_edit);
                assert_eq!(var_key, "API_KEY");
            }
            _ => panic!("Expected Modal::VarEditor from context menu Edit click"),
        }
        app.modal = Modal::None;

        // 6. Right-click variable again and click "Delete Variable" (second item at menu_rect.y + 2)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Right),
            column: vars_rect.x + 6,
            row: vars_rect.y + 3,
            modifiers: KeyModifiers::empty(),
        });
        let menu_rect = app.context_menu.as_ref().unwrap().rect(app.last_area);
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: menu_rect.x + 3,
            row: menu_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.context_menu.is_none());
        match &app.modal {
            Modal::ConfirmDeleteVar { var_key, .. } => {
                assert_eq!(var_key, "API_KEY");
            }
            _ => panic!("Expected Modal::ConfirmDeleteVar from context menu Delete click"),
        }
    }

    #[test]
    fn test_status_message_rendered_in_status_bar() {
        let mut app = make_test_app();
        app.set_info("Secret values are now masked.");
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("Secret values are now masked."));
        assert!(content.contains("Environtment Variables Manager"));
        assert!(content.contains("Phase.dev:"));
    }

    #[test]
    fn test_mouse_click_gains_focus_on_panes() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 100, 30);
        let (profiles_rect, vars_rect, effective_rect) = compute_pane_areas(app.last_area);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 2,
            row: vars_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Vars);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: effective_rect.x + 2,
            row: effective_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Effective);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: profiles_rect.x + 2,
            row: profiles_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Profiles);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Right),
            column: vars_rect.x + 2,
            row: vars_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Vars);
        assert!(app.context_menu.is_some());
        app.context_menu = None;
        app.focus = FocusPane::Profiles;

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 1,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Profiles);

        app.modal = Modal::ConfirmDeleteVar {
            var_idx: 0,
            var_key: "API_KEY".to_string(),
        };
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 2,
            row: vars_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Profiles);
    }

    #[test]
    fn test_keyboard_navigation_between_panes() {
        let mut app = make_test_app();
        assert_eq!(app.focus, FocusPane::Profiles);

        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Effective);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Profiles);

        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Effective);
        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Profiles);

        app.handle_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.focus, FocusPane::Profiles);
    }

    #[test]
    fn test_phase_connection_status_is_plain_text_without_green_or_bg() {
        let mut app = make_test_app();
        app.data.phase.auth_method = PhaseAuthMethod::Token;
        app.data.phase.pat_token = "pss_user:test_token_12345".to_string();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let status_row = buffer.area.height - 1;

        let status_text: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();

        assert!(status_text.contains("Connected (API Token"));

        // Verify cells containing "Connected" do not use green text or background
        let needle = "Connected";
        let start_x = status_text.find(needle).expect("needle present");
        for x in start_x..(start_x + needle.len()) {
            let cell = buffer.get(x as u16, status_row);
            assert_ne!(cell.fg, Color::Green, "Connection status must not use green text");
            assert_ne!(cell.bg, Color::Green, "Connection status must not use green background");
            assert_eq!(cell.bg, Color::Rgb(25, 35, 50), "Connection status uses plain status bar background");
        }
    }

    #[test]
    fn test_settings_button_visible_not_clipped_and_clickable() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let row1: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, 1).symbol())
            .collect();

        assert!(row1.contains("[Settings]"), "Closing bracket ']' of [Settings] must be visible: '{}'", row1);

        // Click rightmost Settings button
        let (header_rect, _, _, _, _) = compute_layout_chunks(app.last_area);
        let settings_col = header_rect.x + header_rect.width - 4;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: settings_col,
            row: header_rect.y + 1,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(app.modal, Modal::Settings { .. }));
    }

    #[test]
    fn test_sync_button_and_menu_sets_in_progress_and_success_status() {
        let mut app = make_test_app();
        app.data.phase.auth_method = PhaseAuthMethod::Token;
        app.data.phase.pat_token = "pss_user:mock_token".to_string();
        app.data.profiles[0].phase_binding = Some(PhaseBinding {
            app_id: "app-1".to_string(),
            app_name: "my-app".to_string(),
            env_id: "env-1".to_string(),
            env_name: "prod".to_string(),
        });

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Click header [Sync] button
        terminal.draw(|f| app.draw(f)).unwrap();
        let (header_rect, _, _, _, _) = compute_layout_chunks(app.last_area);
        let sync_col = header_rect.x + header_rect.width - 26;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: sync_col,
            row: header_rect.y + 1,
            modifiers: KeyModifiers::empty(),
        });

        assert_eq!(app.status_message, "Phase.dev sync in progress...");
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::Profile(0)));

        // Verify status bar displays the in-progress message
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let status_row = buffer.area.height - 1;
        let row_text: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();
        assert!(row_text.contains("Phase.dev sync in progress..."));

        // 2. Perform pending sync (mock profile with non-existent secrets will return fail/mock)
        app.perform_pending_sync();
        assert_eq!(app.pending_phase_sync, None);
        assert!(
            app.status_message.contains("Phase.dev sync"),
            "Expected status message to indicate Phase.dev sync completion: '{}'",
            app.status_message
        );

        // Verify status bar displays updated status
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let row_text_completed: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();
        assert!(row_text_completed.contains("Phase.dev sync"));

        // 3. Test context menu sync action
        app.execute_context_action(ContextAction::PhaseSync);
        assert_eq!(app.status_message, "Phase.dev sync in progress...");
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::Profile(0)));
    }

    #[test]
    fn test_status_message_expires_after_five_seconds_while_error_stays() {
        let mut app = make_test_app();
        app.set_info("Phase.dev sync succeeded for 'default' (1 vars)");
        assert_eq!(app.status_message, "Phase.dev sync succeeded for 'default' (1 vars)");

        // 1. Simulating within 5 seconds: message stays
        app.clear_expired_status();
        assert_eq!(app.status_message, "Phase.dev sync succeeded for 'default' (1 vars)");

        // 2. Simulating past 5 seconds (5.1s): info message cleared
        app.status_message_time = Some(Instant::now() - Duration::from_millis(5100));
        app.clear_expired_status();
        assert!(app.status_message.is_empty(), "Info status message must expire after ~5s");

        // 3. Error messages must NOT expire
        app.set_error("Connection timed out to Phase.dev");
        app.status_message_time = Some(Instant::now() - Duration::from_secs(10));
        app.clear_expired_status();
        assert_eq!(
            app.status_message,
            "Connection timed out to Phase.dev",
            "Error messages must remain visible and not expire automatically"
        );
    }

    #[test]
    fn test_panel_widths_swapped() {
        let area = Rect::new(0, 0, 100, 30);
        let (_, profiles, vars, _, _) = compute_layout_chunks(area);

        // Panel widths swapped: Left panel = 24%, Right panel = 76%
        assert_eq!(profiles.width, 24);
        assert_eq!(vars.width, 76);
    }

    #[test]
    fn test_modal_padding_and_buttons_clickable_with_mouse() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        // 1. Open New Profile modal
        app.modal = Modal::NewProfile {
            name: "new-prod".to_string(),
            pull_from_phase: false,
            active_field: 0,
            error: None,
        };

        let popup = get_modal_rect(&app.modal, area);
        assert!(popup.width < area.width, "Popup must be compact and fitted");
        assert!(popup.height < area.height, "Popup must be compact and fitted");

        // Click Cancel button in NewProfile popup
        let btns = get_modal_buttons(&app.modal).expect("has buttons");
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(block_inner);
        let btn_chunk = chunks[1];
        let total_len = btns.primary.len() + 3 + btns.cancel.len();
        let start_x = btn_chunk.x + (btn_chunk.width.saturating_sub(total_len as u16)) / 2;
        let cancel_click_x = start_x + btns.primary.len() as u16 + 4;

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cancel_click_x,
            row: btn_chunk.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(app.modal, Modal::None), "Clicking Cancel button must close the modal");

        // 2. Open VarEditor modal and click Save button
        app.modal = Modal::VarEditor {
            is_edit: false,
            original_index: None,
            var_key: "NEW_KEY".to_string(),
            var_value: "new_value".to_string(),
            active_field: 0,
            error: None,
        };
        let popup = get_modal_rect(&app.modal, area);
        let btns = get_modal_buttons(&app.modal).expect("has buttons");
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(block_inner);
        let btn_chunk = chunks[1];
        let total_len = btns.primary.len() + 3 + btns.cancel.len();
        let start_x = btn_chunk.x + (btn_chunk.width.saturating_sub(total_len as u16)) / 2;
        let save_click_x = start_x + 2;

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: save_click_x,
            row: btn_chunk.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(app.modal, Modal::None), "Clicking Save button must submit and close modal");
        assert!(app.data.profiles[0].vars.iter().any(|v| v.key == "NEW_KEY"), "Variable must be created on Save click");
    }

    #[test]
    fn test_input_box_does_not_shrink_and_cursor_visible() {
        // Test that modern_input_lines maintains constant width regardless of typed text length
        let l_empty = modern_input_lines("Key:", "", "enter key", true, 30, 0);
        let l_1char = modern_input_lines("Key:", "A", "enter key", true, 30, 1);
        let l_5char = modern_input_lines("Key:", "ABCDE", "enter key", true, 30, 5);
        let l_15char = modern_input_lines("Key:", "ABCDEFGHIJKLMNO", "enter key", true, 30, 15);

        let w_empty: usize = l_empty[1].spans.iter().map(|s| s.content.chars().count()).sum();
        let w_1char: usize = l_1char[1].spans.iter().map(|s| s.content.chars().count()).sum();
        let w_5char: usize = l_5char[1].spans.iter().map(|s| s.content.chars().count()).sum();
        let w_15char: usize = l_15char[1].spans.iter().map(|s| s.content.chars().count()).sum();

        assert_eq!(w_empty, w_1char, "Input width must not shrink while typing");
        assert_eq!(w_1char, w_5char, "Input width must not shrink while typing");
        assert_eq!(w_5char, w_15char, "Input width must not shrink while typing");

        // Cursor '█' must be present in the active input
        assert!(l_5char[1].spans.iter().any(|s| s.content == "█"), "Cursor must be visible");

        // Test cursor navigating within text: cursor on character 'C' (idx 2) in "ABCDE"
        let l_inside = modern_input_lines("Key:", "ABCDE", "enter key", true, 30, 2);
        let w_inside: usize = l_inside[1].spans.iter().map(|s| s.content.chars().count()).sum();
        assert_eq!(w_inside, w_5char, "Input width must remain constant while navigating inside text");
        assert!(l_inside[1].spans.iter().any(|s| s.content == "C"), "Character under cursor must be rendered");
    }

    #[test]
    fn test_text_input_cursor_navigation_left_right() {
        let mut app = make_test_app();
        app.modal = Modal::NewProfile {
            name: "hello".to_string(),
            pull_from_phase: false,
            active_field: 0,
            error: None,
        };
        app.input_cursor = 5; // at end of "hello"

        // 1. Press Left arrow key twice (moves cursor to index 3: between 'l' and 'o', over second 'l')
        app.handle_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.input_cursor, 4);
        app.handle_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.input_cursor, 3);

        // 2. Insert character 'X' at cursor position 3 -> "helXlo"
        app.handle_key(KeyEvent::from(KeyCode::Char('X')));
        assert_eq!(app.input_cursor, 4);
        match &app.modal {
            Modal::NewProfile { name, .. } => assert_eq!(name, "helXlo"),
            _ => panic!("Expected NewProfile modal"),
        }

        // 3. Press Left arrow key once (cursor at 3, over 'X') and press Backspace (deletes 'l' at index 2)
        app.handle_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.input_cursor, 3);
        app.handle_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(app.input_cursor, 2);
        match &app.modal {
            Modal::NewProfile { name, .. } => assert_eq!(name, "heXlo"),
            _ => panic!("Expected NewProfile modal"),
        }

        // 4. Press Delete key (deletes 'X' at cursor 2) -> "helo"
        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert_eq!(app.input_cursor, 2);
        match &app.modal {
            Modal::NewProfile { name, .. } => assert_eq!(name, "helo"),
            _ => panic!("Expected NewProfile modal"),
        }

        // 5. Press Right arrow key until end of string (index 4)
        app.handle_key(KeyEvent::from(KeyCode::Right));
        assert_eq!(app.input_cursor, 3);
        app.handle_key(KeyEvent::from(KeyCode::Right));
        assert_eq!(app.input_cursor, 4);
        // Pressing Right at the end must not go beyond string length
        app.handle_key(KeyEvent::from(KeyCode::Right));
        assert_eq!(app.input_cursor, 4);
    }

    #[test]
    fn test_new_profile_vertical_radios_and_no_source_note() {
        let mut app = make_test_app();
        app.modal = Modal::NewProfile {
            name: String::new(),
            pull_from_phase: false,
            active_field: 1,
            error: None,
        };

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // 1. Radio options are rendered vertically (with (●) / (○))
        assert!(content.contains("(●) Custom Environment"));
        assert!(content.contains("(○) Phase.dev Synchronization"));

        // Verify they are on different vertical rows
        let custom_row = (0..buffer.area.height).find(|&y| {
            let row_str: String = (0..buffer.area.width).map(|x| buffer.get(x, y).symbol()).collect();
            row_str.contains("(●) Custom")
        }).expect("Custom option row");

        let phase_row = (0..buffer.area.height).find(|&y| {
            let row_str: String = (0..buffer.area.width).map(|x| buffer.get(x, y).symbol()).collect();
            row_str.contains("(○) Phase.dev")
        }).expect("Phase option row");

        assert_ne!(custom_row, phase_row, "Radio options must be on separate lines, not inline");
        assert_eq!(phase_row, custom_row + 1, "Radio options must be stacked vertically consecutive lines");

        // 2. Note stating that each profile uses exclusively one source must NOT be present
        assert!(!content.contains("exclusively one source"));
        assert!(!content.contains("sources cannot be mixed"));
    }

    #[test]
    fn test_effective_pane_source_column_not_truncated() {
        let mut app = make_test_app();
        app.data.profiles.push(Profile::new_phase(
            "staging".to_string(),
            PhaseBinding {
                app_id: "app-1".to_string(),
                app_name: "my-app".to_string(),
                env_id: "env-1".to_string(),
                env_name: "production".to_string(),
            },
            vec![("DATABASE_URL".to_string(), "postgres://...".to_string())],
        ));
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("PROFILE"));
        assert!(content.contains("Phase (my-app/production)"));
    }
}
