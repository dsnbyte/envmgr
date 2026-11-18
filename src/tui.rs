use crate::model::{
    is_valid_env_key, normalize_secret_path, AppSettings, AppStateData, Collection, EnvVar,
    HostMode, PhaseAuthMethod, PhaseBinding, PhaseConfig, PhaseVarRef, PHASE_CLOUD_HOST,
};
use crate::phase::{
    detect_phase_cli_detailed, fetch_apps_and_envs, fetch_detailed_secrets_for_env,
    fetch_secrets_for_env, sync_phase_collections, try_detect_local_phase_cli_host, PhaseAppInfo,
    PhaseCliStatus, PhaseSecretItem,
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
        Block, BorderType, Borders, Cell, Clear, List, ListItem, ListState, Padding, Paragraph,
        Row, Table, TableState, Wrap,
    },
    Frame,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use std::io::Write;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Collections,
    Vars,
    Effective,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Preferences,
    PhaseAuth,
}

#[derive(Debug, Clone)]
pub enum Modal {
    None,
    NewCollection {
        name: String,
        pull_from_phase: bool,
        active_field: usize, // 0 = name, 1 = data source
        error: Option<String>,
    },
    PhasePicker {
        target_collection_idx: Option<usize>,
        new_collection_name: Option<String>,
        apps: Vec<PhaseAppInfo>,
        selected_app: usize,
        selected_env: usize,
        picker_step: usize, // 0 = app, 1 = env, 2 = path scope
        export_all_paths: bool,
        error: Option<String>,
    },
    VarEditor {
        is_edit: bool,
        original_index: Option<usize>,
        var_key: String,
        is_phase_source: bool,
        phase_ref: Option<PhaseVarRef>,
        var_value: String,
        var_comment: String,
        active_field: usize, // 0 = key, 1 = source, 2 = value/ref, 3 = comment
        error: Option<String>,
    },
    PhaseVarPicker {
        is_edit: bool,
        original_index: Option<usize>,
        var_key: String,
        prev_value: String,
        prev_comment: String,
        existing_phase_ref: Option<PhaseVarRef>,
        apps: Vec<PhaseAppInfo>,
        selected_app: usize,
        selected_env: usize,
        loaded_env: Option<(String, String)>,
        env_secrets: Vec<PhaseSecretItem>,
        folders: Vec<String>,
        selected_folder: usize,
        selected_secret: usize,
        picker_step: usize, // 0 = app, 1 = env, 2 = folder, 3 = secret
        error: Option<String>,
    },
    ConfirmDeleteCollection {
        collection_idx: usize,
        collection_name: String,
    },
    ConfirmDeleteVar {
        var_idx: usize,
        var_key: String,
    },
    EditCollection {
        collection_idx: usize,
        name: String,
        error: Option<String>,
    },
    VarDetail {
        key: String,
        value: String,
        source: String,
        comment: String,
    },
    Settings {
        tab: SettingsTab,
        draft: AppSettings,
        active_field: usize,
        auth_method: PhaseAuthMethod,
        host_mode: HostMode,
        custom_url: String,
        pat_token: String,
        cli_status: PhaseCliStatus,
        pending_new_collection: Option<String>,
        error: Option<String>,
    },
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextAction {
    ToggleCollection,
    ToggleVar,
    Edit,
    Delete,
    MoveUp,
    MoveDown,
    NewCollection,
    AddVar,
    PhaseSync,
    PhaseRebind,
    ToggleMask,
    ReloadShell,
    CopyKey,
    CopyValue,
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
    pub items: Vec<ContextMenuItem>,
    pub selected: usize,
}

impl ContextMenu {
    pub fn rect(&self, area: Rect) -> Rect {
        let min_gap = 4;
        let content_width = self
            .items
            .iter()
            .map(|item| {
                2 + item.label.chars().count() + min_gap + item.shortcut.chars().count() + 2 + 1
            })
            .max()
            .unwrap_or(18) as u16;
        let width = (content_width + 2).min(area.width.saturating_sub(2));
        let height = (self.items.len() as u16 + 2).min(area.height.saturating_sub(1));
        let x = self.x.min(area.width.saturating_sub(width));
        let y = self.y.min(area.height.saturating_sub(height));
        Rect::new(x, y, width, height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSyncTarget {
    Collection(usize),
    All,
}

pub struct App {
    pub data: AppStateData,
    pub focus: FocusPane,
    pub selected_collection: usize,
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
    pub sync_start_time: Option<Instant>,
    pub input_cursor: usize,
    pub last_var_click: Option<(FocusPane, usize, Instant)>,
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

        let show_values = false;

        let mut app = Self {
            data,
            focus: FocusPane::Collections,
            selected_collection: 0,
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
            sync_start_time: None,
            input_cursor: 0,
            last_var_click: None,
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

    pub fn sync_to_system_silent(&mut self) {
        if cfg!(test) {
            return;
        }
        match apply_state_to_system(&self.data) {
            Ok(_) => {
                let effective = self.data.compute_effective_vars();
                let _ = reload_shell_environment(&effective);
            }
            Err(e) => {
                self.set_error(format!("Failed to sync state.enc: {}", e));
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

    pub fn current_collection(&self) -> Option<&Collection> {
        self.data.collections.get(self.selected_collection)
    }

    pub fn current_collection_mut(&mut self) -> Option<&mut Collection> {
        self.data.collections.get_mut(self.selected_collection)
    }

    pub fn current_vars(&self) -> &[EnvVar] {
        if let Some(coll) = self.current_collection() {
            &coll.vars
        } else {
            &[]
        }
    }

    pub fn current_target_title(&self) -> String {
        if let Some(coll) = self.current_collection() {
            let state_str = if coll.enabled { "ON" } else { "OFF" };
            let phase_str = match &coll.phase_binding {
                Some(b) => format!(" | Phase: {}/{}", b.app_name, b.env_name),
                None => String::new(),
            };
            format!("Collection: {} [{}]{}", coll.name, state_str, phase_str)
        } else {
            "No Collection Selected".to_string()
        }
    }

    pub fn clamp_selections(&mut self) {
        if self.data.collections.is_empty() {
            self.selected_collection = 0;
        } else if self.selected_collection >= self.data.collections.len() {
            self.selected_collection = self.data.collections.len() - 1;
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

    pub fn open_settings_modal(&mut self) {
        self.open_settings_modal_with_tab(SettingsTab::Preferences, None, None);
    }

    pub fn open_phase_connect_modal(
        &mut self,
        pending_new_collection: Option<String>,
        error: Option<String>,
    ) {
        self.open_settings_modal_with_tab(
            SettingsTab::PhaseAuth,
            pending_new_collection,
            error,
        );
    }

    pub fn open_settings_modal_with_tab(
        &mut self,
        tab: SettingsTab,
        pending_new_collection: Option<String>,
        error: Option<String>,
    ) {
        let cli_status = detect_phase_cli_detailed();
        let auth_method = if self.data.phase.pat_token.trim().is_empty() && cli_status.installed {
            PhaseAuthMethod::Cli
        } else {
            self.data.phase.auth_method
        };
        self.input_cursor = 0;
        self.modal = Modal::Settings {
            tab,
            draft: self.data.settings.clone(),
            active_field: 0,
            auth_method,
            host_mode: self.data.phase.host_mode,
            custom_url: self.data.phase.custom_url.clone(),
            pat_token: self.data.phase.pat_token.clone(),
            cli_status,
            pending_new_collection,
            error,
        };
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') => {
                    self.should_quit = true;
                    return;
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.modal = Modal::NewCollection {
                        name: String::new(),
                        pull_from_phase: false,
                        active_field: 0,
                        error: None,
                    };
                    return;
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.open_add_var_modal();
                    return;
                }
                KeyCode::Char('e') | KeyCode::Char('E') => {
                    self.handle_edit_action();
                    return;
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.reload_shell();
                    return;
                }
                KeyCode::Char('p') | KeyCode::Char('P') => {
                    self.open_settings_modal();
                    return;
                }
                KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Char('m') | KeyCode::Char('M') => {
                    self.toggle_mask_values();
                    return;
                }
                KeyCode::Char('b') | KeyCode::Char('B') => {
                    if key.modifiers.contains(KeyModifiers::SHIFT) || key.code == KeyCode::Char('B') {
                        self.sync_all_phase_collections();
                    } else {
                        self.handle_phase_sync_action(false);
                    }
                    return;
                }
                _ => {}
            }
        }

        if !self.status_message.is_empty() {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.status_message.clear();
                    self.status_message_time = None;
                }
                _ => {}
            }
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
                    FocusPane::Collections => FocusPane::Vars,
                    FocusPane::Vars => FocusPane::Effective,
                    FocusPane::Effective => FocusPane::Collections,
                };
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    FocusPane::Collections => FocusPane::Effective,
                    FocusPane::Vars => FocusPane::Collections,
                    FocusPane::Effective => FocusPane::Vars,
                };
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.focus = FocusPane::Collections;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if self.focus == FocusPane::Collections {
                    self.focus = FocusPane::Vars;
                }
            }
            KeyCode::Delete => {
                self.handle_delete_action();
            }
            _ => match self.focus {
                FocusPane::Collections => self.handle_collections_pane_key(key),
                FocusPane::Vars => self.handle_vars_pane_key(key),
                FocusPane::Effective => self.handle_effective_pane_key(key),
            },
        }
    }

    fn handle_phase_sync_action(&mut self, force_rebind_picker: bool) {
        let Some(coll) = self.current_collection() else {
            return;
        };

        let is_phase_coll = coll.is_phase();
        let has_phase_vars = coll.has_phase_vars();
        if !is_phase_coll && !has_phase_vars {
            return;
        }

        let idx = self.selected_collection;
        if force_rebind_picker {
            if !is_phase_coll {
                return;
            }
            self.open_phase_picker(Some(idx), None);
            return;
        }
        if !self.data.phase.is_configured() {
            self.open_phase_connect_modal(
                None,
                Some("Configure Phase.dev authentication to sync this collection.".to_string()),
            );
            return;
        }
        self.set_info("Phase.dev sync in progress...");
        self.sync_start_time = Some(Instant::now());
        self.pending_phase_sync = Some(PendingSyncTarget::Collection(idx));
    }

    pub fn perform_pending_sync(&mut self) -> bool {
        let Some(target) = self.pending_phase_sync.take() else {
            return false;
        };

        let sync_start = self.sync_start_time.take();

        let result = match target {
            PendingSyncTarget::Collection(idx) => {
                if idx >= self.data.collections.len() {
                    return true;
                }
                let res = sync_phase_collections(&mut self.data, Some(idx));
                (target, res)
            }
            PendingSyncTarget::All => {
                let res = sync_phase_collections(&mut self.data, None);
                (target, res)
            }
        };

        // Ensure the sync status remains visible for at least one second
        if let Some(start) = sync_start {
            let min_duration = Duration::from_secs(1);
            let elapsed = start.elapsed();
            if elapsed < min_duration {
                std::thread::sleep(min_duration - elapsed);
            }
        }

        match result {
            (PendingSyncTarget::Collection(idx), Ok((_, vars_count))) => {
                self.clamp_selections();
                let cname = self.data.collections[idx].name.clone();
                self.sync_to_system(&format!(
                    "Phase.dev sync succeeded for '{}' ({} vars)",
                    cname, vars_count
                ));
            }
            (PendingSyncTarget::Collection(_), Err(e)) => {
                self.set_error(format!("Phase.dev sync failed: {}", e));
            }
            (PendingSyncTarget::All, Ok((_, vars_count))) => {
                let coll_names: Vec<String> = self
                    .data
                    .collections
                    .iter()
                    .filter(|c| c.is_phase() || c.has_phase_vars())
                    .map(|c| c.name.clone())
                    .collect();
                let coll_desc = if coll_names.len() == 1 {
                    format!("'{}'", coll_names[0])
                } else {
                    format!("{} collections", coll_names.len())
                };
                self.clamp_selections();
                self.sync_to_system(&format!(
                    "Phase.dev sync succeeded for {} ({} vars)",
                    coll_desc, vars_count
                ));
            }
            (PendingSyncTarget::All, Err(e)) => {
                self.set_error(format!("Phase.dev sync failed: {}", e));
            }
        }
        true
    }

    fn handle_edit_action(&mut self) {
        match self.focus {
            FocusPane::Collections => {
                self.open_edit_collection();
            }
            FocusPane::Vars => {
                self.open_edit_var();
            }
            FocusPane::Effective => {
                self.open_edit_effective_var();
            }
        }
    }

    fn open_edit_collection(&mut self) {
        if let Some(coll) = self.current_collection() {
            let n = coll.name.clone();
            self.input_cursor = n.chars().count();
            self.modal = Modal::EditCollection {
                collection_idx: self.selected_collection,
                name: n,
                error: None,
            };
        } else {
            self.set_info("No collection selected to edit.");
        }
    }

    fn open_edit_var(&mut self) {
        let Some(coll) = self.current_collection() else {
            self.set_info("No collection selected.");
            return;
        };
        if coll.is_phase() {
            let cname = coll.name.clone();
            self.set_error(format!(
                "Collection '{}' is synced with Phase.dev. Variables cannot be edited manually (press [Ctrl+B] to sync).",
                cname
            ));
            return;
        }
        if let Some(var) = self.current_vars().get(self.selected_var).cloned() {
            let is_phase_source = var.phase_ref.is_some();
            self.input_cursor = if is_phase_source {
                0
            } else {
                var.value.chars().count()
            };
            self.modal = Modal::VarEditor {
                is_edit: true,
                original_index: Some(self.selected_var),
                var_key: var.key,
                is_phase_source,
                phase_ref: var.phase_ref,
                var_value: var.value,
                var_comment: var.comment,
                active_field: 2,
                error: None,
            };
        } else {
            self.set_info("No variable selected to edit.");
        }
    }

    fn open_edit_effective_var(&mut self) {
        let eff = self.data.compute_effective_vars();
        if let Some(ev) = eff.get(self.selected_effective) {
            for (c_idx, coll) in self.data.collections.iter().enumerate() {
                if !coll.enabled {
                    continue;
                }
                if let Some(v_idx) = coll.vars.iter().position(|v| v.enabled && v.key == ev.key) {
                    if coll.is_phase() {
                        let cname = coll.name.clone();
                        let vkey = ev.key.clone();
                        self.set_error(format!(
                            "Variable '{}' belongs to Phase.dev collection '{}' and cannot be edited manually.",
                            vkey, cname
                        ));
                        return;
                    }
                    self.selected_collection = c_idx;
                    self.selected_var = v_idx;
                    self.focus = FocusPane::Vars;
                    let key = coll.vars[v_idx].key.clone();
                    let val = coll.vars[v_idx].value.clone();
                    let comment = coll.vars[v_idx].comment.clone();
                    let phase_ref = coll.vars[v_idx].phase_ref.clone();
                    let is_phase_source = phase_ref.is_some();
                    self.input_cursor = if is_phase_source {
                        0
                    } else {
                        val.chars().count()
                    };
                    self.modal = Modal::VarEditor {
                        is_edit: true,
                        original_index: Some(v_idx),
                        var_key: key,
                        is_phase_source,
                        phase_ref,
                        var_value: val,
                        var_comment: comment,
                        active_field: 2,
                        error: None,
                    };
                    return;
                }
            }
        }
        self.set_info("No effective variable selected to edit.");
    }

    fn open_var_detail(&mut self) {
        let Some(coll) = self.current_collection() else {
            self.set_info("No collection selected.");
            return;
        };
        if let Some(var) = coll.vars.get(self.selected_var) {
            self.modal = Modal::VarDetail {
                key: var.key.clone(),
                value: var.value.clone(),
                source: coll.var_source_label(var),
                comment: var.comment.clone(),
            };
        } else {
            self.set_info("No variable selected.");
        }
    }

    fn open_effective_var_detail(&mut self) {
        let eff = self.data.compute_effective_vars();
        if let Some(ev) = eff.get(self.selected_effective) {
            let comment = self
                .data
                .collections
                .iter()
                .filter(|c| c.enabled)
                .find_map(|c| c.vars.iter().find(|v| v.enabled && v.key == ev.key))
                .map(|v| v.comment.clone())
                .unwrap_or_default();
            self.modal = Modal::VarDetail {
                key: ev.key.clone(),
                value: ev.value.clone(),
                source: ev.source_label.clone(),
                comment,
            };
        } else {
            self.set_info("No effective variable selected.");
        }
    }

    fn register_var_click(&mut self, pane: FocusPane, idx: usize) -> bool {
        let now = Instant::now();
        let is_double = self
            .last_var_click
            .map(|(p, prev_idx, t)| {
                p == pane
                    && prev_idx == idx
                    && now.duration_since(t) <= std::time::Duration::from_millis(500)
            })
            .unwrap_or(false);
        if is_double {
            self.last_var_click = None;
            true
        } else {
            self.last_var_click = Some((pane, idx, now));
            false
        }
    }

    fn handle_delete_action(&mut self) {
        match self.focus {
            FocusPane::Collections => {
                if let Some(coll) = self.current_collection() {
                    self.modal = Modal::ConfirmDeleteCollection {
                        collection_idx: self.selected_collection,
                        collection_name: coll.name.clone(),
                    };
                }
            }
            FocusPane::Vars => {
                let Some(coll) = self.current_collection() else {
                    return;
                };
                if coll.is_phase() {
                    let cname = coll.name.clone();
                    self.set_error(format!(
                        "Collection '{}' is synced with Phase.dev. Manage variables in Phase.dev and press [Ctrl+B] to sync.",
                        cname
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
            for (c_idx, coll) in self.data.collections.iter().enumerate() {
                if !coll.enabled {
                    continue;
                }
                if let Some(v_idx) = coll.vars.iter().position(|v| v.enabled && v.key == ev.key) {
                    if coll.is_phase() {
                        let cname = coll.name.clone();
                        let vkey = ev.key.clone();
                        self.set_error(format!(
                            "Variable '{}' belongs to Phase.dev collection '{}' and cannot be deleted manually.",
                            vkey, cname
                        ));
                        return;
                    }
                    self.selected_collection = c_idx;
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

    fn open_new_collection_modal(&mut self) {
        self.input_cursor = 0;
        self.modal = Modal::NewCollection {
            name: String::new(),
            pull_from_phase: false,
            active_field: 0,
            error: None,
        };
    }

    fn open_add_var_modal(&mut self) {
        let Some(coll) = self.current_collection() else {
            self.set_error("No collection available. Create a collection first with [Ctrl+N].");
            return;
        };
        if coll.is_phase() {
            let cname = coll.name.clone();
            self.set_error(format!(
                "Collection '{}' uses Phase.dev synchronization. Sources cannot be mixed (create a Custom collection with [Ctrl+N]).",
                cname
            ));
        } else {
            self.input_cursor = 0;
            self.modal = Modal::VarEditor {
                is_edit: false,
                original_index: None,
                var_key: String::new(),
                is_phase_source: false,
                phase_ref: None,
                var_value: String::new(),
                var_comment: String::new(),
                active_field: 0,
                error: None,
            };
        }
    }

    fn toggle_current_collection(&mut self) {
        if let Some(coll) = self.current_collection_mut() {
            coll.enabled = !coll.enabled;
            self.clamp_selections();
            self.sync_to_system_silent();
        }
    }

    fn toggle_current_var(&mut self) {
        let var_idx = self.selected_var;
        if let Some(coll) = self.current_collection_mut() {
            if let Some(var) = coll.vars.get_mut(var_idx) {
                var.enabled = !var.enabled;
                self.clamp_selections();
                self.sync_to_system_silent();
            }
        }
    }

    pub fn sync_all_phase_collections(&mut self) {
        let has_any_phase = self
            .data
            .collections
            .iter()
            .any(|c| c.is_phase() || c.has_phase_vars());
        if !has_any_phase {
            self.set_error("No Phase.dev collections found to sync. Press [Ctrl+N] to create one.");
            return;
        }
        if !self.data.phase.is_configured() {
            self.open_phase_connect_modal(
                None,
                Some("Configure Phase.dev authentication to sync Phase collections.".to_string()),
            );
            return;
        }
        self.set_info("Phase.dev sync in progress...");
        self.sync_start_time = Some(Instant::now());
        self.pending_phase_sync = Some(PendingSyncTarget::All);
    }

    fn copy_selected_key(&mut self) {
        match self.focus {
            FocusPane::Vars => {
                if let Some(v) = self.current_vars().get(self.selected_var) {
                    copy_to_clipboard(&v.key);
                }
            }
            FocusPane::Effective => {
                let eff = self.data.compute_effective_vars();
                if let Some(ev) = eff.get(self.selected_effective) {
                    copy_to_clipboard(&ev.key);
                }
            }
            _ => {}
        }
    }

    fn copy_selected_value(&mut self) {
        match self.focus {
            FocusPane::Vars => {
                if let Some(v) = self.current_vars().get(self.selected_var) {
                    copy_to_clipboard(&v.value);
                }
            }
            FocusPane::Effective => {
                let eff = self.data.compute_effective_vars();
                if let Some(ev) = eff.get(self.selected_effective) {
                    copy_to_clipboard(&ev.value);
                }
            }
            _ => {}
        }
    }

    fn toggle_mask_values(&mut self) {
        self.show_values = !self.show_values;
    }

    pub fn execute_context_action(&mut self, action: ContextAction) {
        match action {
            ContextAction::ToggleCollection => self.toggle_current_collection(),
            ContextAction::ToggleVar => self.toggle_current_var(),
            ContextAction::Edit => self.handle_edit_action(),
            ContextAction::Delete => self.handle_delete_action(),
            ContextAction::MoveUp => self.move_selected_collection_up(),
            ContextAction::MoveDown => self.move_selected_collection_down(),
            ContextAction::NewCollection => self.open_new_collection_modal(),
            ContextAction::AddVar => self.open_add_var_modal(),
            ContextAction::PhaseSync => self.handle_phase_sync_action(false),
            ContextAction::PhaseRebind => self.handle_phase_sync_action(true),
            ContextAction::ToggleMask => self.toggle_mask_values(),
            ContextAction::ReloadShell => self.reload_shell(),
            ContextAction::CopyKey => self.copy_selected_key(),
            ContextAction::CopyValue => self.copy_selected_value(),
        }
    }

    pub fn open_context_menu_for_pane(&mut self, pane: FocusPane, x: u16, y: u16) {
        let mut items = Vec::new();
        match pane {
            FocusPane::Collections => {
                if let Some(coll) = self.current_collection() {
                    let toggle_label = if coll.enabled {
                        "Disable Collection"
                    } else {
                        "Enable Collection"
                    };
                    items.push(ContextMenuItem {
                        label: "Edit Collection".to_string(),
                        shortcut: "Ctrl+E",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: toggle_label.to_string(),
                        shortcut: "Space",
                        action: ContextAction::ToggleCollection,
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
                    if coll.is_phase() {
                        items.push(ContextMenuItem {
                            label: "Sync Environment".to_string(),
                            shortcut: "Ctrl+B",
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
                            shortcut: "Ctrl+A",
                            action: ContextAction::AddVar,
                            is_danger: false,
                        });
                        if coll.has_phase_vars() {
                            items.push(ContextMenuItem {
                                label: "Sync Phase Variables".to_string(),
                                shortcut: "Ctrl+B",
                                action: ContextAction::PhaseSync,
                                is_danger: false,
                            });
                        }
                    }
                    items.push(ContextMenuItem {
                        label: "New Collection".to_string(),
                        shortcut: "Ctrl+N",
                        action: ContextAction::NewCollection,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Collection".to_string(),
                        shortcut: "Delete",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                } else {
                    items.push(ContextMenuItem {
                        label: "New Collection".to_string(),
                        shortcut: "Ctrl+N",
                        action: ContextAction::NewCollection,
                        is_danger: false,
                    });
                }
            }
            FocusPane::Vars => {
                let has_vars = !self.current_vars().is_empty();
                let (is_phase, has_phase_vars) = self
                    .current_collection()
                    .map(|p| (p.is_phase(), p.has_phase_vars()))
                    .unwrap_or((false, false));
                if has_vars && !is_phase {
                    items.push(ContextMenuItem {
                        label: "Edit Variable".to_string(),
                        shortcut: "Ctrl+E",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Variable".to_string(),
                        shortcut: "Delete",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                }
                if let Some(var) = self.current_vars().get(self.selected_var) {
                    let toggle_label = if var.enabled {
                        "Disable Variable"
                    } else {
                        "Enable Variable"
                    };
                    items.push(ContextMenuItem {
                        label: toggle_label.to_string(),
                        shortcut: "Space",
                        action: ContextAction::ToggleVar,
                        is_danger: false,
                    });
                }
                if is_phase {
                    items.push(ContextMenuItem {
                        label: "Sync Environment".to_string(),
                        shortcut: "Ctrl+B",
                        action: ContextAction::PhaseSync,
                        is_danger: false,
                    });
                } else {
                    items.push(ContextMenuItem {
                        label: "Add Variable".to_string(),
                        shortcut: "Ctrl+A",
                        action: ContextAction::AddVar,
                        is_danger: false,
                    });
                    if has_phase_vars {
                        items.push(ContextMenuItem {
                            label: "Sync Phase Variables".to_string(),
                            shortcut: "Ctrl+B",
                            action: ContextAction::PhaseSync,
                            is_danger: false,
                        });
                    }
                }
                if has_vars {
                    items.push(ContextMenuItem {
                        label: "Copy Key".to_string(),
                        shortcut: "Y",
                        action: ContextAction::CopyKey,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Copy Value".to_string(),
                        shortcut: "Shift+Y",
                        action: ContextAction::CopyValue,
                        is_danger: false,
                    });
                }
            }
            FocusPane::Effective => {
                let has_vars = !self.data.compute_effective_vars().is_empty();
                if has_vars {
                    items.push(ContextMenuItem {
                        label: "Edit Variable".to_string(),
                        shortcut: "Ctrl+E",
                        action: ContextAction::Edit,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Delete Variable".to_string(),
                        shortcut: "Delete",
                        action: ContextAction::Delete,
                        is_danger: true,
                    });
                    items.push(ContextMenuItem {
                        label: "Copy Key".to_string(),
                        shortcut: "Y",
                        action: ContextAction::CopyKey,
                        is_danger: false,
                    });
                    items.push(ContextMenuItem {
                        label: "Copy Value".to_string(),
                        shortcut: "Shift+Y",
                        action: ContextAction::CopyValue,
                        is_danger: false,
                    });
                }
                items.push(ContextMenuItem {
                    label: "Reload Shell Env".to_string(),
                    shortcut: "Ctrl+S",
                    action: ContextAction::ReloadShell,
                    is_danger: false,
                });
            }
        };

        if !items.is_empty() {
            self.context_menu = Some(ContextMenu {
                x,
                y,
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
            KeyCode::Delete => {
                self.execute_context_action(ContextAction::Delete);
            }
            KeyCode::Char(' ') => match self.focus {
                FocusPane::Vars => self.execute_context_action(ContextAction::ToggleVar),
                _ => self.execute_context_action(ContextAction::ToggleCollection),
            },
            KeyCode::Char('u') => self.execute_context_action(ContextAction::MoveUp),
            KeyCode::Char('d') => self.execute_context_action(ContextAction::MoveDown),
            KeyCode::Char('P') => self.execute_context_action(ContextAction::PhaseRebind),
            KeyCode::Char('y') | KeyCode::Char('c') => {
                self.execute_context_action(ContextAction::CopyKey);
            }
            KeyCode::Char('Y') | KeyCode::Char('C') => {
                self.execute_context_action(ContextAction::CopyValue);
            }
            _ => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('n') | KeyCode::Char('N') => {
                            self.execute_context_action(ContextAction::NewCollection);
                            return;
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            self.execute_context_action(ContextAction::AddVar);
                            return;
                        }
                        KeyCode::Char('e') | KeyCode::Char('E') => {
                            self.execute_context_action(ContextAction::Edit);
                            return;
                        }
                        KeyCode::Char('b') | KeyCode::Char('B') => {
                            self.execute_context_action(ContextAction::PhaseSync);
                            return;
                        }
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            self.execute_context_action(ContextAction::ReloadShell);
                            return;
                        }
                        KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Char('m') | KeyCode::Char('M') => {
                            self.execute_context_action(ContextAction::ToggleMask);
                            return;
                        }
                        _ => {}
                    }
                }
                self.context_menu = Some(menu);
            }
        }
    }

    fn handle_collections_pane_key(&mut self, key: KeyEvent) {
        let total_items = self.data.collections.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_collection > 0 {
                    self.selected_collection -= 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_collection + 1 < total_items {
                    self.selected_collection += 1;
                    self.selected_var = 0;
                }
            }
            KeyCode::Char('u') => {
                self.move_selected_collection_up();
            }
            KeyCode::Char('d') => {
                self.move_selected_collection_down();
            }
            KeyCode::Char(' ') => {
                self.toggle_current_collection();
            }
            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.open_edit_collection();
            }
            _ => {}
        }
    }

    fn move_selected_collection_up(&mut self) {
        if self.selected_collection == 0 {
            return;
        }
        self.data
            .collections
            .swap(self.selected_collection, self.selected_collection - 1);
        self.selected_collection -= 1;
        self.sync_to_system_silent();
    }

    fn move_selected_collection_down(&mut self) {
        if self.data.collections.is_empty() || self.selected_collection + 1 >= self.data.collections.len() {
            return;
        }
        self.data
            .collections
            .swap(self.selected_collection, self.selected_collection + 1);
        self.selected_collection += 1;
        self.sync_to_system_silent();
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
            KeyCode::Char(' ') => {
                self.toggle_current_var();
            }
            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.open_var_detail();
            }
            KeyCode::Char('y') => {
                self.copy_selected_key();
            }
            KeyCode::Char('Y') => {
                self.copy_selected_value();
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
            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.open_effective_var_detail();
            }
            KeyCode::Char('y') => {
                self.copy_selected_key();
            }
            KeyCode::Char('Y') => {
                self.copy_selected_value();
            }
            _ => {}
        }
    }

    fn open_phase_picker(
        &mut self,
        target_collection_idx: Option<usize>,
        new_collection_name: Option<String>,
    ) {
        if let Some(idx) = target_collection_idx {
            if let Some(coll) = self.data.collections.get(idx) {
                if coll.is_custom() {
                    let cname = coll.name.clone();
                    self.set_error(format!(
                        "Collection '{}' is a Custom collection; sources cannot be mixed.",
                        cname
                    ));
                    return;
                }
            }
        }

        if !self.data.phase.is_configured() {
            self.open_phase_connect_modal(
                new_collection_name,
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
                    target_collection_idx,
                    new_collection_name,
                    apps,
                    selected_app: 0,
                    selected_env: 0,
                    picker_step: 0,
                    export_all_paths: true,
                    error: None,
                };
            }
            Err(e) => {
                self.set_error(format!("Phase.dev error: {}", e));
                self.open_phase_connect_modal(new_collection_name, Some(e));
            }
        }
    }

    fn open_phase_var_picker_from_editor(
        &mut self,
        is_edit: bool,
        original_index: Option<usize>,
        var_key: String,
        prev_value: String,
        prev_comment: String,
        existing_phase_ref: Option<PhaseVarRef>,
        active_field: usize,
    ) {
        if !self.data.phase.is_configured() {
            self.modal = Modal::VarEditor {
                is_edit,
                original_index,
                var_key,
                is_phase_source: true,
                phase_ref: existing_phase_ref,
                var_value: prev_value,
                var_comment: prev_comment,
                active_field,
                error: Some(
                    "Phase.dev authentication is not configured. Configure it in Settings [Ctrl+P]."
                        .to_string(),
                ),
            };
            return;
        }

        match fetch_apps_and_envs(&self.data.phase) {
            Ok(mut apps) => {
                if apps.is_empty() {
                    self.modal = Modal::VarEditor {
                        is_edit,
                        original_index,
                        var_key,
                        is_phase_source: true,
                        phase_ref: existing_phase_ref,
                        var_value: prev_value,
                        var_comment: prev_comment,
                        active_field,
                        error: Some("Connected to Phase.dev, but no Apps were found.".to_string()),
                    };
                    return;
                }
                self.cached_apps = apps.clone();
                let mut selected_app = 0;
                let mut selected_env = 0;
                if let Some(pref) = &existing_phase_ref {
                    if let Some(app_idx) = apps
                        .iter()
                        .position(|a| a.id == pref.app_id || a.name == pref.app_name)
                    {
                        selected_app = app_idx;
                        if let Some(env_idx) = apps[app_idx]
                            .environments
                            .iter()
                            .position(|e| e.id == pref.env_id || e.name == pref.env_name)
                        {
                            selected_env = env_idx;
                        }
                    }
                }
                let mut loaded_env = None;
                let mut env_secrets = Vec::new();
                let mut folders = Vec::new();
                let mut selected_folder = 0;
                let mut selected_secret = 0;
                let mut error = None;
                if existing_phase_ref.is_some() {
                    ensure_phase_var_picker_env_loaded(
                        &self.data.phase,
                        &mut apps,
                        selected_app,
                        selected_env,
                        existing_phase_ref.as_ref(),
                        &mut loaded_env,
                        &mut env_secrets,
                        &mut folders,
                        &mut selected_folder,
                        &mut selected_secret,
                        &mut error,
                    );
                }
                self.modal = Modal::PhaseVarPicker {
                    is_edit,
                    original_index,
                    var_key,
                    prev_value,
                    prev_comment,
                    existing_phase_ref,
                    apps,
                    selected_app,
                    selected_env,
                    loaded_env,
                    env_secrets,
                    folders,
                    selected_folder,
                    selected_secret,
                    picker_step: 0,
                    error,
                };
            }
            Err(e) => {
                self.modal = Modal::VarEditor {
                    is_edit,
                    original_index,
                    var_key,
                    is_phase_source: true,
                    phase_ref: existing_phase_ref,
                    var_value: prev_value,
                    var_comment: prev_comment,
                    active_field,
                    error: Some(format!("Phase.dev error: {}", e)),
                };
            }
        }
    }

    fn insert_new_collection(&mut self, collection: Collection) {
        if self.data.settings.insert_new_collection_at_top {
            self.data.collections.insert(0, collection);
            self.selected_collection = 0;
        } else {
            self.data.collections.push(collection);
            self.selected_collection = self.data.collections.len().saturating_sub(1);
        }
        self.selected_var = 0;
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => {}

            Modal::NewCollection {
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
                            error = Some("Collection name cannot be empty.".to_string());
                        } else if self
                            .data
                            .collections
                            .iter()
                            .any(|c| c.name.eq_ignore_ascii_case(&trimmed))
                        {
                            error = Some(format!("Collection '{}' already exists.", trimmed));
                        } else if pull_from_phase {
                            self.open_phase_picker(None, Some(trimmed));
                            return;
                        } else {
                            self.insert_new_collection(Collection::new_custom(trimmed.clone()));
                            self.sync_to_system(&format!(
                                "Created custom collection '{}'",
                                trimmed
                            ));
                            return;
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::NewCollection {
                    name,
                    pull_from_phase,
                    active_field,
                    error,
                };
            }

            Modal::PhasePicker {
                target_collection_idx,
                new_collection_name,
                apps,
                mut selected_app,
                mut selected_env,
                mut picker_step,
                mut export_all_paths,
                mut error,
            } => {
                let env_count = apps
                    .get(selected_app)
                    .map(|a| a.environments.len())
                    .unwrap_or(0);

                match key.code {
                    KeyCode::Esc => {
                        if picker_step > 0 {
                            picker_step -= 1;
                            error = None;
                        } else {
                            return;
                        }
                    }
                    KeyCode::BackTab => {
                        if picker_step > 0 {
                            picker_step -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Left => {
                        if picker_step == 2 {
                            export_all_paths = !export_all_paths;
                        } else if picker_step == 1 {
                            picker_step = 0;
                            error = None;
                        }
                    }
                    KeyCode::Right => {
                        if picker_step == 2 {
                            export_all_paths = !export_all_paths;
                        } else if picker_step == 0 {
                            if env_count > 0 {
                                picker_step = 1;
                                selected_env = 0;
                                error = None;
                            } else {
                                error = Some("Selected App has no environments.".to_string());
                            }
                        } else if picker_step == 1 {
                            picker_step = 2;
                            error = None;
                        }
                    }
                    KeyCode::Tab => {
                        if picker_step == 0 {
                            if env_count > 0 {
                                picker_step = 1;
                                selected_env = 0;
                                error = None;
                            } else {
                                error = Some("Selected App has no environments.".to_string());
                            }
                        } else if picker_step == 1 {
                            picker_step = 2;
                            error = None;
                        } else {
                            picker_step = 0;
                            error = None;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if picker_step == 0 {
                            if selected_app > 0 {
                                selected_app -= 1;
                                selected_env = 0;
                            }
                        } else if picker_step == 1 {
                            if selected_env > 0 {
                                selected_env -= 1;
                            }
                        } else if picker_step == 2 {
                            export_all_paths = !export_all_paths;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if picker_step == 0 {
                            if selected_app + 1 < apps.len() {
                                selected_app += 1;
                                selected_env = 0;
                            }
                        } else if picker_step == 1 {
                            if selected_env + 1 < env_count {
                                selected_env += 1;
                            }
                        } else if picker_step == 2 {
                            export_all_paths = !export_all_paths;
                        }
                    }
                    KeyCode::Char(' ') => {
                        if picker_step == 2 {
                            export_all_paths = !export_all_paths;
                        }
                    }
                    KeyCode::Enter => {
                        if picker_step == 0 {
                            if env_count == 0 {
                                error = Some("Selected App has no environments.".to_string());
                            } else {
                                picker_step = 1;
                                selected_env = 0;
                                error = None;
                            }
                        } else if picker_step == 1 {
                            picker_step = 2;
                            error = None;
                        } else if let Some(app) = apps.get(selected_app) {
                            if let Some(env) = app.environments.get(selected_env) {
                                match fetch_secrets_for_env(
                                    &self.data.phase,
                                    &app.id,
                                    &env.id,
                                    Some(&env.name),
                                    export_all_paths,
                                ) {
                                    Ok(fetched_pairs) => {
                                        let fetched_len = fetched_pairs.len();
                                        let binding = PhaseBinding {
                                            app_id: app.id.clone(),
                                            app_name: app.name.clone(),
                                            env_id: env.id.clone(),
                                            env_name: env.name.clone(),
                                            export_all_paths,
                                        };
                                        self.data.last_phase_sync_epoch =
                                            AppStateData::current_epoch_secs();

                                        if let Some(coll_name) = new_collection_name {
                                            let new_coll = Collection::new_phase(
                                                coll_name.clone(),
                                                binding,
                                                fetched_pairs,
                                            );
                                            self.insert_new_collection(new_coll);
                                            let path_desc = if export_all_paths { "all paths" } else { "root only" };
                                            self.sync_to_system(&format!(
                                                "Created Phase.dev collection '{}' with {} var(s) ({}/{}, {})",
                                                coll_name, fetched_len, app.name, env.name, path_desc
                                            ));
                                        } else if let Some(idx) = target_collection_idx {
                                            if let Some(coll) = self.data.collections.get_mut(idx) {
                                                coll.set_phase_vars(binding, fetched_pairs);
                                                let cname = coll.name.clone();
                                                let path_desc = if export_all_paths { "all paths" } else { "root only" };
                                                self.sync_to_system(&format!(
                                                    "Synced {} var(s) from Phase ({}/{}, {}) into '{}'",
                                                    fetched_len, app.name, env.name, path_desc, cname
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
                    target_collection_idx,
                    new_collection_name,
                    apps,
                    selected_app,
                    selected_env,
                    picker_step,
                    export_all_paths,
                    error,
                };
            }

            Modal::VarEditor {
                is_edit,
                original_index,
                mut var_key,
                mut is_phase_source,
                phase_ref,
                mut var_value,
                mut var_comment,
                mut active_field,
                mut error,
            } => {
                let field_count = if is_phase_source { 3 } else { 4 };
                match key.code {
                    KeyCode::Esc => {
                        return;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        active_field = (active_field + 1) % field_count;
                        self.input_cursor = match active_field {
                            0 => var_key.chars().count(),
                            2 if !is_phase_source => var_value.chars().count(),
                            3 if !is_phase_source => var_comment.chars().count(),
                            _ => 0,
                        };
                        error = None;
                    }
                    KeyCode::Up | KeyCode::BackTab => {
                        active_field = if active_field == 0 {
                            field_count - 1
                        } else {
                            active_field - 1
                        };
                        self.input_cursor = match active_field {
                            0 => var_key.chars().count(),
                            2 if !is_phase_source => var_value.chars().count(),
                            3 if !is_phase_source => var_comment.chars().count(),
                            _ => 0,
                        };
                        error = None;
                    }
                    KeyCode::Left => {
                        if active_field == 1 {
                            is_phase_source = !is_phase_source;
                        } else if active_field == 0
                            || (!is_phase_source && (active_field == 2 || active_field == 3))
                        {
                            self.input_cursor = self.input_cursor.saturating_sub(1);
                        }
                        error = None;
                    }
                    KeyCode::Right => {
                        if active_field == 1 {
                            is_phase_source = !is_phase_source;
                        } else if active_field == 0
                            || (!is_phase_source && (active_field == 2 || active_field == 3))
                        {
                            let len = match active_field {
                                0 => var_key.chars().count(),
                                2 => var_value.chars().count(),
                                _ => var_comment.chars().count(),
                            };
                            self.input_cursor = (self.input_cursor + 1).min(len);
                        }
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
                        let len = match active_field {
                            0 => var_key.chars().count(),
                            2 if !is_phase_source => var_value.chars().count(),
                            3 if !is_phase_source => var_comment.chars().count(),
                            _ => 0,
                        };
                        self.input_cursor = len;
                    }
                    KeyCode::Char(' ') if active_field == 1 => {
                        is_phase_source = !is_phase_source;
                        error = None;
                    }
                    KeyCode::Char(' ') if active_field == 2 && is_phase_source => {
                        self.open_phase_var_picker_from_editor(
                            is_edit,
                            original_index,
                            var_key,
                            var_value,
                            var_comment,
                            phase_ref,
                            active_field,
                        );
                        return;
                    }
                    KeyCode::Char('p')
                        if is_phase_source && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        self.open_phase_var_picker_from_editor(
                            is_edit,
                            original_index,
                            var_key,
                            var_value,
                            var_comment,
                            phase_ref,
                            active_field,
                        );
                        return;
                    }
                    KeyCode::Backspace => {
                        let editable = active_field == 0
                            || (!is_phase_source && (active_field == 2 || active_field == 3));
                        if editable && self.input_cursor > 0 {
                            match active_field {
                                0 => remove_char_at(&mut var_key, self.input_cursor - 1),
                                2 => remove_char_at(&mut var_value, self.input_cursor - 1),
                                3 => remove_char_at(&mut var_comment, self.input_cursor - 1),
                                _ => false,
                            };
                            self.input_cursor -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Delete => {
                        let editable = active_field == 0
                            || (!is_phase_source && (active_field == 2 || active_field == 3));
                        if editable {
                            match active_field {
                                0 => remove_char_at(&mut var_key, self.input_cursor),
                                2 => remove_char_at(&mut var_value, self.input_cursor),
                                3 => remove_char_at(&mut var_comment, self.input_cursor),
                                _ => false,
                            };
                            error = None;
                        }
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let editable = active_field == 0
                            || (!is_phase_source && (active_field == 2 || active_field == 3));
                        if editable {
                            match active_field {
                                0 => var_key.clear(),
                                2 => var_value.clear(),
                                3 => var_comment.clear(),
                                _ => {}
                            };
                            self.input_cursor = 0;
                            error = None;
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if active_field == 0 {
                            insert_char_at(&mut var_key, self.input_cursor, c);
                            self.input_cursor += 1;
                            error = None;
                        } else if !is_phase_source && active_field == 2 {
                            insert_char_at(&mut var_value, self.input_cursor, c);
                            self.input_cursor += 1;
                            error = None;
                        } else if !is_phase_source && active_field == 3 {
                            if var_comment.chars().count() < 100 {
                                insert_char_at(&mut var_comment, self.input_cursor, c);
                                self.input_cursor += 1;
                            }
                            error = None;
                        }
                    }
                    KeyCode::Enter => {
                        if active_field == 2 && is_phase_source && phase_ref.is_none() {
                            self.open_phase_var_picker_from_editor(
                                is_edit,
                                original_index,
                                var_key,
                                var_value,
                                var_comment,
                                phase_ref,
                                active_field,
                            );
                            return;
                        }
                        let k = var_key.trim().to_string();
                        if !is_valid_env_key(&k) {
                            error = Some(
                                "Invalid variable name. Use letters, digits, '_' (cannot start with digit)."
                                    .to_string(),
                            );
                        } else if is_phase_source && phase_ref.is_none() {
                            error = Some(
                                "Please select a Phase.dev variable first (press Space on field 3)."
                                    .to_string(),
                            );
                        } else if let Some(coll) = self.current_collection_mut() {
                            if coll.is_phase() {
                                error = Some(
                                    "Cannot modify variables manually in a Phase.dev collection."
                                        .to_string(),
                                );
                            } else {
                                let final_ref = if is_phase_source {
                                    phase_ref.clone()
                                } else {
                                    None
                                };
                                let final_comment: String = if is_phase_source {
                                    var_comment.chars().take(100).collect()
                                } else {
                                    var_comment.trim().chars().take(100).collect()
                                };
                                if is_edit {
                                    if let Some(idx) = original_index {
                                        if let Some(v) = coll.vars.get_mut(idx) {
                                            v.key = k.clone();
                                            v.set_value(var_value.clone());
                                            v.comment = final_comment;
                                            v.phase_ref = final_ref.clone();
                                        }
                                    }
                                } else {
                                    let _ = coll.upsert_custom_var_with_phase_ref(
                                        k.clone(),
                                        var_value.clone(),
                                        final_comment,
                                        final_ref.clone(),
                                    );
                                }
                                if final_ref.is_some() {
                                    coll.last_sync_epoch = Some(AppStateData::current_epoch_secs());
                                }
                                self.clamp_selections();
                                self.sync_to_system_silent();
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
                    is_phase_source,
                    phase_ref,
                    var_value,
                    var_comment,
                    active_field,
                    error,
                };
            }

            Modal::PhaseVarPicker {
                is_edit,
                original_index,
                mut var_key,
                prev_value,
                prev_comment,
                existing_phase_ref,
                mut apps,
                mut selected_app,
                mut selected_env,
                mut loaded_env,
                mut env_secrets,
                mut folders,
                mut selected_folder,
                mut selected_secret,
                mut picker_step,
                mut error,
            } => {
                let env_count = apps
                    .get(selected_app)
                    .map(|a| a.environments.len())
                    .unwrap_or(0);

                match key.code {
                    KeyCode::Esc => {
                        if picker_step > 0 {
                            picker_step -= 1;
                            error = None;
                        } else {
                            self.modal = Modal::VarEditor {
                                is_edit,
                                original_index,
                                var_key,
                                is_phase_source: true,
                                phase_ref: existing_phase_ref,
                                var_value: prev_value,
                                var_comment: prev_comment,
                                active_field: 2,
                                error: None,
                            };
                            return;
                        }
                    }
                    KeyCode::BackTab => {
                        if picker_step > 0 {
                            picker_step -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Left => {
                        if picker_step > 0 {
                            picker_step -= 1;
                            error = None;
                        }
                    }
                    KeyCode::Right | KeyCode::Tab => {
                        let next_step = if key.code == KeyCode::Tab {
                            (picker_step + 1) % 4
                        } else {
                            (picker_step + 1).min(3)
                        };
                        if picker_step == 0 && env_count == 0 {
                            error = Some("Selected App has no environments.".to_string());
                        } else if next_step == 1 {
                            picker_step = 1;
                            ensure_phase_var_picker_env_loaded(
                                &self.data.phase,
                                &mut apps,
                                selected_app,
                                selected_env,
                                existing_phase_ref.as_ref(),
                                &mut loaded_env,
                                &mut env_secrets,
                                &mut folders,
                                &mut selected_folder,
                                &mut selected_secret,
                                &mut error,
                            );
                        } else if next_step >= 2 {
                            if ensure_phase_var_picker_env_loaded(
                                &self.data.phase,
                                &mut apps,
                                selected_app,
                                selected_env,
                                existing_phase_ref.as_ref(),
                                &mut loaded_env,
                                &mut env_secrets,
                                &mut folders,
                                &mut selected_folder,
                                &mut selected_secret,
                                &mut error,
                            ) {
                                picker_step = next_step;
                            }
                        } else {
                            picker_step = next_step;
                            error = None;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        error = None;
                        match picker_step {
                            0 => {
                                if selected_app > 0 {
                                    selected_app -= 1;
                                    selected_env = 0;
                                    loaded_env = None;
                                    env_secrets.clear();
                                    folders.clear();
                                    selected_folder = 0;
                                    selected_secret = 0;
                                }
                            }
                            1 => {
                                if selected_env > 0 {
                                    selected_env -= 1;
                                    loaded_env = None;
                                    env_secrets.clear();
                                    folders.clear();
                                    selected_folder = 0;
                                    selected_secret = 0;
                                    ensure_phase_var_picker_env_loaded(
                                        &self.data.phase,
                                        &mut apps,
                                        selected_app,
                                        selected_env,
                                        existing_phase_ref.as_ref(),
                                        &mut loaded_env,
                                        &mut env_secrets,
                                        &mut folders,
                                        &mut selected_folder,
                                        &mut selected_secret,
                                        &mut error,
                                    );
                                }
                            }
                            2 => {
                                if selected_folder > 0 {
                                    selected_folder -= 1;
                                    selected_secret = 0;
                                }
                            }
                            3 => {
                                if selected_secret > 0 {
                                    selected_secret -= 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        error = None;
                        match picker_step {
                            0 => {
                                if selected_app + 1 < apps.len() {
                                    selected_app += 1;
                                    selected_env = 0;
                                    loaded_env = None;
                                    env_secrets.clear();
                                    folders.clear();
                                    selected_folder = 0;
                                    selected_secret = 0;
                                }
                            }
                            1 => {
                                if selected_env + 1 < env_count {
                                    selected_env += 1;
                                    loaded_env = None;
                                    env_secrets.clear();
                                    folders.clear();
                                    selected_folder = 0;
                                    selected_secret = 0;
                                    ensure_phase_var_picker_env_loaded(
                                        &self.data.phase,
                                        &mut apps,
                                        selected_app,
                                        selected_env,
                                        existing_phase_ref.as_ref(),
                                        &mut loaded_env,
                                        &mut env_secrets,
                                        &mut folders,
                                        &mut selected_folder,
                                        &mut selected_secret,
                                        &mut error,
                                    );
                                }
                            }
                            2 => {
                                if selected_folder + 1 < folders.len() {
                                    selected_folder += 1;
                                    selected_secret = 0;
                                }
                            }
                            3 => {
                                let sec_len = phase_var_picker_folder_secrets(
                                    &env_secrets,
                                    &folders,
                                    selected_folder,
                                )
                                .len();
                                if selected_secret + 1 < sec_len {
                                    selected_secret += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Enter => match picker_step {
                        0 => {
                            if env_count == 0 {
                                error = Some("Selected App has no environments.".to_string());
                            } else {
                                picker_step = 1;
                                ensure_phase_var_picker_env_loaded(
                                    &self.data.phase,
                                    &mut apps,
                                    selected_app,
                                    selected_env,
                                    existing_phase_ref.as_ref(),
                                    &mut loaded_env,
                                    &mut env_secrets,
                                    &mut folders,
                                    &mut selected_folder,
                                    &mut selected_secret,
                                    &mut error,
                                );
                            }
                        }
                        1 => {
                            if ensure_phase_var_picker_env_loaded(
                                &self.data.phase,
                                &mut apps,
                                selected_app,
                                selected_env,
                                existing_phase_ref.as_ref(),
                                &mut loaded_env,
                                &mut env_secrets,
                                &mut folders,
                                &mut selected_folder,
                                &mut selected_secret,
                                &mut error,
                            ) {
                                if folders.is_empty() {
                                    error = Some("No variables found in this environment.".to_string());
                                } else {
                                    picker_step = 2;
                                    error = None;
                                }
                            }
                        }
                        2 => {
                            let folder_secrets = phase_var_picker_folder_secrets(
                                &env_secrets,
                                &folders,
                                selected_folder,
                            );
                            if folder_secrets.is_empty() {
                                error = Some("No variables found in this folder.".to_string());
                            } else {
                                if selected_secret >= folder_secrets.len() {
                                    selected_secret = 0;
                                }
                                picker_step = 3;
                                error = None;
                            }
                        }
                        3 => {
                            let folder_secrets = phase_var_picker_folder_secrets(
                                &env_secrets,
                                &folders,
                                selected_folder,
                            );
                            if let (Some(app), Some(env), Some(folder), Some(secret)) = (
                                apps.get(selected_app),
                                apps.get(selected_app)
                                    .and_then(|a| a.environments.get(selected_env)),
                                folders.get(selected_folder),
                                folder_secrets.get(selected_secret),
                            ) {
                                if var_key.trim().is_empty() {
                                    var_key = secret.key.clone();
                                }
                                let pref = PhaseVarRef {
                                    app_id: app.id.clone(),
                                    app_name: app.name.clone(),
                                    env_id: env.id.clone(),
                                    env_name: env.name.clone(),
                                    path: folder.clone(),
                                    secret_key: secret.key.clone(),
                                };
                                self.input_cursor = 0;
                                self.modal = Modal::VarEditor {
                                    is_edit,
                                    original_index,
                                    var_key,
                                    is_phase_source: true,
                                    phase_ref: Some(pref),
                                    var_value: secret.value.clone(),
                                    var_comment: secret.comment.chars().take(100).collect(),
                                    active_field: 2,
                                    error: None,
                                };
                                return;
                            } else {
                                error = Some("Please select a variable.".to_string());
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }

                self.modal = Modal::PhaseVarPicker {
                    is_edit,
                    original_index,
                    var_key,
                    prev_value,
                    prev_comment,
                    existing_phase_ref,
                    apps,
                    selected_app,
                    selected_env,
                    loaded_env,
                    env_secrets,
                    folders,
                    selected_folder,
                    selected_secret,
                    picker_step,
                    error,
                };
            }

            Modal::ConfirmDeleteCollection {
                collection_idx,
                collection_name,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if collection_idx < self.data.collections.len() {
                        self.data.collections.remove(collection_idx);
                        self.clamp_selections();
                        self.sync_to_system(&format!("Deleted collection '{}'", collection_name));
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => {
                    self.modal = Modal::ConfirmDeleteCollection {
                        collection_idx,
                        collection_name,
                    };
                }
            },

            Modal::ConfirmDeleteVar { var_idx, var_key } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if let Some(coll) = self.current_collection_mut() {
                        if coll.is_custom() && var_idx < coll.vars.len() {
                            coll.vars.remove(var_idx);
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

            Modal::EditCollection {
                collection_idx,
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
                        if let Some(coll) = self.data.collections.get(collection_idx) {
                            if coll.is_phase() {
                                self.open_phase_picker(Some(collection_idx), None);
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
                            error = Some("Collection name cannot be empty.".to_string());
                        } else if self
                            .data
                            .collections
                            .iter()
                            .enumerate()
                            .any(|(i, c)| i != collection_idx && c.name.eq_ignore_ascii_case(&trimmed))
                        {
                            error = Some(format!("Collection '{}' already exists.", trimmed));
                        } else {
                            if let Some(coll) = self.data.collections.get_mut(collection_idx) {
                                let old_name = coll.name.clone();
                                coll.name = trimmed.clone();
                                self.sync_to_system(&format!(
                                    "Renamed collection '{}' to '{}'",
                                    old_name, trimmed
                                ));
                            }
                            return;
                        }
                    }
                    _ => {}
                }

                self.modal = Modal::EditCollection {
                    collection_idx,
                    name,
                    error,
                };
            }

            Modal::Settings {
                mut tab,
                mut draft,
                mut active_field,
                mut auth_method,
                mut host_mode,
                mut custom_url,
                mut pat_token,
                mut cli_status,
                pending_new_collection,
                mut error,
            } => {
                match tab {
                    SettingsTab::Preferences => {
                        const PREF_FIELDS: usize = 3;
                        match key.code {
                            KeyCode::Esc => {
                                return;
                            }
                            KeyCode::Char('2') => {
                                tab = SettingsTab::PhaseAuth;
                                active_field = 0;
                                error = None;
                            }
                            KeyCode::Tab => {
                                tab = SettingsTab::PhaseAuth;
                                active_field = 0;
                                error = None;
                            }
                            KeyCode::BackTab => {
                                tab = SettingsTab::PhaseAuth;
                                active_field = 0;
                                error = None;
                            }
                            KeyCode::Down => {
                                active_field = (active_field + 1) % PREF_FIELDS;
                                error = None;
                            }
                            KeyCode::Up => {
                                active_field = (active_field + PREF_FIELDS - 1) % PREF_FIELDS;
                                error = None;
                            }
                            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
                                error = None;
                                match active_field {
                                    0 => {
                                        draft.sync_only_enabled_collections =
                                            !draft.sync_only_enabled_collections;
                                    }
                                    1 => {
                                        draft.insert_new_collection_at_top =
                                            !draft.insert_new_collection_at_top;
                                    }
                                    2 => {
                                        draft.shell_prompt_hook = !draft.shell_prompt_hook;
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Enter => {
                                self.data.settings = draft;
                                self.sync_to_system("Saved application Settings");
                                return;
                            }
                            _ => {}
                        }
                    }
                    SettingsTab::PhaseAuth => {
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
                                return;
                            }
                            KeyCode::Char('1') if active_field < 2 => {
                                tab = SettingsTab::Preferences;
                                active_field = 0;
                                error = None;
                            }
                            KeyCode::Tab => {
                                if active_field + 1 >= max_fields {
                                    tab = SettingsTab::Preferences;
                                    active_field = 0;
                                    error = None;
                                } else {
                                    active_field += 1;
                                    self.input_cursor = if host_mode == HostMode::SelfHosted && active_field == 2 {
                                        custom_url.chars().count()
                                    } else if active_field == pat_field_idx {
                                        pat_token.chars().count()
                                    } else {
                                        0
                                    };
                                }
                            }
                            KeyCode::BackTab => {
                                if active_field == 0 {
                                    tab = SettingsTab::Preferences;
                                    active_field = 2;
                                    error = None;
                                } else {
                                    active_field -= 1;
                                    self.input_cursor = if host_mode == HostMode::SelfHosted && active_field == 2 {
                                        custom_url.chars().count()
                                    } else if active_field == pat_field_idx {
                                        pat_token.chars().count()
                                    } else {
                                        0
                                    };
                                }
                            }
                            KeyCode::Down => {
                                error = None;
                                match active_field {
                                    0 => {
                                        if auth_method == PhaseAuthMethod::Cli {
                                            auth_method = PhaseAuthMethod::Token;
                                        } else {
                                            active_field = 1;
                                        }
                                    }
                                    1 => {
                                        if host_mode == HostMode::Cloud {
                                            host_mode = HostMode::SelfHosted;
                                        } else {
                                            active_field = 2;
                                            self.input_cursor = custom_url.chars().count();
                                        }
                                    }
                                    2 => {
                                        if host_mode == HostMode::SelfHosted {
                                            active_field = 3;
                                            self.input_cursor = pat_token.chars().count();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Up => {
                                error = None;
                                match active_field {
                                    0 => {
                                        if auth_method == PhaseAuthMethod::Token {
                                            auth_method = PhaseAuthMethod::Cli;
                                            cli_status = detect_phase_cli_detailed();
                                        }
                                    }
                                    1 => {
                                        if host_mode == HostMode::SelfHosted {
                                            host_mode = HostMode::Cloud;
                                        } else {
                                            active_field = 0;
                                        }
                                    }
                                    2 => {
                                        active_field = 1;
                                    }
                                    3 => {
                                        active_field = 2;
                                        self.input_cursor = custom_url.chars().count();
                                    }
                                    _ => {}
                                }
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
                            KeyCode::Char(' ') if active_field == 0 => {
                                auth_method = match auth_method {
                                    PhaseAuthMethod::Cli => PhaseAuthMethod::Token,
                                    PhaseAuthMethod::Token => {
                                        cli_status = detect_phase_cli_detailed();
                                        PhaseAuthMethod::Cli
                                    }
                                };
                                active_field = 0;
                                self.input_cursor = 0;
                                error = None;
                            }
                            KeyCode::Char(' ') if auth_method == PhaseAuthMethod::Token && active_field == 1 => {
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
                                                if let Some(coll_name) = pending_new_collection {
                                                    self.modal = Modal::PhasePicker {
                                                        target_collection_idx: None,
                                                        new_collection_name: Some(coll_name),
                                                        apps,
                                                        selected_app: 0,
                                                        selected_env: 0,
                                                        picker_step: 0,
                                                        export_all_paths: true,
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
                                } else if host_mode == HostMode::SelfHosted && custom_url.trim().is_empty() {
                                    error = Some("Self-hosted URL cannot be empty.".to_string());
                                } else if pat_token.trim().is_empty() {
                                    error = Some("Personal Access Token (PAT) cannot be empty.".to_string());
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
                                            if let Some(coll_name) = pending_new_collection {
                                                self.modal = Modal::PhasePicker {
                                                    target_collection_idx: None,
                                                    new_collection_name: Some(coll_name),
                                                    apps,
                                                    selected_app: 0,
                                                    selected_env: 0,
                                                    picker_step: 0,
                                                    export_all_paths: true,
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

                        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
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
                    }
                }

                self.modal = Modal::Settings {
                    tab,
                    draft,
                    active_field,
                    auth_method,
                    host_mode,
                    custom_url,
                    pat_token,
                    cli_status,
                    pending_new_collection,
                    error,
                };
            }

            Modal::VarDetail {
                key: var_key,
                value: var_value,
                source,
                comment,
            } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('c') => {}
                KeyCode::Char('y') | KeyCode::Char('k') => {
                    copy_to_clipboard(&var_key);
                    self.set_info(format!("Copied key '{}' to clipboard", var_key));
                    self.modal = Modal::VarDetail {
                        key: var_key,
                        value: var_value,
                        source,
                        comment,
                    };
                }
                KeyCode::Char('Y') | KeyCode::Char('v') => {
                    copy_to_clipboard(&var_value);
                    self.set_info(format!("Copied value for '{}' to clipboard", var_key));
                    self.modal = Modal::VarDetail {
                        key: var_key,
                        value: var_value,
                        source,
                        comment,
                    };
                }
                _ => {
                    self.modal = Modal::VarDetail {
                        key: var_key,
                        value: var_value,
                        source,
                        comment,
                    };
                }
            },

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
        let (header_rect, collections_rect, vars_rect, effective_rect, status_bar_rect) =
            compute_layout_chunks(frame.area());

        self.draw_header(frame, header_rect);
        self.draw_collections_pane(frame, collections_rect);
        self.draw_vars_pane(frame, vars_rect);
        self.draw_effective_pane(frame, effective_rect);
        self.draw_footer(frame, status_bar_rect);

        if self.context_menu.is_some() {
            self.draw_context_menu(frame, frame.area());
        }

        if !matches!(self.modal, Modal::None) {
            self.draw_modal(frame, frame.area());
        }

        if !self.status_message.is_empty() {
            self.draw_status_popup(frame, frame.area());
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

        if inner.width >= 93 {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(34), Constraint::Length(59)])
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
                Span::styled(" [+Collection] ", btn_style),
                sep.clone(),
                Span::styled(" [+Var] ", btn_style),
                sep.clone(),
                Span::styled(" [Sync All] ", btn_style),
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

    fn draw_collections_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == FocusPane::Collections;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let mut items: Vec<ListItem> = Vec::with_capacity(self.data.collections.len());

        for coll in &self.data.collections {
            let check = if coll.enabled { "[✓] " } else { "[ ] " };
            let check_style = if coll.enabled {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let name_style = if coll.enabled {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let badge = match &coll.phase_binding {
                Some(b) => format!(" [Phase:{}/{}]", b.app_name, b.env_name),
                None => " [Custom]".to_string(),
            };

            let line = Line::from(vec![
                Span::styled(check, check_style),
                Span::styled(&coll.name, name_style),
                Span::styled(
                    badge,
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }

        if items.is_empty() {
            items.push(ListItem::new(Line::from(Span::styled(
                "No collections. Click [+Collection] or press [Ctrl+N] to create one.",
                Style::default().fg(Color::DarkGray),
            ))));
        }

        let title = if area.width >= 34 {
            " Collections (Top Wins Priority) "
        } else {
            " Collections (Top Wins) "
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
        if !self.data.collections.is_empty() {
            state.select(Some(self.selected_collection));
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

        let (key_col_width, _) = right_pane_effective_col_widths(area.width);
        let constraints = [
            Constraint::Length(key_col_width),
            Constraint::Percentage(46),
            Constraint::Percentage(54),
        ];
        let vars_cols = Layout::horizontal(constraints)
            .spacing(1)
            .split(Rect::new(0, 0, area.width.saturating_sub(6), 1));
        let max_val_width = vars_cols[1].width as usize;

        let coll_opt = self.current_collection();
        let coll_enabled = coll_opt.map(|c| c.enabled).unwrap_or(true);
        let vars = self.current_vars();
        let rows: Vec<Row> = vars
            .iter()
            .map(|v| {
                let is_active = coll_enabled && v.enabled;
                let check = if v.enabled { "[✓] " } else { "[ ] " };
                let check_style = if !coll_enabled {
                    Style::default().fg(Color::DarkGray)
                } else if v.enabled {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let text_style = if is_active {
                    Style::default()
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let val_display = truncate_with_ellipsis(
                    v.masked_display(self.show_values),
                    max_val_width,
                );
                let source_label = coll_opt
                    .map(|c| c.var_source_label(v))
                    .unwrap_or_else(|| "Manual".to_string());
                Row::new(vec![
                    Cell::from(Line::from(vec![
                        Span::styled(check, check_style),
                        Span::styled(v.key.clone(), text_style),
                    ])),
                    Cell::from(Span::styled(val_display, text_style)),
                    Cell::from(Span::styled(source_label, text_style)),
                ])
            })
            .collect();

        let header = Row::new(vec!["KEY", "VALUE", "SOURCE"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let title = if let Some(coll) = self.current_collection() {
            let count = vars.len();
            let var_word = if count == 1 { "variable" } else { "variables" };
            if coll.is_phase() || coll.has_phase_vars() {
                let now = AppStateData::current_epoch_secs();
                let sync_epoch = coll
                    .last_sync_epoch
                    .filter(|&e| e > 0)
                    .or_else(|| (self.data.last_phase_sync_epoch > 0).then_some(self.data.last_phase_sync_epoch));
                let compact = area.width < 55;
                let sync_time = crate::model::format_relative_sync_time(sync_epoch, now, compact);
                if area.width >= 55 {
                    format!(
                        " {} {} in {} collection • Last sync: {} ",
                        count, var_word, coll.name, sync_time
                    )
                } else if area.width >= 40 {
                    format!(" {} {} in {} • Last sync: {} ", count, var_word, coll.name, sync_time)
                } else {
                    format!(" {} vars • Sync: {} ", count, sync_time)
                }
            } else {
                format!(" {} {} in {} collection ", count, var_word, coll.name)
            }
        } else {
            " 0 variables in collection ".to_string()
        };

        let table = Table::new(rows, constraints)
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
        let (_, max_val_width) = right_pane_effective_col_widths(area.width);
        let max_val_width = max_val_width as usize;
        let (header, constraints, rows): (Row, Vec<Constraint>, Vec<Row>) = if area.width >= 55 {
            (
                Row::new(vec!["EXPORTED KEY", "EFFECTIVE VALUE", "COLLECTION", "SOURCE"]).style(
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                vec![
                    Constraint::Percentage(22),
                    Constraint::Percentage(34),
                    Constraint::Percentage(12),
                    Constraint::Percentage(32),
                ],
                effective
                    .iter()
                    .map(|ev| {
                        let val_display = truncate_with_ellipsis(
                            ev.masked_display(self.show_values),
                            max_val_width,
                        );
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
                Row::new(vec!["KEY", "VAL", "COLLECTION", "SOURCE"]).style(
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                vec![
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(10),
                    Constraint::Length(6),
                ],
                effective
                    .iter()
                    .map(|ev| {
                        let val_display = truncate_with_ellipsis(
                            ev.masked_display(self.show_values),
                            max_val_width,
                        );
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
            if area.width >= 110 {
                Span::raw(format!("Connected ({}: {})", auth_tag, host))
            } else {
                Span::raw(format!("Connected ({})", auth_tag))
            }
        } else if area.width >= 110 {
            Span::raw("Optional / Offline ([Ctrl+P] Settings)")
        } else {
            Span::raw("Offline ([Ctrl+P] Settings)")
        };

        let spans = vec![
            Span::styled(
                " Phase.dev: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            phase_status,
        ];

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

                let prefix = if is_sel { "▸ " } else { "  " };
                let left_len = 2 + item.label.chars().count();
                let right_len = shortcut_str.chars().count() + 1;

                let pad = inner_width.saturating_sub(left_len + right_len);
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
            .style(Style::default().bg(Color::Rgb(20, 26, 38)));

        frame.render_widget(List::new(items).block(block), popup);
    }

    pub fn status_popup_rect(&self, area: Rect) -> Rect {
        let msg_len = self.status_message.chars().count();
        let w = ((msg_len + 12) as u16).clamp(38, 70).min(area.width.saturating_sub(4));
        let inner_w = w.saturating_sub(4) as usize;
        let text_lines = if inner_w > 0 {
            (msg_len + inner_w - 1) / inner_w
        } else {
            1
        };
        let h = (text_lines as u16 + 5).clamp(7, 12).min(area.height.saturating_sub(2));
        let x = area.x + (area.width.saturating_sub(w)) / 2;
        let y = area.y + (area.height.saturating_sub(h)) / 2;
        Rect::new(x, y, w, h)
    }

    pub fn status_popup_ok_button_rect(&self, area: Rect) -> Rect {
        let popup = self.status_popup_rect(area);
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(block_inner);
        let btn_chunk = chunks[1];
        let btn_len = 6u16; // " [OK] "
        let start_x = btn_chunk.x + (btn_chunk.width.saturating_sub(btn_len)) / 2;
        Rect::new(start_x, btn_chunk.y, btn_len, 1)
    }

    pub fn is_status_ok_button_clicked(&self, area: Rect, col: u16, row: u16) -> bool {
        let btn_rect = self.status_popup_ok_button_rect(area);
        row == btn_rect.y && col >= btn_rect.x.saturating_sub(1) && col <= btn_rect.x + btn_rect.width
    }

    fn draw_status_popup(&self, frame: &mut Frame, area: Rect) {
        if self.status_message.is_empty() {
            return;
        }

        let popup = self.status_popup_rect(area);
        frame.render_widget(Clear, popup);

        let (title, border_color, is_danger) = if self.is_error_status {
            (" Error ", Color::LightRed, true)
        } else if self.status_message.contains("succeeded")
            || self.status_message.contains("Created")
            || self.status_message.contains("Updated")
            || self.status_message.contains("Deleted")
            || self.status_message.contains("Reloaded")
        {
            (" Success ", Color::Green, false)
        } else if self.status_message.contains("in progress") {
            (" Syncing ", Color::Cyan, false)
        } else {
            (" Notice ", Color::Cyan, false)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .style(Style::default().bg(Color::Rgb(20, 26, 38)))
            .padding(Padding::new(1, 1, 1, 0))
            .title(Span::styled(
                title,
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ));

        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(inner);

        let text = Paragraph::new(Line::from(Span::styled(
            &self.status_message,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Center)
        .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(text, chunks[0]);

        let btn_style = if is_danger {
            Style::default()
                .fg(Color::White)
                .bg(Color::Rgb(140, 35, 45))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(border_color)
                .bg(Color::Rgb(25, 38, 58))
                .add_modifier(Modifier::BOLD)
        };

        let btn_line = Line::from(Span::styled(" [OK] ", btn_style));
        frame.render_widget(
            Paragraph::new(btn_line).alignment(Alignment::Center),
            chunks[1],
        );
    }

    fn draw_modal(&self, frame: &mut Frame, area: Rect) {
        match &self.modal {
            Modal::None => {}
            Modal::NewCollection {
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
                    .title(" New Collection ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let mut lines = vec![
                    Line::from(Span::styled(
                        "Create New Environment Collection",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                ];

                lines.extend(modern_input_lines(
                    "1. Collection Name:",
                    name,
                    "e.g. staging, prod, test",
                    *active_field == 0,
                    36,
                    self.input_cursor,
                ));
                lines.push(Line::from(""));
                lines.extend(modern_vertical_radio_options(
                    "2. Collection Data Source:",
                    &[
                        ("custom", "Custom Environment"),
                        ("phase", "Phase.dev Synchronization"),
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
                picker_step,
                export_all_paths,
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
                    .constraints([
                        Constraint::Min(6),
                        Constraint::Length(3),
                        Constraint::Length(1),
                    ])
                    .split(inner);

                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(chunks[0]);

                let app_items: Vec<ListItem> = apps
                    .iter()
                    .map(|a| ListItem::new(a.name.clone()))
                    .collect();

                let app_border = if *picker_step == 0 {
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

                let env_border = if *picker_step == 1 {
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

                let scope_border = if *picker_step == 2 {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let active_pill = Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let inactive_pill = Style::default()
                    .fg(Color::White)
                    .bg(Color::Rgb(35, 45, 60));

                let scope_block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(scope_border)
                    .title(" 3. Choose Path Scope ");

                let scope_lines = vec![
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(
                            if *export_all_paths { " [● All Paths] " } else { " [○ All Paths] " },
                            if *export_all_paths { active_pill } else { inactive_pill },
                        ),
                        Span::raw("   "),
                        Span::styled(
                            if !*export_all_paths { " [● Root (/) Only] " } else { " [○ Root (/) Only] " },
                            if !*export_all_paths { active_pill } else { inactive_pill },
                        ),
                    ]),
                ];
                frame.render_widget(Paragraph::new(scope_lines).block(scope_block), chunks[1]);

                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[2], btns);
                }
            }

            Modal::VarEditor {
                is_edit,
                var_key,
                is_phase_source,
                phase_ref,
                var_value,
                var_comment,
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

                let box_width = (inner.width as usize).saturating_sub(8).max(20);

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
                    box_width,
                    self.input_cursor,
                ));
                lines.push(Line::from(""));

                let (src_label_style, src_prefix, src_pfx_style) = if *active_field == 1 {
                    (
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        "▸ ",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )
                } else {
                    (
                        Style::default().fg(Color::Yellow),
                        "  ",
                        Style::default().fg(Color::DarkGray),
                    )
                };
                let active_pill = Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let inactive_pill = Style::default()
                    .fg(Color::White)
                    .bg(Color::Rgb(35, 45, 60));

                lines.push(Line::from(vec![
                    Span::styled(src_prefix, src_pfx_style),
                    Span::styled("2. Value Source:", src_label_style),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        if !*is_phase_source {
                            "[● Manual Input]"
                        } else {
                            "[○ Manual Input]"
                        },
                        if !*is_phase_source {
                            active_pill
                        } else {
                            inactive_pill
                        },
                    ),
                    Span::raw("   "),
                    Span::styled(
                        if *is_phase_source {
                            "[● Phase.dev Sync]"
                        } else {
                            "[○ Phase.dev Sync]"
                        },
                        if *is_phase_source {
                            active_pill
                        } else {
                            inactive_pill
                        },
                    ),
                ]));
                lines.push(Line::from(""));

                if *is_phase_source {
                    let ref_display = phase_ref
                        .as_ref()
                        .map(|r| r.reference_syntax())
                        .unwrap_or_default();
                    lines.extend(modern_input_lines(
                        "3. Phase.dev Variable Reference ([Space / Enter] Pick):",
                        &ref_display,
                        "Press [Space] or [Enter] to select App -> Env -> Folder -> Key",
                        *active_field == 2,
                        box_width,
                        ref_display.chars().count(),
                    ));
                    lines.push(Line::from(""));
                    let (ro_comment, ro_ph) = if phase_ref.is_some() {
                        (var_comment.as_str(), "<no comment in Phase.dev>")
                    } else {
                        ("", "<loaded from Phase.dev once variable is selected>")
                    };
                    lines.extend(modern_readonly_lines(
                        "4. Comment (synced from Phase.dev - read-only):",
                        ro_comment,
                        ro_ph,
                        box_width,
                    ));
                } else {
                    lines.extend(modern_input_lines(
                        "3. Variable Value (VALUE):",
                        var_value,
                        "enter secret or value...",
                        *active_field == 2,
                        box_width,
                        self.input_cursor,
                    ));
                    lines.push(Line::from(""));
                    lines.extend(modern_input_lines(
                        "4. Comment (optional, max 100 chars):",
                        var_comment,
                        "enter comment...",
                        *active_field == 3,
                        box_width,
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

            Modal::PhaseVarPicker {
                apps,
                selected_app,
                selected_env,
                loaded_env,
                env_secrets,
                folders,
                selected_folder,
                selected_secret,
                picker_step,
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
                    .title(" Sync Variable from Phase.dev ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(10),
                        Constraint::Length(4),
                        Constraint::Length(1),
                    ])
                    .split(inner);

                let rows = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(chunks[0]);
                let top_cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(rows[0]);
                let bot_cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
                    .split(rows[1]);

                let active_border = Style::default().fg(Color::Cyan);
                let inactive_border = Style::default().fg(Color::DarkGray);
                let hl_style = Style::default()
                    .bg(Color::Rgb(35, 55, 85))
                    .add_modifier(Modifier::BOLD);

                let app_items: Vec<ListItem> =
                    apps.iter().map(|a| ListItem::new(a.name.clone())).collect();
                let app_list = List::new(app_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(if *picker_step == 0 {
                                active_border
                            } else {
                                inactive_border
                            })
                            .title(" 1. Select App "),
                    )
                    .highlight_style(hl_style)
                    .highlight_symbol("▶ ");
                let mut app_state = ListState::default();
                if !apps.is_empty() {
                    app_state.select(Some(*selected_app));
                }
                frame.render_stateful_widget(app_list, top_cols[0], &mut app_state);

                let env_items: Vec<ListItem> = apps
                    .get(*selected_app)
                    .map(|a| {
                        a.environments
                            .iter()
                            .map(|e| ListItem::new(e.name.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                let env_list = List::new(env_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(if *picker_step == 1 {
                                active_border
                            } else {
                                inactive_border
                            })
                            .title(" 2. Select Environment "),
                    )
                    .highlight_style(hl_style)
                    .highlight_symbol("▶ ");
                let mut env_state = ListState::default();
                if apps
                    .get(*selected_app)
                    .map(|a| !a.environments.is_empty())
                    .unwrap_or(false)
                {
                    env_state.select(Some(*selected_env));
                }
                frame.render_stateful_widget(env_list, top_cols[1], &mut env_state);

                let current_env_pair = apps.get(*selected_app).and_then(|a| {
                    a.environments
                        .get(*selected_env)
                        .map(|e| (a.id.clone(), e.id.clone()))
                });
                let is_loaded = current_env_pair.is_some() && *loaded_env == current_env_pair;

                let folder_items: Vec<ListItem> = if !is_loaded {
                    vec![ListItem::new(Span::styled(
                        "Select an environment to view folders",
                        Style::default().fg(Color::DarkGray),
                    ))]
                } else {
                    folders
                        .iter()
                        .map(|f| ListItem::new(f.clone()))
                        .collect()
                };
                let folder_list = List::new(folder_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(if *picker_step == 2 {
                                active_border
                            } else {
                                inactive_border
                            })
                            .title(" 3. Select Folder (Path) "),
                    )
                    .highlight_style(hl_style)
                    .highlight_symbol("▶ ");
                let mut folder_state = ListState::default();
                if is_loaded && !folders.is_empty() {
                    folder_state.select(Some(*selected_folder));
                }
                frame.render_stateful_widget(folder_list, bot_cols[0], &mut folder_state);

                let folder_secrets = if is_loaded {
                    phase_var_picker_folder_secrets(env_secrets, folders, *selected_folder)
                } else {
                    Vec::new()
                };
                let secret_items: Vec<ListItem> = if !is_loaded {
                    vec![ListItem::new(Span::styled(
                        "Select a folder first",
                        Style::default().fg(Color::DarkGray),
                    ))]
                } else {
                    folder_secrets
                        .iter()
                        .map(|s| ListItem::new(s.key.clone()))
                        .collect()
                };
                let secret_list = List::new(secret_items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(if *picker_step == 3 {
                                active_border
                            } else {
                                inactive_border
                            })
                            .title(" 4. Select Variable "),
                    )
                    .highlight_style(hl_style)
                    .highlight_symbol("▶ ");
                let mut secret_state = ListState::default();
                if is_loaded && !folder_secrets.is_empty() {
                    secret_state.select(Some(*selected_secret));
                }
                frame.render_stateful_widget(secret_list, bot_cols[1], &mut secret_state);

                let preview_block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(inactive_border)
                    .title(" Reference Preview ");
                let preview_lines = if let Some(err) = error {
                    vec![Line::from(Span::styled(
                        format!("⚠ Error: {}", err),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    ))]
                } else if let (Some(app), Some(env), Some(folder), Some(sec)) = (
                    apps.get(*selected_app),
                    apps.get(*selected_app)
                        .and_then(|a| a.environments.get(*selected_env)),
                    folders.get(*selected_folder),
                    folder_secrets.get(*selected_secret),
                ) {
                    let pref = PhaseVarRef {
                        app_id: app.id.clone(),
                        app_name: app.name.clone(),
                        env_id: env.id.clone(),
                        env_name: env.name.clone(),
                        path: folder.clone(),
                        secret_key: sec.key.clone(),
                    };
                    let comment_txt = if sec.comment.is_empty() {
                        "<no comment>"
                    } else {
                        sec.comment.as_str()
                    };
                    vec![
                        Line::from(vec![
                            Span::styled(" Ref     : ", Style::default().fg(Color::DarkGray)),
                            Span::styled(
                                pref.reference_syntax(),
                                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                            ),
                        ]),
                        Line::from(vec![
                            Span::styled(" Comment : ", Style::default().fg(Color::DarkGray)),
                            Span::styled(comment_txt.to_string(), Style::default().fg(Color::Gray)),
                        ]),
                    ]
                } else {
                    vec![
                        Line::from(Span::styled(
                            " Select App -> Environment -> Folder -> Variable",
                            Style::default().fg(Color::DarkGray),
                        )),
                    ]
                };
                frame.render_widget(
                    Paragraph::new(preview_lines).block(preview_block),
                    chunks[1],
                );

                if let Some(btns) = get_modal_buttons(&self.modal) {
                    render_modal_buttons(frame, chunks[2], btns);
                }
            }

            Modal::ConfirmDeleteCollection { collection_name, .. } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Red))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Confirm Delete Collection ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Delete collection '{}' and all its variables?", collection_name),
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

            Modal::EditCollection {
                collection_idx,
                name,
                error,
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let is_phase = self
                    .data
                    .collections
                    .get(*collection_idx)
                    .map(|c| c.is_phase())
                    .unwrap_or(false);
                let src_label = self
                    .data
                    .collections
                    .get(*collection_idx)
                    .map(|c| c.source_label())
                    .unwrap_or_else(|| "Manual".to_string());

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Edit Collection ");
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
                    "Rename Collection:",
                    name,
                    "enter collection name",
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

            Modal::VarDetail {
                key,
                value,
                source,
                comment,
            } => {
                let popup = get_modal_rect(&self.modal, area);
                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::new(1, 1, 1, 0))
                    .title(" Variable Details ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let label_style = Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD);
                let max_field_width = (chunks[0].width as usize).saturating_sub(9);
                let key_display = truncate_with_ellipsis(key.clone(), max_field_width);
                let val_line = if value.is_empty() {
                    Span::styled("<empty>", Style::default().fg(Color::DarkGray))
                } else {
                    let val_display = truncate_with_ellipsis(
                        value.replace(['\r', '\n'], " "),
                        max_field_width,
                    );
                    Span::styled(val_display, Style::default().fg(Color::White))
                };
                let source_display = truncate_with_ellipsis(source.clone(), max_field_width);
                let comment_line = if comment.is_empty() {
                    Span::styled("<none>", Style::default().fg(Color::DarkGray))
                } else {
                    let comment_display = truncate_with_ellipsis(
                        comment.replace(['\r', '\n'], " "),
                        max_field_width,
                    );
                    Span::styled(comment_display, Style::default().fg(Color::Gray))
                };

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Key:     ", label_style),
                        Span::styled(
                            key_display,
                            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Value:   ", label_style),
                        val_line,
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Source:  ", label_style),
                        Span::styled(source_display, Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Comment: ", label_style),
                        comment_line,
                    ]),
                ];

                frame.render_widget(Paragraph::new(lines), chunks[0]);

                let btns = var_detail_buttons();
                let total_len: usize = btns.iter().map(|b| b.len()).sum::<usize>() + 4;
                let left_pad = (chunks[1].width as usize).saturating_sub(total_len) / 2;
                let btn_line = Line::from(vec![
                    Span::raw(" ".repeat(left_pad)),
                    Span::styled(
                        btns[0],
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        btns[1],
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        btns[2],
                        Style::default()
                            .fg(Color::White)
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]);
                frame.render_widget(Paragraph::new(btn_line), chunks[1]);
            }

            Modal::Settings {
                tab,
                draft,
                active_field,
                auth_method,
                host_mode,
                custom_url,
                pat_token,
                cli_status,
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
                    .title(" Settings ");
                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(1)])
                    .split(inner);

                let active_pill = Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let inactive_pill = Style::default()
                    .fg(Color::White)
                    .bg(Color::Rgb(35, 45, 60));

                let active_tab_style = Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let inactive_tab_style = Style::default()
                    .fg(Color::White)
                    .bg(Color::Rgb(35, 45, 60));

                let pref_tab_style = if *tab == SettingsTab::Preferences {
                    active_tab_style
                } else {
                    inactive_tab_style
                };
                let phase_tab_style = if *tab == SettingsTab::PhaseAuth {
                    active_tab_style
                } else {
                    inactive_tab_style
                };

                let tab_line = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" [ General ] ", pref_tab_style),
                    Span::raw("  "),
                    Span::styled(" [ Phase.dev ] ", phase_tab_style),
                    Span::raw("   "),
                    Span::styled("(Press Tab or 1 / 2 to switch tabs)", Style::default().fg(Color::DarkGray)),
                ]);

                let mut lines = vec![tab_line, Line::from("")];

                match tab {
                    SettingsTab::Preferences => {
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

                        lines.extend(vec![
                            Line::from(Span::styled(
                                "Application & Synchronization Settings",
                                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                            )),
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(pfx0, s0),
                                Span::styled("1. Sync Collection Scope          : ", s0),
                                Span::styled(if draft.sync_only_enabled_collections { " [● Enabled Only] " } else { " [○ Enabled Only] " }, if draft.sync_only_enabled_collections { active_pill } else { inactive_pill }),
                                Span::raw(" "),
                                Span::styled(if !draft.sync_only_enabled_collections { " [● All Collections] " } else { " [○ All Collections] " }, if !draft.sync_only_enabled_collections { active_pill } else { inactive_pill }),
                            ]),
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(pfx1, s1),
                                Span::styled("2. New Collection Default Place   : ", s1),
                                Span::styled(if draft.insert_new_collection_at_top { " [● Top] " } else { " [○ Top] " }, if draft.insert_new_collection_at_top { active_pill } else { inactive_pill }),
                                Span::raw(" "),
                                Span::styled(if !draft.insert_new_collection_at_top { " [● Bottom] " } else { " [○ Bottom] " }, if !draft.insert_new_collection_at_top { active_pill } else { inactive_pill }),
                            ]),
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(pfx2, s2),
                                Span::styled("3. Shell Prompt Auto-Reload Hook  : ", s2),
                                Span::styled(if draft.shell_prompt_hook { " [● ON ] " } else { " [○ ON ] " }, if draft.shell_prompt_hook { active_pill } else { inactive_pill }),
                                Span::raw(" "),
                                Span::styled(if !draft.shell_prompt_hook { " [● OFF] " } else { " [○ OFF] " }, if !draft.shell_prompt_hook { active_pill } else { inactive_pill }),
                            ]),
                        ]);
                    }
                    SettingsTab::PhaseAuth => {
                        lines.extend(vec![
                            Line::from(Span::styled(
                                "Configure Phase.dev Authentication",
                                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                            )),
                            Line::from(""),
                        ]);

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
                                    42,
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
                                42,
                                self.input_cursor,
                            ));
                        }
                    }
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
                    .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
                    .split(inner);

                let key_style = Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD);
                let desc_style = Style::default().fg(Color::White);

                let lines = vec![
                    Line::from(vec![
                        Span::styled("  [Ctrl+N]           ", key_style),
                        Span::styled("Create a new collection", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Space]            ", key_style),
                        Span::styled("Toggle selected collection or variable ON / OFF", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [u / d]            ", key_style),
                        Span::styled("Move priority up / down (top collection wins)", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+A]           ", key_style),
                        Span::styled("Add a custom environment variable", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+E / Enter]   ", key_style),
                        Span::styled("Edit selected collection or variable", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Delete]           ", key_style),
                        Span::styled("Delete selected collection or variable", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+R]           ", key_style),
                        Span::styled("Show or hide masked secret values", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+B]           ", key_style),
                        Span::styled("Sync the selected environment", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+Shift+B]     ", key_style),
                        Span::styled("Sync all environments", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+S]           ", key_style),
                        Span::styled("Save encrypted state and reload the environment", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Ctrl+P]           ", key_style),
                        Span::styled("Open application settings", desc_style),
                    ]),
                    Line::from(vec![
                        Span::styled("  [Tab / Shift+Tab]  ", key_style),
                        Span::styled("Cycle focus between panes", desc_style),
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
                    render_modal_buttons(frame, chunks[2], btns);
                }
            }
        }
    }

    fn collection_index_at_row(&self, collections_rect: Rect, row: u16) -> Option<usize> {
        let item_start_y = collections_rect.y.saturating_add(2);
        let item_end_y = collections_rect
            .y
            .saturating_add(collections_rect.height.saturating_sub(1));
        if row < item_start_y || row >= item_end_y || self.data.collections.is_empty() {
            return None;
        }
        let visible_rows = (item_end_y - item_start_y) as usize;
        let offset = if visible_rows > 0 && self.selected_collection >= visible_rows {
            self.selected_collection + 1 - visible_rows
        } else {
            0
        };
        let idx = offset + (row - item_start_y) as usize;
        (idx < self.data.collections.len()).then_some(idx)
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
            FocusPane::Collections => {
                if self.selected_collection > 0 {
                    self.selected_collection -= 1;
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
            FocusPane::Collections => {
                if self.selected_collection + 1 < self.data.collections.len() {
                    self.selected_collection += 1;
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

        // 1. Handle active Status Popup interactions
        if !self.status_message.is_empty() {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                if self.is_status_ok_button_clicked(area, mouse.column, mouse.row) {
                    self.status_message.clear();
                    self.status_message_time = None;
                }
            }
            return;
        }

        // 2. Handle active Context Menu interactions
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

        let (header_rect, collections_rect, vars_rect, effective_rect, status_bar_rect) =
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
                    if inner_w >= 90 && mouse.row == header_rect.y + 1 {
                        let right_edge = header_rect.x + header_rect.width - 1;
                        let offset_from_right = right_edge.saturating_sub(mouse.column);
                        // Toolbar layout from right edge:
                        // " [+Collection]  [+Var]  [Sync All]  [Show]  [Settings] " (total 59 chars)
                        if offset_from_right < 13 {
                            self.open_settings_modal();
                        } else if offset_from_right < 22 {
                            self.toggle_mask_values();
                        } else if offset_from_right < 35 {
                            self.sync_all_phase_collections();
                        } else if offset_from_right < 44 {
                            self.open_add_var_modal();
                        } else if offset_from_right < 59 {
                            self.open_new_collection_modal();
                        }
                    }
                    return;
                }

                // Panes & items left-click handling
                if rect_contains(collections_rect, mouse.column, mouse.row) {
                    self.last_var_click = None;
                    self.focus = FocusPane::Collections;
                    if let Some(idx) = self.collection_index_at_row(collections_rect, mouse.row) {
                        if self.selected_collection != idx {
                            self.selected_collection = idx;
                            self.selected_var = 0;
                        }
                        let check_start = collections_rect.x.saturating_add(4);
                        let check_end = collections_rect.x.saturating_add(7);
                        if mouse.column >= check_start && mouse.column < check_end {
                            self.toggle_current_collection();
                        }
                    }
                } else if rect_contains(vars_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Vars;
                    if let Some(idx) = self.var_index_at_row(vars_rect, mouse.row) {
                        self.selected_var = idx;
                        let check_start = vars_rect.x.saturating_add(4);
                        let check_end = vars_rect.x.saturating_add(7);
                        if mouse.column >= check_start && mouse.column < check_end {
                            self.last_var_click = None;
                            self.toggle_current_var();
                        } else if self.register_var_click(FocusPane::Vars, idx) {
                            self.open_var_detail();
                        }
                    } else {
                        self.last_var_click = None;
                    }
                } else if rect_contains(effective_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Effective;
                    if let Some(idx) = self.effective_index_at_row(effective_rect, mouse.row) {
                        self.selected_effective = idx;
                        if self.register_var_click(FocusPane::Effective, idx) {
                            self.open_effective_var_detail();
                        }
                    } else {
                        self.last_var_click = None;
                    }
                } else {
                    self.last_var_click = None;
                }
            }

            MouseEventKind::Down(MouseButton::Right) => {
                if rect_contains(collections_rect, mouse.column, mouse.row) {
                    self.focus = FocusPane::Collections;
                    if let Some(idx) = self.collection_index_at_row(collections_rect, mouse.row) {
                        if self.selected_collection != idx {
                            self.selected_collection = idx;
                            self.selected_var = 0;
                        }
                    }
                    self.open_context_menu_for_pane(
                        FocusPane::Collections,
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
                let target_pane = if rect_contains(collections_rect, mouse.column, mouse.row) {
                    FocusPane::Collections
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
                let target_pane = if rect_contains(collections_rect, mouse.column, mouse.row) {
                    FocusPane::Collections
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
            Modal::Settings {
                tab: SettingsTab::PhaseAuth,
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
            Modal::NewCollection {
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
                is_phase_source,
                var_value,
                var_comment,
                active_field,
                error,
                ..
            } => {
                let single_line: String = clean
                    .chars()
                    .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
                    .collect();
                if *active_field == 0 {
                    for c in single_line.chars() {
                        insert_char_at(var_key, self.input_cursor, c);
                        self.input_cursor += 1;
                    }
                    *error = None;
                } else if !*is_phase_source && *active_field == 2 {
                    for c in single_line.chars() {
                        insert_char_at(var_value, self.input_cursor, c);
                        self.input_cursor += 1;
                    }
                    *error = None;
                } else if !*is_phase_source && *active_field == 3 {
                    for c in single_line.chars() {
                        if var_comment.chars().count() < 100 {
                            insert_char_at(var_comment, self.input_cursor, c);
                            self.input_cursor += 1;
                        }
                    }
                    *error = None;
                }
            }
            Modal::EditCollection { name, error, .. } => {
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

        let btn_chunk = if matches!(self.modal, Modal::Help) {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
                .split(block_inner)[2]
        } else {
            chunks[1]
        };

        if let Modal::VarDetail { key, value, .. } = &self.modal {
            if row == btn_chunk.y {
                let btns = var_detail_buttons();
                let total_len: usize = btns.iter().map(|b| b.len()).sum::<usize>() + 4;
                let start_x = btn_chunk.x + (btn_chunk.width.saturating_sub(total_len as u16)) / 2;
                let copy_key_end = start_x + btns[0].len() as u16;
                let copy_val_start = copy_key_end + 2;
                let copy_val_end = copy_val_start + btns[1].len() as u16;
                let close_start = copy_val_end + 2;
                let close_end = close_start + btns[2].len() as u16;

                if col >= start_x && col < copy_key_end {
                    let k = key.clone();
                    copy_to_clipboard(&k);
                    self.set_info(format!("Copied key '{}' to clipboard", k));
                } else if col >= copy_val_start && col < copy_val_end {
                    let k = key.clone();
                    let v = value.clone();
                    copy_to_clipboard(&v);
                    self.set_info(format!("Copied value for '{}' to clipboard", k));
                } else if col >= close_start && col < close_end {
                    self.modal = Modal::None;
                }
            }
            return;
        }

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
            Modal::NewCollection {
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
            Modal::VarEditor {
                active_field,
                var_key,
                is_phase_source,
                var_value,
                var_comment,
                ..
            } => {
                let mut open_picker = false;
                if row >= block_inner.y + 2 && row <= block_inner.y + 3 {
                    *active_field = 0;
                    if col >= block_inner.x + 6 {
                        self.input_cursor =
                            ((col - (block_inner.x + 6)) as usize).min(var_key.chars().count());
                    } else {
                        self.input_cursor = var_key.chars().count();
                    }
                } else if row >= block_inner.y + 5 && row <= block_inner.y + 6 {
                    *active_field = 1;
                    self.input_cursor = 0;
                    if row == block_inner.y + 6 {
                        let manual_start = block_inner.x + 4;
                        let manual_end = manual_start + 16;
                        let phase_start = manual_end + 3;
                        let phase_end = phase_start + 18;
                        if col >= phase_start && col < phase_end {
                            *is_phase_source = true;
                        } else if col >= manual_start && col < manual_end {
                            *is_phase_source = false;
                        } else {
                            *is_phase_source = !*is_phase_source;
                        }
                    }
                } else if row >= block_inner.y + 8 && row <= block_inner.y + 9 {
                    *active_field = 2;
                    if *is_phase_source {
                        self.input_cursor = 0;
                        if row == block_inner.y + 9 && col >= block_inner.x + 4 {
                            open_picker = true;
                        }
                    } else if col >= block_inner.x + 6 {
                        self.input_cursor =
                            ((col - (block_inner.x + 6)) as usize).min(var_value.chars().count());
                    } else {
                        self.input_cursor = var_value.chars().count();
                    }
                } else if !*is_phase_source
                    && row >= block_inner.y + 11
                    && row <= block_inner.y + 12
                {
                    *active_field = 3;
                    if col >= block_inner.x + 6 {
                        self.input_cursor =
                            ((col - (block_inner.x + 6)) as usize).min(var_comment.chars().count());
                    } else {
                        self.input_cursor = var_comment.chars().count();
                    }
                }

                if open_picker {
                    if let Modal::VarEditor {
                        is_edit,
                        original_index,
                        var_key,
                        phase_ref,
                        var_value,
                        var_comment,
                        active_field,
                        ..
                    } = std::mem::replace(&mut self.modal, Modal::None)
                    {
                        self.open_phase_var_picker_from_editor(
                            is_edit,
                            original_index,
                            var_key,
                            var_value,
                            var_comment,
                            phase_ref,
                            active_field,
                        );
                    }
                }
            }
            Modal::EditCollection { name, .. } => {
                if col >= block_inner.x + 6 {
                    self.input_cursor = ((col - (block_inner.x + 6)) as usize).min(name.chars().count());
                } else {
                    self.input_cursor = name.chars().count();
                }
            }
            Modal::Settings {
                tab,
                draft,
                active_field,
                auth_method,
                host_mode,
                cli_status,
                custom_url,
                pat_token,
                ..
            } => {
                if row == block_inner.y {
                    let pref_tab_end = block_inner.x + 15;
                    let phase_tab_end = block_inner.x + 33;
                    if col <= pref_tab_end {
                        *tab = SettingsTab::Preferences;
                        *active_field = 0;
                    } else if col <= phase_tab_end {
                        *tab = SettingsTab::PhaseAuth;
                        *active_field = 0;
                    }
                    return;
                }

                match tab {
                    SettingsTab::Preferences => {
                        let start_row = block_inner.y + 4;
                        if row == start_row {
                            *active_field = 0;
                            if col >= block_inner.x + 36 {
                                draft.sync_only_enabled_collections =
                                    !draft.sync_only_enabled_collections;
                            }
                        } else if row == start_row + 2 {
                            *active_field = 1;
                            if col >= block_inner.x + 36 {
                                draft.insert_new_collection_at_top =
                                    !draft.insert_new_collection_at_top;
                            }
                        } else if row == start_row + 4 {
                            *active_field = 2;
                            if col >= block_inner.x + 36 {
                                draft.shell_prompt_hook = !draft.shell_prompt_hook;
                            }
                        }
                    }
                    SettingsTab::PhaseAuth => {
                        if row == block_inner.y + 4 {
                            *active_field = 0;
                        } else if row == block_inner.y + 5 {
                            *active_field = 0;
                            *auth_method = PhaseAuthMethod::Cli;
                            *cli_status = detect_phase_cli_detailed();
                        } else if row == block_inner.y + 6 {
                            *active_field = 0;
                            *auth_method = PhaseAuthMethod::Token;
                        } else if *auth_method == PhaseAuthMethod::Token {
                            if row == block_inner.y + 8 {
                                *active_field = 1;
                            } else if row == block_inner.y + 9 {
                                *active_field = 1;
                                *host_mode = HostMode::Cloud;
                            } else if row == block_inner.y + 10 {
                                *active_field = 1;
                                *host_mode = HostMode::SelfHosted;
                            } else if *host_mode == HostMode::SelfHosted {
                                if row >= block_inner.y + 12 && row <= block_inner.y + 13 {
                                    *active_field = 2;
                                    if col >= block_inner.x + 6 {
                                        self.input_cursor = ((col - (block_inner.x + 6)) as usize)
                                            .min(custom_url.chars().count());
                                    } else {
                                        self.input_cursor = custom_url.chars().count();
                                    }
                                } else if row >= block_inner.y + 15 && row <= block_inner.y + 16 {
                                    *active_field = 3;
                                    if col >= block_inner.x + 6 {
                                        self.input_cursor = ((col - (block_inner.x + 6)) as usize)
                                            .min(pat_token.chars().count());
                                    } else {
                                        self.input_cursor = pat_token.chars().count();
                                    }
                                }
                            } else if *host_mode == HostMode::Cloud
                                && row >= block_inner.y + 12 && row <= block_inner.y + 13
                            {
                                *active_field = 2;
                                if col >= block_inner.x + 6 {
                                    self.input_cursor = ((col - (block_inner.x + 6)) as usize)
                                        .min(pat_token.chars().count());
                                } else {
                                    self.input_cursor = pat_token.chars().count();
                                }
                            }
                        }
                    }
                }
            }
            Modal::PhasePicker {
                selected_app,
                selected_env,
                picker_step,
                export_all_paths,
                apps,
                error,
                ..
            } => {
                let picker_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(6),
                        Constraint::Length(3),
                        Constraint::Length(1),
                    ])
                    .split(block_inner);

                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(picker_chunks[0]);

                if rect_contains(cols[0], col, row) {
                    *picker_step = 0;
                    *error = None;
                    if row >= cols[0].y + 1 && row < cols[0].y + cols[0].height.saturating_sub(1) {
                        let offset = (row - (cols[0].y + 1)) as usize;
                        if offset < apps.len() {
                            *selected_app = offset;
                            *selected_env = 0;
                        }
                    }
                } else if rect_contains(cols[1], col, row) {
                    *picker_step = 1;
                    *error = None;
                    if row >= cols[1].y + 1 && row < cols[1].y + cols[1].height.saturating_sub(1) {
                        let offset = (row - (cols[1].y + 1)) as usize;
                        if let Some(app) = apps.get(*selected_app) {
                            if offset < app.environments.len() {
                                *selected_env = offset;
                            }
                        }
                    }
                } else if rect_contains(picker_chunks[1], col, row) {
                    *picker_step = 2;
                    let pill_all_start = picker_chunks[1].x + 4;
                    let pill_all_end = pill_all_start + 15;
                    let pill_root_start = pill_all_end + 3;
                    let pill_root_end = pill_root_start + 19;
                    if row == picker_chunks[1].y + 1 {
                        if col >= pill_all_start && col < pill_all_end {
                            *export_all_paths = true;
                        } else if col >= pill_root_start && col < pill_root_end {
                            *export_all_paths = false;
                        } else {
                            *export_all_paths = !*export_all_paths;
                        }
                    } else if col >= picker_chunks[1].x + 3 && col <= picker_chunks[1].x + 42 {
                        *export_all_paths = !*export_all_paths;
                    }
                }
            }
            Modal::PhaseVarPicker {
                existing_phase_ref,
                apps,
                selected_app,
                selected_env,
                loaded_env,
                env_secrets,
                folders,
                selected_folder,
                selected_secret,
                picker_step,
                error,
                ..
            } => {
                let picker_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(10),
                        Constraint::Length(4),
                        Constraint::Length(1),
                    ])
                    .split(block_inner);
                let grid_rows = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(picker_chunks[0]);
                let top_cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(grid_rows[0]);
                let bot_cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
                    .split(grid_rows[1]);

                if rect_contains(top_cols[0], col, row) {
                    *picker_step = 0;
                    *error = None;
                    if let Some(idx) =
                        list_index_at_row(top_cols[0], row, *selected_app, apps.len())
                    {
                        if *selected_app != idx {
                            *selected_app = idx;
                            *selected_env = 0;
                            *loaded_env = None;
                            env_secrets.clear();
                            folders.clear();
                            *selected_folder = 0;
                            *selected_secret = 0;
                        }
                    }
                } else if rect_contains(top_cols[1], col, row) {
                    *picker_step = 1;
                    *error = None;
                    let env_len = apps
                        .get(*selected_app)
                        .map(|a| a.environments.len())
                        .unwrap_or(0);
                    if let Some(idx) = list_index_at_row(top_cols[1], row, *selected_env, env_len) {
                        if *selected_env != idx {
                            *selected_env = idx;
                            *loaded_env = None;
                            env_secrets.clear();
                            folders.clear();
                            *selected_folder = 0;
                            *selected_secret = 0;
                        }
                    }
                    ensure_phase_var_picker_env_loaded(
                        &self.data.phase,
                        apps,
                        *selected_app,
                        *selected_env,
                        existing_phase_ref.as_ref(),
                        loaded_env,
                        env_secrets,
                        folders,
                        selected_folder,
                        selected_secret,
                        error,
                    );
                } else if rect_contains(bot_cols[0], col, row) {
                    if !ensure_phase_var_picker_env_loaded(
                        &self.data.phase,
                        apps,
                        *selected_app,
                        *selected_env,
                        existing_phase_ref.as_ref(),
                        loaded_env,
                        env_secrets,
                        folders,
                        selected_folder,
                        selected_secret,
                        error,
                    ) {
                        return;
                    }
                    *picker_step = 2;
                    *error = None;
                    if let Some(idx) =
                        list_index_at_row(bot_cols[0], row, *selected_folder, folders.len())
                    {
                        if *selected_folder != idx {
                            *selected_folder = idx;
                            *selected_secret = 0;
                        }
                    }
                } else if rect_contains(bot_cols[1], col, row) {
                    if !ensure_phase_var_picker_env_loaded(
                        &self.data.phase,
                        apps,
                        *selected_app,
                        *selected_env,
                        existing_phase_ref.as_ref(),
                        loaded_env,
                        env_secrets,
                        folders,
                        selected_folder,
                        selected_secret,
                        error,
                    ) {
                        return;
                    }
                    *picker_step = 3;
                    *error = None;
                    let sec_len = phase_var_picker_folder_secrets(
                        env_secrets,
                        folders,
                        *selected_folder,
                    )
                    .len();
                    if let Some(idx) =
                        list_index_at_row(bot_cols[1], row, *selected_secret, sec_len)
                    {
                        *selected_secret = idx;
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
        Modal::ConfirmDeleteCollection { .. } | Modal::ConfirmDeleteVar { .. } => {
            compact_modal_rect(54, 9, area)
        }
        Modal::EditCollection { .. } => compact_modal_rect(58, 12, area),
        Modal::VarDetail { .. } => compact_modal_rect(76, 17, area),
        Modal::NewCollection { .. } => compact_modal_rect(64, 14, area),
        Modal::VarEditor { .. } => compact_modal_rect(80, 21, area),
        Modal::PhaseVarPicker { .. } => compact_modal_rect(84, 22, area),
        Modal::Settings { .. } => compact_modal_rect(82, 23, area),
        Modal::PhasePicker { .. } => compact_modal_rect(76, 20, area),
        Modal::Help => compact_modal_rect(76, 20, area),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModalButtons {
    pub primary: &'static str,
    pub cancel: &'static str,
    pub is_danger: bool,
}

fn var_detail_buttons() -> [&'static str; 3] {
    [" [Copy Key] ", " [Copy Value] ", " [Close] "]
}

pub fn get_modal_buttons(modal: &Modal) -> Option<ModalButtons> {
    match modal {
        Modal::None => None,
        Modal::NewCollection { .. } => Some(ModalButtons {
            primary: " [Create] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::VarEditor { .. } => Some(ModalButtons {
            primary: " [Save] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::PhaseVarPicker { picker_step, .. } => {
            if *picker_step < 3 {
                Some(ModalButtons {
                    primary: " [Next ▶] ",
                    cancel: if *picker_step == 0 {
                        " [Cancel] "
                    } else {
                        " [Back] "
                    },
                    is_danger: false,
                })
            } else {
                Some(ModalButtons {
                    primary: " [Select Variable] ",
                    cancel: " [Back] ",
                    is_danger: false,
                })
            }
        }
        Modal::EditCollection { .. } => Some(ModalButtons {
            primary: " [Save] ",
            cancel: " [Cancel] ",
            is_danger: false,
        }),
        Modal::ConfirmDeleteCollection { .. } | Modal::ConfirmDeleteVar { .. } => Some(ModalButtons {
            primary: " [Delete] ",
            cancel: " [Cancel] ",
            is_danger: true,
        }),
        Modal::Settings { tab, .. } => match tab {
            SettingsTab::Preferences => Some(ModalButtons {
                primary: " [Save] ",
                cancel: " [Cancel] ",
                is_danger: false,
            }),
            SettingsTab::PhaseAuth => Some(ModalButtons {
                primary: " [Connect / Save] ",
                cancel: " [Cancel] ",
                is_danger: false,
            }),
        },
        Modal::PhasePicker { picker_step, .. } => {
            if *picker_step < 2 {
                Some(ModalButtons {
                    primary: " [Next ▶] ",
                    cancel: " [Cancel] ",
                    is_danger: false,
                })
            } else {
                Some(ModalButtons {
                    primary: " [Connect & Import] ",
                    cancel: " [Back] ",
                    is_danger: false,
                })
            }
        },
        Modal::Help => Some(ModalButtons {
            primary: " [Close] ",
            cancel: "",
            is_danger: false,
        }),
        Modal::VarDetail { .. } => None,
    }
}

pub fn copy_to_clipboard(text: &str) {
    let b64 = BASE64_STANDARD.encode(text);
    let osc52 = format!("\x1b]52;c;{}\x07", b64);
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(osc52.as_bytes());
    let _ = stdout.flush();

    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            if let Ok(mut child) = std::process::Command::new("wl-copy")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return;
            }
        }
        if std::env::var_os("DISPLAY").is_some() {
            if let Ok(mut child) = std::process::Command::new("xclip")
                .args(["-selection", "clipboard"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return;
            }
            if let Ok(mut child) = std::process::Command::new("xsel")
                .args(["--clipboard", "--input"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(mut child) = std::process::Command::new("clip.exe")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
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

fn phase_var_picker_folder_secrets<'a>(
    env_secrets: &'a [PhaseSecretItem],
    folders: &[String],
    selected_folder: usize,
) -> Vec<&'a PhaseSecretItem> {
    let Some(folder) = folders.get(selected_folder) else {
        return Vec::new();
    };
    env_secrets
        .iter()
        .filter(|s| normalize_secret_path(&s.path) == *folder)
        .collect()
}

fn load_phase_var_picker_env_with_cfg(
    config: &PhaseConfig,
    apps: &mut [PhaseAppInfo],
    selected_app: usize,
    selected_env: usize,
    existing_ref: Option<&PhaseVarRef>,
) -> Result<((String, String), Vec<PhaseSecretItem>, Vec<String>, usize, usize), String> {
    let app = apps
        .get_mut(selected_app)
        .ok_or_else(|| "Selected App does not exist.".to_string())?;
    let app_id = app.id.clone();
    let app_name = app.name.clone();
    let env = app
        .environments
        .get_mut(selected_env)
        .ok_or_else(|| "Selected App has no environments.".to_string())?;

    let secrets = if !env.cached_secrets.is_empty() {
        env.cached_secrets.clone()
    } else {
        let fetched =
            fetch_detailed_secrets_for_env(config, &app_id, &env.id, Some(&env.name), true)?;
        env.cached_secrets = fetched.clone();
        fetched
    };

    let mut folder_set = std::collections::BTreeSet::new();
    for s in &secrets {
        folder_set.insert(normalize_secret_path(&s.path));
    }
    let folders: Vec<String> = folder_set.into_iter().collect();
    if folders.is_empty() {
        return Err("No variables found in this environment.".to_string());
    }

    let mut selected_folder = 0;
    let mut selected_secret = 0;
    if let Some(pref) = existing_ref {
        if (pref.app_id == app_id || pref.app_name == app_name)
            && (pref.env_id == env.id || pref.env_name == env.name)
        {
            let target_path = pref.normalized_path();
            if let Some(f_idx) = folders.iter().position(|f| f == &target_path) {
                selected_folder = f_idx;
                let folder_secrets =
                    phase_var_picker_folder_secrets(&secrets, &folders, selected_folder);
                if let Some(s_idx) = folder_secrets.iter().position(|s| s.key == pref.secret_key) {
                    selected_secret = s_idx;
                }
            }
        }
    }

    Ok((
        (app_id, env.id.clone()),
        secrets,
        folders,
        selected_folder,
        selected_secret,
    ))
}

#[allow(clippy::too_many_arguments)]
fn ensure_phase_var_picker_env_loaded(
    phase_cfg: &PhaseConfig,
    apps: &mut [PhaseAppInfo],
    selected_app: usize,
    selected_env: usize,
    existing_ref: Option<&PhaseVarRef>,
    loaded_env: &mut Option<(String, String)>,
    env_secrets: &mut Vec<PhaseSecretItem>,
    folders: &mut Vec<String>,
    selected_folder: &mut usize,
    selected_secret: &mut usize,
    error: &mut Option<String>,
) -> bool {
    let current_env_pair = apps.get(selected_app).and_then(|a| {
        a.environments
            .get(selected_env)
            .map(|e| (a.id.clone(), e.id.clone()))
    });
    if current_env_pair.is_some() && *loaded_env == current_env_pair {
        return true;
    }

    match load_phase_var_picker_env_with_cfg(
        phase_cfg,
        apps,
        selected_app,
        selected_env,
        existing_ref,
    ) {
        Ok((pair, secrets, flds, sel_f, sel_s)) => {
            *loaded_env = Some(pair);
            *env_secrets = secrets;
            *folders = flds;
            *selected_folder = sel_f;
            *selected_secret = sel_s;
            *error = None;
            true
        }
        Err(e) => {
            *loaded_env = None;
            env_secrets.clear();
            folders.clear();
            *selected_folder = 0;
            *selected_secret = 0;
            *error = Some(e);
            false
        }
    }
}

fn list_index_at_row(rect: Rect, row: u16, selected: usize, len: usize) -> Option<usize> {
    let start_y = rect.y.saturating_add(1);
    let end_y = rect.y.saturating_add(rect.height.saturating_sub(1));
    if row < start_y || row >= end_y || len == 0 {
        return None;
    }
    let visible_rows = (end_y - start_y) as usize;
    let offset = if visible_rows > 0 && selected >= visible_rows {
        selected + 1 - visible_rows
    } else {
        0
    };
    let idx = offset + (row - start_y) as usize;
    (idx < len).then_some(idx)
}

fn compute_input_window(chars_len: usize, cursor: usize, box_width: usize) -> (usize, usize) {
    if box_width == 0 || chars_len == 0 {
        return (0, 0);
    }
    if cursor >= chars_len {
        let max_text = box_width.saturating_sub(1);
        let start = chars_len.saturating_sub(max_text);
        (start, chars_len)
    } else if chars_len <= box_width {
        (0, chars_len)
    } else {
        let end = (cursor + 1).max(box_width).min(chars_len);
        let start = end.saturating_sub(box_width);
        (start, end)
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
        let ph_chars: Vec<char> = placeholder.chars().collect();
        if is_active {
            content_spans.push(Span::styled(
                "█",
                Style::default().fg(Color::Cyan).bg(bg).add_modifier(Modifier::BOLD),
            ));
            let pad_len = box_width.saturating_sub(1);
            if !ph_chars.is_empty() && pad_len > 1 {
                let take_len = ph_chars.len().min(pad_len - 1);
                let shown_ph: String = ph_chars[..take_len].iter().collect();
                content_spans.push(Span::styled(
                    shown_ph,
                    Style::default().fg(Color::DarkGray).bg(bg),
                ));
                let rem = pad_len.saturating_sub(take_len);
                if rem > 0 {
                    content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
                }
            } else if pad_len > 0 {
                content_spans.push(Span::styled(" ".repeat(pad_len), Style::default().bg(bg)));
            }
        } else {
            let take_len = ph_chars.len().min(box_width);
            let shown_ph: String = ph_chars[..take_len].iter().collect();
            content_spans.push(Span::styled(
                shown_ph,
                Style::default().fg(Color::DarkGray).bg(bg),
            ));
            let rem = box_width.saturating_sub(take_len);
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        }
    } else if is_active {
        let (start, end) = compute_input_window(chars.len(), cursor, box_width);
        if cursor < chars.len() {
            let before: String = chars[start..cursor].iter().collect();
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
            let after: String = chars[cursor + 1..end].iter().collect();
            if !after.is_empty() {
                content_spans.push(Span::styled(
                    after,
                    Style::default().fg(Color::White).bg(bg).add_modifier(Modifier::BOLD),
                ));
            }
            let shown_len = end.saturating_sub(start);
            let rem = box_width.saturating_sub(shown_len);
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        } else {
            let visible: String = chars[start..end].iter().collect();
            let shown_len = end.saturating_sub(start);
            if !visible.is_empty() {
                content_spans.push(Span::styled(
                    visible,
                    Style::default().fg(Color::White).bg(bg).add_modifier(Modifier::BOLD),
                ));
            }
            content_spans.push(Span::styled(
                "█",
                Style::default().fg(Color::Cyan).bg(bg).add_modifier(Modifier::BOLD),
            ));
            let rem = box_width.saturating_sub(shown_len + 1);
            if rem > 0 {
                content_spans.push(Span::styled(" ".repeat(rem), Style::default().bg(bg)));
            }
        }
    } else {
        let (shown_text, shown_len) = if chars.len() <= box_width {
            (value.to_string(), chars.len())
        } else if box_width > 1 {
            let mut s: String = chars[..box_width - 1].iter().collect();
            s.push('…');
            (s, box_width)
        } else {
            let s: String = chars[..box_width].iter().collect();
            (s, box_width)
        };
        content_spans.push(Span::styled(
            shown_text,
            Style::default().fg(Color::White).bg(bg),
        ));
        let rem = box_width.saturating_sub(shown_len);
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

fn right_pane_effective_col_widths(area_width: u16) -> (u16, u16) {
    if area_width >= 55 {
        // borders (2) + padding (2) + highlight_symbol "▶ " (2)
        let table_inner_w = area_width.saturating_sub(6);
        let cols = Layout::horizontal([
            Constraint::Percentage(22),
            Constraint::Percentage(34),
            Constraint::Percentage(12),
            Constraint::Percentage(32),
        ])
        .spacing(1)
        .split(Rect::new(0, 0, table_inner_w, 1));
        (cols[0].width, cols[1].width)
    } else {
        (3, 3)
    }
}

fn truncate_with_ellipsis(s: String, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if s.chars().count() <= max_width {
        return s;
    }
    if max_width == 1 {
        return "…".to_string();
    }
    let mut out: String = s.chars().take(max_width - 1).collect();
    out.push('…');
    out
}

fn modern_readonly_lines(
    label: &str,
    value: &str,
    placeholder: &str,
    box_width: usize,
) -> Vec<Line<'static>> {
    let bg = Color::Rgb(16, 20, 26);
    let bracket_style = Style::default().fg(Color::DarkGray);
    let label_style = Style::default().fg(Color::DarkGray);

    let chars: Vec<char> = value.chars().collect();
    let content_span = if chars.is_empty() {
        let ph_chars: Vec<char> = placeholder.chars().collect();
        let take_len = ph_chars.len().min(box_width);
        let shown: String = ph_chars[..take_len].iter().collect();
        let rem = box_width.saturating_sub(take_len);
        (
            Span::styled(shown, Style::default().fg(Color::DarkGray).bg(bg)),
            rem,
        )
    } else {
        let (shown, take_len) = if chars.len() <= box_width {
            (value.to_string(), chars.len())
        } else if box_width > 1 {
            let mut s: String = chars[..box_width - 1].iter().collect();
            s.push('…');
            (s, box_width)
        } else {
            let s: String = chars[..box_width].iter().collect();
            (s, box_width)
        };
        let rem = box_width.saturating_sub(take_len);
        (
            Span::styled(shown, Style::default().fg(Color::Gray).bg(bg)),
            rem,
        )
    };

    let mut line2_spans = vec![
        Span::raw("    "),
        Span::styled("[ ", bracket_style),
        content_span.0,
    ];
    if content_span.1 > 0 {
        line2_spans.push(Span::styled(
            " ".repeat(content_span.1),
            Style::default().bg(bg),
        ));
    }
    line2_spans.push(Span::styled(" ]", bracket_style));

    vec![
        Line::from(vec![
            Span::styled("  ", Style::default().fg(Color::DarkGray)),
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
    let (_, collections, vars, effective, _) = compute_layout_chunks(area);
    (collections, vars, effective)
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
        crossterm::event::EnableMouseCapture,
        crossterm::event::PushKeyboardEnhancementFlags(
            crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        )
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
        crossterm::event::PopKeyboardEnhancementFlags,
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
        data.collections[0].vars.push(EnvVar::new(
            "API_KEY".to_string(),
            "sk-123456789xyz".to_string(),
            VarSource::Custom,
        ));
        App {
            data,
            focus: FocusPane::Collections,
            selected_collection: 0,
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
            sync_start_time: None,
            input_cursor: 0,
            last_var_click: None,
        }
    }

    #[test]
    fn test_default_collection_can_be_edited_renamed_toggled_deleted() {
        let mut app = make_test_app();
        assert_eq!(app.data.collections[0].name, "default");
        assert!(app.data.collections[0].enabled);

        // 1. Toggle OFF
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(!app.data.collections[0].enabled);
        assert!(app.status_message.is_empty(), "Toggle must not pop up a status message");

        // 2. Toggle ON
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(app.data.collections[0].enabled);
        assert!(app.status_message.is_empty(), "Toggle must not pop up a status message");

        // 3. Edit (Rename) via Ctrl+E
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        match &app.modal {
            Modal::EditCollection {
                collection_idx, name, ..
            } => {
                assert_eq!(*collection_idx, 0);
                assert_eq!(name, "default");
            }
            _ => panic!("Expected Modal::EditCollection"),
        }

        // Type new name: Ctrl+u to clear, type "staging", Enter
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for c in "staging".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::None));
        assert_eq!(app.data.collections[0].name, "staging");
        app.handle_key(KeyEvent::from(KeyCode::Enter));

        // 4. Delete via Delete (bare 'x' is removed and does nothing)
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(app.modal, Modal::None));
        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert!(matches!(app.modal, Modal::ConfirmDeleteCollection { .. }));
        app.handle_key(KeyEvent::from(KeyCode::Char('y')));
        assert!(app.data.collections.is_empty());
    }

    #[test]
    fn test_move_priority_shortcut_u_d() {
        let mut app = make_test_app();
        app.data.collections.push(Collection {
            name: "second_collection".to_string(),
            enabled: true,
            phase_binding: None,
            last_sync_epoch: None,
            vars: Vec::new(),
        });
        assert_eq!(app.data.collections[0].name, "default");
        assert_eq!(app.data.collections[1].name, "second_collection");

        app.selected_collection = 1;

        app.handle_key(KeyEvent::from(KeyCode::Char('u')));
        assert_eq!(app.data.collections[0].name, "second_collection");
        assert_eq!(app.data.collections[1].name, "default");
        assert_eq!(app.selected_collection, 0);
        assert!(app.status_message.is_empty(), "Move priority must not pop up a status message");

        app.handle_key(KeyEvent::from(KeyCode::Char('d')));
        assert_eq!(app.data.collections[0].name, "default");
        assert_eq!(app.data.collections[1].name, "second_collection");
        assert_eq!(app.selected_collection, 1);
        assert!(app.status_message.is_empty(), "Move priority must not pop up a status message");

        app.handle_key(KeyEvent::from(KeyCode::Char('K')));
        assert_eq!(app.data.collections[1].name, "second_collection");
        app.handle_key(KeyEvent::from(KeyCode::Char('J')));
        assert_eq!(app.data.collections[1].name, "second_collection");
    }

    #[test]
    fn test_edit_action_works_across_panes() {
        let mut app = make_test_app();

        app.focus = FocusPane::Collections;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::EditCollection { .. }));
        app.modal = Modal::None;

        app.focus = FocusPane::Vars;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
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
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
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
    fn test_phase_collection_disallows_manual_var_mixing() {
        let mut app = make_test_app();
        app.data.collections.insert(
            0,
            Collection::new_phase(
                "phase_prod".to_string(),
                PhaseBinding {
                    app_id: "app1".to_string(),
                    app_name: "MyService".to_string(),
                    env_id: "env1".to_string(),
                    env_name: "Production".to_string(),
                    export_all_paths: true,
                },
                vec![("PHASE_SECRET".to_string(), "val123456".to_string(), String::new())],
            ),
        );
        app.selected_collection = 0;

        // Pressing Ctrl+A on a Phase collection must NOT open VarEditor
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);

        // Pressing Ctrl+E on Vars pane of a Phase collection must NOT open VarEditor
        app.focus = FocusPane::Vars;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);

        // Pressing Delete on Vars pane of a Phase collection must NOT open ConfirmDeleteVar
        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.is_error_status);
    }

    #[test]
    fn test_settings_modal_toggle_options() {
        let mut app = make_test_app();
        assert!(app.data.settings.sync_only_enabled_collections);

        // Open settings with Ctrl+P
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::Settings { .. }));

        // Field 0: toggle sync_only_enabled_collections with Space
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        // Save with Enter
        app.handle_key(KeyEvent::from(KeyCode::Enter));

        assert!(matches!(app.modal, Modal::None));
        assert!(!app.data.settings.sync_only_enabled_collections);
    }

    #[test]
    fn test_vars_panel_title_shows_last_sync_only_for_phase_collections() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Initially, selected collection is 'default' (Custom collection)
        assert!(app.data.collections[0].is_custom());
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

        assert!(content.contains("1 variable in default collection"));
        assert!(!content.contains("Last sync"));

        // 2. Add and select a Phase collection
        let phase_coll = Collection::new_phase(
            "phase_prod".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "MyService".to_string(),
                env_id: "env1".to_string(),
                env_name: "Production".to_string(),
                export_all_paths: true,
            },
            vec![("PHASE_KEY".to_string(), "val".to_string(), String::new())],
        );
        app.data.collections.push(phase_coll);
        app.selected_collection = 1;
        assert!(app.data.collections[1].is_phase());

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

        assert!(content2.contains("1 variable in phase_prod collection"));
        assert!(content2.contains("Last sync: just now"));

        // 3. Switch back to custom collection (index 0)
        app.selected_collection = 0;
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

        assert!(content3.contains("1 variable in default collection"));
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

        assert!(content.contains("Collections (Top Wins"));
        assert!(!content.contains("1. Default & Collections"));
        assert!(!content.contains("Collections (Top #1 Wins Priority)"));
        assert!(content.contains("1 variable in default"));
        assert!(!content.contains("Variables in Collection:"));
        assert!(!content.contains("Variables in collection"));
        assert!(!content.contains("(1v)"));
        assert!(!content.contains("Collection #1"));
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
        assert!(content.contains("COLLECTION"));
        assert!(!content.contains("WINNING COLLECTION"));
        assert!(content.contains("COLLECTION"));
        assert!(!content.contains("WINNING COLLECTION"));
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

        let popup = get_modal_rect(&app.modal, app.last_area);
        let popup_content: String = (popup.y..popup.y + popup.height)
            .map(|y| {
                (popup.x..popup.x + popup.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(popup_content.contains("Keyboard Shortcuts & Help"));
        assert!(popup_content.contains("Move priority up / down"));
        assert!(popup_content.contains("Sync all environments"));
        assert!(!popup_content.contains("Phase.dev"));
        assert!(!popup_content.contains("phase.dev"));
        assert!(!popup_content.contains("Mouse Actions"));
        assert!(!popup_content.contains("Right Click"));

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
        app.data.collections[0].vars.push(EnvVar::new(
            "SECOND_KEY".to_string(),
            "val-987654321".to_string(),
            VarSource::Custom,
        ));
        app.data.collections.push(Collection::new_custom("staging".to_string()));
        app.last_area = Rect::new(0, 0, 120, 30);

        let (collections_rect, vars_rect, _) = compute_pane_areas(app.last_area);

        // 1. Left-click the second collection ("staging" at row collections_rect.y + 3)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: collections_rect.x + 8,
            row: collections_rect.y + 3,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Collections);
        assert_eq!(app.selected_collection, 1);

        // 2. Left-click back on the first collection ("default" at row collections_rect.y + 2)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: collections_rect.x + 8,
            row: collections_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.selected_collection, 0);

        // 3. Left-click the second variable ("SECOND_KEY" at row vars_rect.y + 4)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 8,
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
    fn test_status_message_rendered_in_centered_popup() {
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

        // Status bar line must NOT contain the message
        let status_row = buffer.area.height - 1;
        let row_text: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();
        assert!(!row_text.contains("Secret values are now masked."));
    }

    #[test]
    fn test_mouse_click_gains_focus_on_panes() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 100, 30);
        let (collections_rect, vars_rect, effective_rect) = compute_pane_areas(app.last_area);

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
            column: collections_rect.x + 2,
            row: collections_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Collections);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Right),
            column: vars_rect.x + 2,
            row: vars_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Vars);
        assert!(app.context_menu.is_some());
        app.context_menu = None;
        app.focus = FocusPane::Collections;

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 1,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.focus, FocusPane::Collections);

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
        assert_eq!(app.focus, FocusPane::Collections);
    }

    #[test]
    fn test_keyboard_navigation_between_panes() {
        let mut app = make_test_app();
        assert_eq!(app.focus, FocusPane::Collections);

        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Effective);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, FocusPane::Collections);

        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Effective);
        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.focus, FocusPane::Collections);

        app.handle_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(app.focus, FocusPane::Vars);
        app.handle_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.focus, FocusPane::Collections);
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
        app.data.collections[0].phase_binding = Some(PhaseBinding {
            app_id: "app-1".to_string(),
            app_name: "my-app".to_string(),
            env_id: "env-1".to_string(),
            env_name: "prod".to_string(),
            export_all_paths: true,
        });

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Click header [Sync All] button
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
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::All));

        // Verify centered popup displays the in-progress message (and status bar does not)
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let status_row = buffer.area.height - 1;
        let row_text: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!row_text.contains("Phase.dev sync in progress..."));
        assert!(screen_text.contains("Phase.dev sync in progress..."));

        // 2. Perform pending sync (mock collection with non-existent secrets will return fail/mock)
        app.perform_pending_sync();
        assert_eq!(app.pending_phase_sync, None);
        assert!(
            app.status_message.contains("Phase.dev sync"),
            "Expected status message to indicate Phase.dev sync completion: '{}'",
            app.status_message
        );

        // Verify centered popup displays completion status (and status bar does not)
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let row_text_completed: String = (0..buffer.area.width)
            .map(|x| buffer.get(x, status_row).symbol())
            .collect();
        let screen_text_completed: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!row_text_completed.contains("Phase.dev sync"));
        assert!(screen_text_completed.contains("Phase.dev sync"));

        // 3. Test context menu sync action
        app.execute_context_action(ContextAction::PhaseSync);
        assert_eq!(app.status_message, "Phase.dev sync in progress...");
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::Collection(0)));
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
        let (_, collections, vars, _, _) = compute_layout_chunks(area);

        // Panel widths swapped: Left panel = 24%, Right panel = 76%
        assert_eq!(collections.width, 24);
        assert_eq!(vars.width, 76);
    }

    #[test]
    fn test_modal_padding_and_buttons_clickable_with_mouse() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        // 1. Open New Collection modal
        app.modal = Modal::NewCollection {
            name: "new-prod".to_string(),
            pull_from_phase: false,
            active_field: 0,
            error: None,
        };

        let popup = get_modal_rect(&app.modal, area);
        assert!(popup.width < area.width, "Popup must be compact and fitted");
        assert!(popup.height < area.height, "Popup must be compact and fitted");

        // Click Cancel button in NewCollection popup
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
            is_phase_source: false,
            phase_ref: None,
            var_value: "new_value".to_string(),
            var_comment: String::new(),
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
        assert!(app.data.collections[0].vars.iter().any(|v| v.key == "NEW_KEY"), "Variable must be created on Save click");
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
        app.modal = Modal::NewCollection {
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
            Modal::NewCollection { name, .. } => assert_eq!(name, "helXlo"),
            _ => panic!("Expected NewCollection modal"),
        }

        // 3. Press Left arrow key once (cursor at 3, over 'X') and press Backspace (deletes 'l' at index 2)
        app.handle_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.input_cursor, 3);
        app.handle_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(app.input_cursor, 2);
        match &app.modal {
            Modal::NewCollection { name, .. } => assert_eq!(name, "heXlo"),
            _ => panic!("Expected NewCollection modal"),
        }

        // 4. Press Delete key (deletes 'X' at cursor 2) -> "helo"
        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert_eq!(app.input_cursor, 2);
        match &app.modal {
            Modal::NewCollection { name, .. } => assert_eq!(name, "helo"),
            _ => panic!("Expected NewCollection modal"),
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
    fn test_new_collection_vertical_radios_and_no_source_note() {
        let mut app = make_test_app();
        app.modal = Modal::NewCollection {
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

        // 1. Radio options are rendered vertically (with (●) / (○)) without parenthetical descriptions
        assert!(content.contains("(●) Custom Environment"));
        assert!(content.contains("(○) Phase.dev Synchronization"));
        assert!(!content.contains("(Manual Variables)"));
        assert!(!content.contains("(Select App & Env)"));

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

        // 2. Note stating that each collection uses exclusively one source must NOT be present
        assert!(!content.contains("exclusively one source"));
        assert!(!content.contains("sources cannot be mixed"));
    }

    #[test]
    fn test_effective_pane_source_column_not_truncated() {
        let mut app = make_test_app();
        app.data.collections.push(Collection::new_phase(
            "staging".to_string(),
            PhaseBinding {
                app_id: "app-1".to_string(),
                app_name: "my-app".to_string(),
                env_id: "env-1".to_string(),
                env_name: "production".to_string(),
                export_all_paths: true,
            },
            vec![("DATABASE_URL".to_string(), "postgres://...".to_string(), String::new())],
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

        assert!(content.contains("COLLECTION"));
        assert!(content.contains("Phase (my-app/production)"));
    }

    #[test]
    fn test_context_menu_no_header_and_right_aligned_shortcuts_in_all_panels() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 120, 30);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Collections pane context menu
        app.open_context_menu_for_pane(FocusPane::Collections, 10, 5);
        assert!(app.context_menu.is_some());
        let menu_rect = app.context_menu.as_ref().unwrap().rect(app.last_area);
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

        // Header must be removed
        assert!(!content.contains("Collection Actions"));
        assert!(content.contains("Edit Collection"));
        assert!(content.contains("Disable Collection"));

        // Verify shortcuts are right-aligned: in every menu row, the closing bracket ']'
        // must be at the exact same column (menu_rect.x + menu_rect.width - 3)
        let right_bracket_col = menu_rect.x + menu_rect.width - 3;
        for row in (menu_rect.y + 1)..(menu_rect.y + menu_rect.height - 1) {
            let ch = buffer[(right_bracket_col, row)].symbol();
            assert_eq!(ch, "]", "Shortcut right bracket must be right-aligned at col {}", right_bracket_col);
        }
        app.context_menu = None;

        // 2. Vars pane context menu
        app.open_context_menu_for_pane(FocusPane::Vars, 40, 5);
        assert!(app.context_menu.is_some());
        let vars_menu_rect = app.context_menu.as_ref().unwrap().rect(app.last_area);
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content_vars: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!content_vars.contains("Variable Actions"));
        assert!(content_vars.contains("Edit Variable"));
        assert!(!content_vars.contains("Mask Secret Values"));
        assert!(content_vars.contains("Copy Key"));
        assert!(content_vars.contains("Copy Value"));
        assert!(content_vars.contains("[Y]"));
        assert!(content_vars.contains("[Shift+Y]"));
        let vars_bracket_col = vars_menu_rect.x + vars_menu_rect.width - 3;
        for row in (vars_menu_rect.y + 1)..(vars_menu_rect.y + vars_menu_rect.height - 1) {
            let ch = buffer[(vars_bracket_col, row)].symbol();
            assert_eq!(ch, "]", "Vars shortcut right bracket must be right-aligned at col {}", vars_bracket_col);
        }
        app.context_menu = None;

        // 3. Effective pane context menu
        app.open_context_menu_for_pane(FocusPane::Effective, 50, 10);
        assert!(app.context_menu.is_some());
        let eff_menu_rect = app.context_menu.as_ref().unwrap().rect(app.last_area);
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let content_eff: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!content_eff.contains("Effective Env Actions"));
        assert!(content_eff.contains("Reload Shell Env"));
        assert!(!content_eff.contains("Mask Secret Values"));
        assert!(content_eff.contains("Copy Key"));
        assert!(content_eff.contains("Copy Value"));
        assert!(content_eff.contains("[Y]"));
        assert!(content_eff.contains("[Shift+Y]"));
        let eff_bracket_col = eff_menu_rect.x + eff_menu_rect.width - 3;
        for row in (eff_menu_rect.y + 1)..(eff_menu_rect.y + eff_menu_rect.height - 1) {
            let ch = buffer[(eff_bracket_col, row)].symbol();
            assert_eq!(ch, "]", "Effective shortcut right bracket must be right-aligned at col {}", eff_bracket_col);
        }
    }

    #[test]
    fn test_error_status_popup_requires_manual_dismissal() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 120, 30);
        app.set_error("Phase.dev sync failed: 401 Unauthorized");

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Centered popup contains error elements without icons
        assert!(screen.contains("Error"));
        assert!(screen.contains("[OK]"));
        assert!(!screen.contains('✖'));
        assert!(!screen.contains('✔'));
        assert!(!screen.contains('ℹ'));
        assert!(screen.contains("Phase.dev sync failed: 401 Unauthorized"));

        // Status bar line must NOT contain the error
        let status_row = buffer.area.height - 1;
        let row_text: String = (0..buffer.area.width)
            .map(|x| buffer[(x, status_row)].symbol())
            .collect();
        assert!(!row_text.contains("Phase.dev sync failed"));

        // Error must NOT auto-close even after simulated 10 seconds
        app.status_message_time = Some(Instant::now() - Duration::from_secs(10));
        app.clear_expired_status();
        assert_eq!(app.status_message, "Phase.dev sync failed: 401 Unauthorized");

        // Arbitrary keys (e.g. Tab, 'x', 'j') must NOT dismiss the error
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.status_message, "Phase.dev sync failed: 401 Unauthorized");
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert_eq!(app.status_message, "Phase.dev sync failed: 401 Unauthorized");

        // Esc key dismisses the error
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.status_message.is_empty(), "Esc key must manually dismiss error popup");

        // Mouse click on OK button dismisses error as well
        app.set_error("Another error occurred");
        assert!(!app.status_message.is_empty());
        let btn_rect = app.status_popup_ok_button_rect(app.last_area);
        // Click outside the OK button does NOT dismiss
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 10,
            modifiers: KeyModifiers::empty(),
        });
        assert!(!app.status_message.is_empty(), "Clicking outside OK button must NOT dismiss the popup");
        // Click directly on the OK button dismisses
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: btn_rect.x + 2,
            row: btn_rect.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.status_message.is_empty(), "Left mouse click on OK button must manually dismiss error popup");
    }

    #[test]
    fn test_success_status_popup_auto_closes_and_can_be_dismissed() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 120, 30);
        app.set_info("Phase.dev sync succeeded for 'default' (5 vars)");

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(screen.contains("Success"));
        assert!(screen.contains("[OK]"));
        assert!(!screen.contains('✖'));
        assert!(!screen.contains('✔'));
        assert!(!screen.contains('ℹ'));
        assert!(screen.contains("Phase.dev sync succeeded for 'default' (5 vars)"));

        // Status bar line must NOT contain the message
        let status_row = buffer.area.height - 1;
        let row_text: String = (0..buffer.area.width)
            .map(|x| buffer[(x, status_row)].symbol())
            .collect();
        assert!(!row_text.contains("Phase.dev sync succeeded"));

        // Message stays within 5 seconds
        app.clear_expired_status();
        assert_eq!(app.status_message, "Phase.dev sync succeeded for 'default' (5 vars)");

        // Arbitrary keys do NOT dismiss success popup
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert_eq!(app.status_message, "Phase.dev sync succeeded for 'default' (5 vars)");

        // Message automatically expires after ~5 seconds
        app.status_message_time = Some(Instant::now() - Duration::from_millis(5100));
        app.clear_expired_status();
        assert!(app.status_message.is_empty(), "Success popup must automatically close after ~5 seconds");

        // Success popup dismissed manually on Enter (OK button)
        app.set_info("Created collection 'dev'");
        assert_eq!(app.status_message, "Created collection 'dev'");
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.status_message.is_empty(), "Enter key must dismiss success popup via OK button");

        // Success popup dismissed manually by clicking OK button
        app.set_info("Created collection 'prod'");
        assert_eq!(app.status_message, "Created collection 'prod'");
        let btn_rect = app.status_popup_ok_button_rect(app.last_area);
        // Clicking outside does not dismiss
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 5,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.status_message, "Created collection 'prod'");
        // Clicking OK button dismisses
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: btn_rect.x + 2,
            row: btn_rect.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.status_message.is_empty(), "Clicking OK button must dismiss success popup");
    }

    #[test]
    fn test_sync_status_remains_visible_at_least_one_second() {
        let mut app = make_test_app();
        app.data.phase.auth_method = PhaseAuthMethod::Token;
        app.data.phase.pat_token = "pss_user:mock_token".to_string();
        app.data.collections[0].phase_binding = Some(PhaseBinding {
            app_id: "app-1".to_string(),
            app_name: "my-app".to_string(),
            env_id: "env-1".to_string(),
            env_name: "prod".to_string(),
            export_all_paths: true,
        });

        app.set_info("Phase.dev sync in progress...");
        app.sync_start_time = Some(Instant::now());
        app.pending_phase_sync = Some(PendingSyncTarget::Collection(0));

        let t0 = Instant::now();
        app.perform_pending_sync();
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= Duration::from_millis(990),
            "Sync status must remain visible for at least one second, elapsed was: {:?}",
            elapsed
        );
        assert!(app.status_message.contains("Phase.dev sync"));
    }

    #[test]
    fn test_toggle_mask_no_prompt() {
        let mut app = make_test_app();
        assert!(!app.show_values);

        // Press Ctrl+R to show values
        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(app.show_values);
        assert!(app.status_message.is_empty(), "Toggling mask must NOT set an informational prompt");

        // Toggle mask directly
        app.toggle_mask_values();
        assert!(!app.show_values);
        assert!(app.status_message.is_empty(), "Toggling mask directly must NOT set an informational prompt");
    }

    #[test]
    fn test_phase_collection_vars_pane_hides_edit_button_and_copy_actions() {
        let mut app = make_test_app();
        app.data.collections.insert(
            0,
            Collection::new_phase(
                "phase_prod".to_string(),
                PhaseBinding {
                    app_id: "app1".to_string(),
                    app_name: "MyService".to_string(),
                    env_id: "env1".to_string(),
                    env_name: "Production".to_string(),
                    export_all_paths: true,
                },
                vec![("SECRET_TOKEN".to_string(), "super_secret_val_123".to_string(), String::new())],
            ),
        );
        app.selected_collection = 0;
        app.last_area = Rect::new(0, 0, 120, 30);

        // Open context menu for Vars pane of Phase collection
        app.open_context_menu_for_pane(FocusPane::Vars, 30, 5);
        assert!(app.context_menu.is_some());

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // 1. Edit Variable must be hidden for Phase collection
        assert!(!screen.contains("Edit Variable"), "Edit Variable must be hidden for Phase.dev collections");
        assert!(!screen.contains("Delete Variable"), "Delete Variable must be hidden for Phase.dev collections");

        // 2. Sync Environment must be present
        assert!(screen.contains("Sync Environment"));

        // 3. Mask Secret Values must be removed
        assert!(!screen.contains("Mask Secret Values"));

        // 4. Copy Key and Copy Value must be present
        assert!(screen.contains("Copy Key"));
        assert!(screen.contains("Copy Value"));

        // 5. Test Copy Key and Copy Value actions execute without errors
        app.focus = FocusPane::Vars;
        app.selected_var = 0;
        app.execute_context_action(ContextAction::CopyKey);
        app.execute_context_action(ContextAction::CopyValue);
    }

    #[test]
    fn test_sync_all_shortcut_shift_s() {
        let mut app = make_test_app();
        app.data.phase.auth_method = PhaseAuthMethod::Token;
        app.data.phase.pat_token = "pss_user:token".to_string();
        app.data.collections.push(Collection::new_phase(
            "phase_test".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "App".to_string(),
                env_id: "env1".to_string(),
                env_name: "Env".to_string(),
                export_all_paths: true,
            },
            vec![],
        ));

        // Press Ctrl+Shift+B
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL | KeyModifiers::SHIFT));
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::All));
        assert_eq!(app.status_message, "Phase.dev sync in progress...");
    }

    #[test]
    fn test_shortcut_c_removed_and_settings_phase_auth_integration() {
        let mut app = make_test_app();

        // 1. Press 'c' -> should not open anything (modal remains None)
        app.handle_key(KeyEvent::from(KeyCode::Char('c')));
        assert!(matches!(app.modal, Modal::None));

        // 2. Press Ctrl+P -> opens Settings on Preferences tab
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        match &app.modal {
            Modal::Settings { tab, active_field, .. } => {
                assert_eq!(*tab, SettingsTab::Preferences);
                assert_eq!(*active_field, 0);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // 3. Switch to PhaseAuth tab with '2'
        app.handle_key(KeyEvent::from(KeyCode::Char('2')));
        match &app.modal {
            Modal::Settings { tab, .. } => {
                assert_eq!(*tab, SettingsTab::PhaseAuth);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // 4. Switch back to Preferences tab with '1'
        app.handle_key(KeyEvent::from(KeyCode::Char('1')));
        match &app.modal {
            Modal::Settings { tab, .. } => {
                assert_eq!(*tab, SettingsTab::Preferences);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // 5. Navigate with Tab to switch from Preferences to PhaseAuth tab
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        match &app.modal {
            Modal::Settings { tab, .. } => {
                assert_eq!(*tab, SettingsTab::PhaseAuth);
            }
            _ => panic!("Expected Modal::Settings"),
        }
    }

    #[test]
    fn test_secrets_always_masked_at_startup() {
        let app = make_test_app();
        assert!(!app.show_values, "Secret values must always be masked automatically at startup");
    }

    #[test]
    fn test_settings_popup_dimensions_and_no_wrap() {
        let mut app = make_test_app();
        app.open_settings_modal();

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Verify label does NOT have "Phase" in collection sync scope
        assert!(screen.contains("Sync Collection Scope"), "Label must not contain Phase");
        assert!(!screen.contains("Phase Sync Collection Scope"), "Label must not contain Phase");
        // Verify other items are present and intact
        assert!(screen.contains("New Collection Default Place"));
        assert!(screen.contains("Shell Prompt Auto-Reload Hook"));
        assert!(!screen.contains("Phase.dev Authentication Setup"));
        assert!(screen.contains("[● Top]"));
        assert!(screen.contains("[○ Bottom]"));
        assert!(screen.contains("[ General ]"));
        assert!(screen.contains("[ Phase.dev ]"));

        // Verify modal rect has width 82, height 23 on 120-wide terminal
        let rect = get_modal_rect(&app.modal, Rect::new(0, 0, 120, 30));
        assert_eq!(rect.width, 82);
        assert_eq!(rect.height, 23);
    }

    #[test]
    fn test_phase_picker_flow_three_steps_and_path_scope() {
        let mut app = make_test_app();
        let test_apps = vec![PhaseAppInfo {
            id: "app-1".to_string(),
            name: "BackendApp".to_string(),
            environments: vec![
                crate::phase::PhaseEnvInfo {
                    id: "env-1".to_string(),
                    name: "production".to_string(),
                    identity_key: String::new(),
                    wrapped_seed: String::new(),
                    wrapped_salt: String::new(),
                    cached_secrets: Vec::new(),
                },
            ],
        }];

        app.modal = Modal::PhasePicker {
            target_collection_idx: None,
            new_collection_name: Some("imported_phase".to_string()),
            apps: test_apps,
            selected_app: 0,
            selected_env: 0,
            picker_step: 0,
            export_all_paths: true,
            error: None,
        };

        // Draw and verify:
        // 1. App name is shown without environment count
        // 2. Environment selector displays name without variable count
        // 3. Path scope does NOT show the removed description line
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("BackendApp"));
        assert!(!screen.contains("BackendApp ("));
        assert!(screen.contains("production"));
        assert!(!screen.contains("production ("));
        assert!(!screen.contains("imports across all folder paths"));
        assert!(!screen.contains("Press Space or Left/Right"));

        // Step 0: Select App, press Enter -> advances to Step 1 (Select Environment)
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        match &app.modal {
            Modal::PhasePicker { picker_step, .. } => assert_eq!(*picker_step, 1),
            _ => panic!("Expected PhasePicker at step 1"),
        }

        // Step 1: Select Environment, press Enter -> advances to Step 2 (Choose Path Scope)
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        match &app.modal {
            Modal::PhasePicker { picker_step, export_all_paths, .. } => {
                assert_eq!(*picker_step, 2);
                assert!(*export_all_paths);
            }
            _ => panic!("Expected PhasePicker at step 2"),
        }

        // Step 2: Toggle path scope with Space -> switches export_all_paths to false (root only)
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        match &app.modal {
            Modal::PhasePicker { picker_step, export_all_paths, .. } => {
                assert_eq!(*picker_step, 2);
                assert!(!*export_all_paths);
            }
            _ => panic!("Expected PhasePicker at step 2 with export_all_paths == false"),
        }

        // Press Esc -> goes back to step 1
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        match &app.modal {
            Modal::PhasePicker { picker_step, .. } => assert_eq!(*picker_step, 1),
            _ => panic!("Expected PhasePicker at step 1"),
        }
    }

    #[test]
    fn test_phase_auth_vertical_arrow_navigation() {
        let mut app = make_test_app();
        app.data.phase.host_mode = HostMode::Cloud;
        app.open_settings_modal_with_tab(SettingsTab::PhaseAuth, None, None);

        // Initial state on PhaseAuth: active_field = 0, auth_method = Cli
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Cli);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Right arrow does NOT change auth_method (only vertical Up/Down)
        app.handle_key(KeyEvent::from(KeyCode::Right));
        match &app.modal {
            Modal::Settings { auth_method, .. } => assert_eq!(*auth_method, PhaseAuthMethod::Cli),
            _ => panic!("Expected Modal::Settings"),
        }

        // Down arrow on CLI switches to API Token (option below)
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Token);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Down arrow on API Token advances to field 1 (Server Mode)
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::Cloud);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Down arrow on Cloud switches to Self-Hosted (option below)
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::SelfHosted);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Down arrow on Self-Hosted advances to field 2 (Self-Hosted URL)
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::Settings { active_field, .. } => assert_eq!(*active_field, 2),
            _ => panic!("Expected Modal::Settings"),
        }

        // Down arrow on field 2 advances to field 3 (Phase API Token)
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::Settings { active_field, .. } => assert_eq!(*active_field, 3),
            _ => panic!("Expected Modal::Settings"),
        }

        // Up arrow on field 3 moves to field 2 (URL)
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::Settings { active_field, .. } => assert_eq!(*active_field, 2),
            _ => panic!("Expected Modal::Settings"),
        }

        // Up arrow on field 2 moves to field 1 (Server Mode: Self-Hosted)
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::SelfHosted);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Up arrow on Self-Hosted switches to Cloud (option above)
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::Cloud);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Up arrow on Cloud moves to field 0 (Auth Method: Token)
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Token);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Up arrow on Token switches to CLI (option above)
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Cli);
            }
            _ => panic!("Expected Modal::Settings"),
        }
    }

    #[test]
    fn test_phase_auth_mouse_clicks_on_radio_buttons() {
        let mut app = make_test_app();
        app.data.phase.host_mode = HostMode::Cloud;
        app.last_area = Rect::new(0, 0, 120, 30);
        app.open_settings_modal_with_tab(SettingsTab::PhaseAuth, None, None);

        let popup = get_modal_rect(&app.modal, app.last_area);
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);

        // Click row 6: "API Token" radio button
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: block_inner.x + 8,
            row: block_inner.y + 6,
            modifiers: KeyModifiers::empty(),
        });
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Token);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Click row 10: "Self-Hosted Console" radio button
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: block_inner.x + 8,
            row: block_inner.y + 10,
            modifiers: KeyModifiers::empty(),
        });
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::SelfHosted);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Click row 9: "Official Cloud" radio button
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: block_inner.x + 8,
            row: block_inner.y + 9,
            modifiers: KeyModifiers::empty(),
        });
        match &app.modal {
            Modal::Settings { active_field, host_mode, .. } => {
                assert_eq!(*active_field, 1);
                assert_eq!(*host_mode, HostMode::Cloud);
            }
            _ => panic!("Expected Modal::Settings"),
        }

        // Click row 5: "Phase CLI" radio button
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: block_inner.x + 8,
            row: block_inner.y + 5,
            modifiers: KeyModifiers::empty(),
        });
        match &app.modal {
            Modal::Settings { active_field, auth_method, .. } => {
                assert_eq!(*active_field, 0);
                assert_eq!(*auth_method, PhaseAuthMethod::Cli);
            }
            _ => panic!("Expected Modal::Settings"),
        }
    }

    #[test]
    fn test_updated_keyboard_shortcuts() {
        let mut app = make_test_app();

        // 1. Create a new collection: Ctrl+N
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::NewCollection { .. }));
        app.modal = Modal::None;

        // Bare 'n' should NOT create a collection
        app.handle_key(KeyEvent::from(KeyCode::Char('n')));
        assert!(matches!(app.modal, Modal::None));

        // 2. Add custom environment variable: Ctrl+A
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::VarEditor { is_edit: false, .. }));
        app.modal = Modal::None;

        // Bare 'a' should NOT add a variable
        app.handle_key(KeyEvent::from(KeyCode::Char('a')));
        assert!(matches!(app.modal, Modal::None));

        // 3. Edit selected collection: Ctrl+E or Enter
        app.focus = FocusPane::Collections;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::EditCollection { .. }));
        app.modal = Modal::None;

        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::EditCollection { .. }));
        app.modal = Modal::None;

        // Bare 'e' should NOT edit
        app.handle_key(KeyEvent::from(KeyCode::Char('e')));
        assert!(matches!(app.modal, Modal::None));

        // 4. Delete: Delete only; remove X
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(app.modal, Modal::None), "Bare 'x' must be removed and do nothing");

        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert!(matches!(app.modal, Modal::ConfirmDeleteCollection { .. }));
        app.modal = Modal::None;

        // 5. Open application settings: Ctrl+P
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::Settings { .. }));
        app.modal = Modal::None;

        // Bare 's' should NOT open settings
        app.handle_key(KeyEvent::from(KeyCode::Char('s')));
        assert!(matches!(app.modal, Modal::None));

        // 6. Show or hide masked secret values: Ctrl+R (Reveal)
        assert!(!app.show_values);
        app.focus = FocusPane::Collections;
        // Ctrl+R must toggle mask
        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(app.show_values);
        assert!(matches!(app.modal, Modal::None), "Ctrl+R must NOT open edit collection form");

        // Bare 'r' should NOT toggle mask or reload
        app.handle_key(KeyEvent::from(KeyCode::Char('r')));
        assert!(app.show_values);
        assert!(app.status_message.is_empty());

        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(!app.show_values);

        // 7. Save encrypted state and reload environment: Ctrl+S
        app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.status_message.contains("Synced state.enc & shell environment"));
        app.status_message.clear();

        // Bare 'r' should NOT reload
        app.handle_key(KeyEvent::from(KeyCode::Char('r')));
        assert!(app.status_message.is_empty());

        // 8. Sync selected environment: Ctrl+B on custom collection does NOTHING
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL));
        assert!(app.status_message.is_empty(), "Sync on custom collection must do nothing");
        assert_eq!(app.pending_phase_sync, None);

        // 9. Sync all environments: Ctrl+Shift+B
        app.data.collections.push(Collection::new_phase(
            "phase_test".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "App".to_string(),
                env_id: "env1".to_string(),
                env_name: "Env".to_string(),
                export_all_paths: true,
            },
            vec![],
        ));
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL | KeyModifiers::SHIFT));
        assert_eq!(app.pending_phase_sync, Some(PendingSyncTarget::All));
    }

    #[test]
    fn test_help_popup_no_phase_text_and_no_group_divisions() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 120, 30);
        app.modal = Modal::Help;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let popup = get_modal_rect(&app.modal, app.last_area);
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);

        let popup_text: String = (popup.y..popup.y + popup.height)
            .map(|y| {
                (popup.x..popup.x + popup.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Verify no "phase.dev" or "Phase.dev" in the popup content
        assert!(!popup_text.contains("Phase.dev"));
        assert!(!popup_text.contains("phase.dev"));

        // Verify group divisions and redundant header are removed
        assert!(!popup_text.contains("Collection & Variable Actions"));
        assert!(!popup_text.contains("Phase.dev, View & System"));

        // Verify redundant header inside the box is gone (title is on top border only)
        let inner_text: String = (block_inner.y..block_inner.y + block_inner.height.saturating_sub(2))
            .map(|y| {
                (block_inner.x..block_inner.x + block_inner.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!inner_text.contains("Keyboard Shortcuts & Help"));

        // Verify all shortcuts are listed together
        assert!(popup_text.contains("[Ctrl+N]"));
        assert!(popup_text.contains("[Ctrl+A]"));
        assert!(popup_text.contains("[Ctrl+E / Enter]"));
        assert!(popup_text.contains("[Delete]"));
        assert!(popup_text.contains("[Ctrl+R]"));
        assert!(popup_text.contains("[Ctrl+B]"));
        assert!(popup_text.contains("[Ctrl+Shift+B]"));
        assert!(popup_text.contains("[Ctrl+S]"));
        assert!(popup_text.contains("[Ctrl+P]"));
        assert!(popup_text.contains("Cycle focus between panes"));
    }

    #[test]
    fn test_phase_picker_panels_focus_and_app_switching() {
        let mut app = make_test_app();
        app.last_area = Rect::new(0, 0, 120, 30);

        let test_apps = vec![
            PhaseAppInfo {
                id: "app-0".to_string(),
                name: "AppZero".to_string(),
                environments: vec![
                    crate::phase::PhaseEnvInfo {
                        id: "env-0".to_string(),
                        name: "development".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: Vec::new(),
                    },
                    crate::phase::PhaseEnvInfo {
                        id: "env-1".to_string(),
                        name: "staging".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: Vec::new(),
                    },
                    crate::phase::PhaseEnvInfo {
                        id: "env-2".to_string(),
                        name: "production".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: Vec::new(),
                    },
                ],
            },
            PhaseAppInfo {
                id: "app-1".to_string(),
                name: "AppOne".to_string(),
                environments: vec![
                    crate::phase::PhaseEnvInfo {
                        id: "env-10".to_string(),
                        name: "testing".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: Vec::new(),
                    },
                ],
            },
        ];

        app.modal = Modal::PhasePicker {
            target_collection_idx: None,
            new_collection_name: Some("test_phase".to_string()),
            apps: test_apps,
            selected_app: 0,
            selected_env: 0,
            picker_step: 0,
            export_all_paths: true,
            error: None,
        };

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();

        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Verify variable counts are not displayed in the environment list
        assert!(screen.contains("development"));
        assert!(screen.contains("staging"));
        assert!(screen.contains("production"));
        assert!(!screen.contains("development ("));
        assert!(!screen.contains("staging ("));
        assert!(!screen.contains("production ("));
        assert!(!screen.contains("vars)"));

        let popup = get_modal_rect(&app.modal, app.last_area);
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let picker_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(block_inner);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(picker_chunks[0]);

        // 1. Initially picker_step is 0 (Panel 1)
        match &app.modal {
            Modal::PhasePicker { picker_step, .. } => assert_eq!(*picker_step, 0),
            _ => panic!("Expected PhasePicker"),
        }

        // 2. Click in Panel 2 empty space (below list items) -> Panel 2 must receive focus (step 1)
        // without altering selected_env
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[1].x + 10,
            row: cols[1].y + 8,
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, selected_env, .. } => {
                assert_eq!(*picker_step, 1, "Panel 2 must receive focus when clicked anywhere in its area");
                assert_eq!(*selected_app, 0);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 3. Click on Panel 2 title/border -> Panel 2 remains focused
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[1].x + 2,
            row: cols[1].y,
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, .. } => assert_eq!(*picker_step, 1),
            _ => panic!("Expected PhasePicker"),
        }

        // 4. Click in Panel 1 empty space (below list items) -> Panel 1 must receive focus (step 0)
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[0].x + 10,
            row: cols[0].y + 8,
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, selected_env, .. } => {
                assert_eq!(*picker_step, 0, "Panel 1 must receive focus when clicked anywhere in its area");
                assert_eq!(*selected_app, 0);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 5. Click on Panel 1 title/border when focus is on step 1 -> Panel 1 must receive focus
        if let Modal::PhasePicker { picker_step, .. } = &mut app.modal {
            *picker_step = 1;
        }
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[0].x + 2,
            row: cols[0].y,
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, .. } => {
                assert_eq!(*picker_step, 0, "Panel 1 border click must focus Panel 1");
                assert_eq!(*selected_app, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 6. Click on App 1 item in Panel 1 -> selects App 1 and resets env to 0
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[0].x + 5,
            row: cols[0].y + 2, // Second app item (index 1)
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, selected_env, .. } => {
                assert_eq!(*picker_step, 0);
                assert_eq!(*selected_app, 1);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 7. Click back to App 0 item in Panel 1
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[0].x + 5,
            row: cols[0].y + 1, // First app item (index 0)
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, selected_env, .. } => {
                assert_eq!(*picker_step, 0);
                assert_eq!(*selected_app, 0);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 8. Click on Env 2 item ("production") in Panel 2 -> focuses Panel 2 and selects env 2
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: cols[1].x + 5,
            row: cols[1].y + 3, // Third env item (index 2)
            modifiers: KeyModifiers::NONE,
        });
        match &app.modal {
            Modal::PhasePicker { picker_step, selected_app, selected_env, .. } => {
                assert_eq!(*picker_step, 1);
                assert_eq!(*selected_app, 0);
                assert_eq!(*selected_env, 2);
            }
            _ => panic!("Expected PhasePicker"),
        }

        // 9. Keyboard navigation app switching: switch focus to Panel 1 and use Down/Up
        if let Modal::PhasePicker { picker_step, .. } = &mut app.modal {
            *picker_step = 0;
        }
        app.handle_key(KeyEvent::from(KeyCode::Down));
        match &app.modal {
            Modal::PhasePicker { selected_app, selected_env, .. } => {
                assert_eq!(*selected_app, 1);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }
        app.handle_key(KeyEvent::from(KeyCode::Up));
        match &app.modal {
            Modal::PhasePicker { selected_app, selected_env, .. } => {
                assert_eq!(*selected_app, 0);
                assert_eq!(*selected_env, 0);
            }
            _ => panic!("Expected PhasePicker"),
        }
    }

    #[test]
    fn test_save_new_custom_variable_without_popup_and_display_comment() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        // Open VarEditor to add a new custom variable
        app.modal = Modal::VarEditor {
            is_edit: false,
            original_index: None,
            var_key: "DATABASE_TIMEOUT".to_string(),
            is_phase_source: false,
            phase_ref: None,
            var_value: "30s".to_string(),
            var_comment: "Timeout for client database queries".to_string(),
            active_field: 0,
            error: None,
        };

        // Press Enter to save the variable
        app.handle_key(KeyEvent::from(KeyCode::Enter));

        // 1. Modal must be closed
        assert!(matches!(app.modal, Modal::None));

        // 2. NO popup must be displayed! status_message must be empty!
        assert!(app.status_message.is_empty(), "Saving custom variable must NOT display a status popup");

        // 3. Variable must be added with key, value, and comment
        let default_coll = &app.data.collections[0];
        let var = default_coll.vars.iter().find(|v| v.key == "DATABASE_TIMEOUT").expect("variable exists");
        assert_eq!(var.value, "30s");
        assert_eq!(var.comment, "Timeout for client database queries");
        assert!(!var.is_phase_synced());

        // 4. Render and verify COMMENT column and [Manual] badge in upper-right panel (vars_pane)
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(screen_text.contains("KEY"));
        assert!(screen_text.contains("VALUE"));
        assert!(screen_text.contains("SOURCE"));
        assert!(!screen_text.contains("COMMENT"));
        assert!(!screen_text.contains("[Manual]"));
        assert!(screen_text.contains("Manual"));
    }

    #[test]
    fn test_var_editor_comment_100_character_limit_and_navigation() {
        let mut app = make_test_app();
        app.focus = FocusPane::Vars;

        // Open add variable modal via Ctrl+A
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 0, .. }));

        // Tab to field 1 (VALUE SOURCE), field 2 (VALUE), then field 3 (COMMENT)
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 1, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 2, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 3, .. }));

        // Typing characters up to 105 characters in COMMENT field
        for _ in 0..105 {
            app.handle_key(KeyEvent::from(KeyCode::Char('c')));
        }
        match &app.modal {
            Modal::VarEditor { var_comment, .. } => {
                assert_eq!(var_comment.chars().count(), 100, "Comment must be strictly limited to 100 characters");
            }
            _ => panic!("Expected VarEditor"),
        }

        // Up arrow navigates back through fields 2 -> 1 -> 0 and wraps to 3
        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 2, .. }));

        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 1, .. }));

        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 0, .. }));

        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 3, .. }));
    }

    #[test]
    fn test_phase_synced_collection_displays_comments_in_upper_right_panel() {
        let mut app = make_test_app();
        let phase_coll = Collection::new_phase(
            "phase_prod".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "Backend".to_string(),
                env_id: "env1".to_string(),
                env_name: "Production".to_string(),
                export_all_paths: true,
            },
            vec![
                ("API_URL".to_string(), "https://api.phase.dev".to_string(), "Main Phase API endpoint".to_string()),
            ],
        );
        app.data.collections.push(phase_coll);
        app.selected_collection = 1;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(screen_text.contains("API_URL"));
        assert!(!screen_text.contains("[Phase]"));
        assert!(screen_text.contains("Phase (Backend/Production)"));
    }

    #[test]
    fn test_var_editor_wide_single_line_value_no_multiline_wrapping() {
        let long_val = format!("prefix_{}_tail_marker", "x".repeat(220));
        let lines = modern_input_lines("VALUE", &long_val, "val", true, 64, long_val.chars().count());
        assert_eq!(lines.len(), 2, "Input box must stay strictly single-line (header + 1 input row)");

        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;
        app.input_cursor = long_val.chars().count();
        app.modal = Modal::VarEditor {
            is_edit: true,
            original_index: Some(0),
            var_key: "LONG_SECRET".to_string(),
            is_phase_source: false,
            phase_ref: None,
            var_value: long_val.clone(),
            var_comment: String::new(),
            active_field: 2,
            error: None,
        };

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let rows: Vec<String> = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect();

        let value_header_idx = rows
            .iter()
            .position(|r| r.contains("3. Variable Value (VALUE):"))
            .expect("VALUE header rendered");
        let input_row = &rows[value_header_idx + 1];
        let next_row = &rows[value_header_idx + 2];

        // Bracket [ ... ] must span nearly the full width of the 80-col popup and keep value on 1 row
        let open_pos = input_row.find("[ ").expect("opening bracket");
        let close_pos = input_row.rfind(" ]").expect("closing bracket on the exact same line");
        let inner_width = input_row[open_pos..close_pos].chars().count();
        assert!(inner_width >= 60, "Expected widened input box >= 60 chars, got {}", inner_width);
        assert!(input_row.contains("_tail_marker"), "Horizontal window should scroll to cursor tail");
        assert!(!next_row.contains('x'), "Long value must never wrap onto the next line");
    }

    #[test]
    fn test_var_editor_phase_source_locks_comment_readonly() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        let pref = PhaseVarRef {
            app_id: "app1".to_string(),
            app_name: "backend_api".to_string(),
            env_id: "env1".to_string(),
            env_name: "production".to_string(),
            path: "/backend/payments".to_string(),
            secret_key: "STRIPE_KEY".to_string(),
        };
        app.modal = Modal::VarEditor {
            is_edit: false,
            original_index: None,
            var_key: "MY_STRIPE".to_string(),
            is_phase_source: true,
            phase_ref: Some(pref),
            var_value: "sk_live_secret".to_string(),
            var_comment: "Synced Stripe API key".to_string(),
            active_field: 0,
            error: None,
        };

        // Tab must cycle 0 -> 1 -> 2 -> 0 and skip field 3 (COMMENT) when Phase.dev source is active
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 1, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 2, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Char('Z')));
        app.handle_key(KeyEvent::from(KeyCode::Backspace));
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 0, .. }));

        match &app.modal {
            Modal::VarEditor { var_value, var_comment, .. } => {
                assert_eq!(var_value, "sk_live_secret");
                assert_eq!(var_comment, "Synced Stripe API key");
            }
            _ => panic!("Expected VarEditor"),
        }

        // Render modal and confirm read-only comment + Phase reference syntax are visible
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen_text.contains("read-only"));
        assert!(screen_text.contains("Synced Stripe API key"));
        assert!(screen_text.contains("${backend_api::production./backend/payments/STRIPE_KEY}"));

        // Save variable and confirm Phase ref & comment are persisted on collection variable
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::None));
        let saved = app.data.collections[0]
            .vars
            .iter()
            .find(|v| v.key == "MY_STRIPE")
            .expect("MY_STRIPE saved");
        assert!(saved.is_phase_synced());
        assert_eq!(saved.value, "sk_live_secret");
        assert_eq!(saved.comment, "Synced Stripe API key");
        assert_eq!(
            saved.phase_ref.as_ref().unwrap().reference_syntax(),
            "${backend_api::production./backend/payments/STRIPE_KEY}"
        );

        // Switching source back to Manual unlocks field 3 for manual comment editing
        app.modal = Modal::VarEditor {
            is_edit: false,
            original_index: None,
            var_key: "MANUAL_AFTER".to_string(),
            is_phase_source: true,
            phase_ref: None,
            var_value: "v".to_string(),
            var_comment: String::new(),
            active_field: 1,
            error: None,
        };
        app.handle_key(KeyEvent::from(KeyCode::Left));
        assert!(matches!(app.modal, Modal::VarEditor { is_phase_source: false, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Tab)); // -> 2
        app.handle_key(KeyEvent::from(KeyCode::Tab)); // -> 3 (Comment)
        assert!(matches!(app.modal, Modal::VarEditor { active_field: 3, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Char('O')));
        app.handle_key(KeyEvent::from(KeyCode::Char('K')));
        match &app.modal {
            Modal::VarEditor { var_comment, .. } => assert_eq!(var_comment, "OK"),
            _ => panic!("Expected VarEditor"),
        }
    }

    #[test]
    fn test_phase_var_picker_four_step_navigation_populates_editor() {
        let mut app = make_test_app();
        app.modal = Modal::PhaseVarPicker {
            is_edit: false,
            original_index: None,
            var_key: String::new(),
            prev_value: String::new(),
            prev_comment: String::new(),
            existing_phase_ref: None,
            apps: vec![PhaseAppInfo {
                id: "app1".to_string(),
                name: "backend_api".to_string(),
                environments: vec![crate::phase::PhaseEnvInfo {
                    id: "env1".to_string(),
                    name: "production".to_string(),
                    identity_key: String::new(),
                    wrapped_seed: String::new(),
                    wrapped_salt: String::new(),
                    cached_secrets: Vec::new(),
                }],
            }],
            selected_app: 0,
            selected_env: 0,
            loaded_env: Some(("app1".to_string(), "env1".to_string())),
            env_secrets: vec![
                PhaseSecretItem {
                    key: "ROOT_VAR".to_string(),
                    value: "root_val".to_string(),
                    path: "/".to_string(),
                    comment: "Root comment".to_string(),
                },
                PhaseSecretItem {
                    key: "STRIPE_KEY".to_string(),
                    value: "sk_live_123".to_string(),
                    path: "/backend/payments".to_string(),
                    comment: "Live Stripe key".to_string(),
                },
            ],
            folders: vec!["/".to_string(), "/backend/payments".to_string()],
            selected_folder: 0,
            selected_secret: 0,
            picker_step: 0,
            error: None,
        };

        // Render Step 0 and confirm all 4 picker panes and root preview appear
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen_text.contains("1. Select App"));
        assert!(screen_text.contains("2. Select Environment"));
        assert!(screen_text.contains("3. Select Folder (Path)"));
        assert!(screen_text.contains("4. Select Variable"));
        assert!(screen_text.contains("${backend_api::production.ROOT_VAR}"));

        // Navigate App -> Env -> Folder (/backend/payments) -> Variable (STRIPE_KEY)
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::PhaseVarPicker { picker_step: 1, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::PhaseVarPicker { picker_step: 2, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Down));
        assert!(matches!(app.modal, Modal::PhaseVarPicker { selected_folder: 1, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::PhaseVarPicker { picker_step: 3, .. }));
        app.handle_key(KeyEvent::from(KeyCode::Enter));

        match &app.modal {
            Modal::VarEditor {
                is_phase_source,
                var_key,
                var_value,
                var_comment,
                phase_ref,
                ..
            } => {
                assert!(*is_phase_source);
                assert_eq!(var_key, "STRIPE_KEY");
                assert_eq!(var_value, "sk_live_123");
                assert_eq!(var_comment, "Live Stripe key");
                let pref = phase_ref.as_ref().expect("phase_ref populated");
                assert_eq!(
                    pref.reference_syntax(),
                    "${backend_api::production./backend/payments/STRIPE_KEY}"
                );
            }
            _ => panic!("Expected VarEditor populated from PhaseVarPicker"),
        }
    }

    #[test]
    fn test_vars_pane_displays_manual_and_phase_indicators() {
        let mut app = make_test_app();
        app.data.collections[0].vars.push(EnvVar::with_phase_ref(
            "MANUAL_ONLY".to_string(),
            "manual_val".to_string(),
            "Entered manually".to_string(),
            None,
        ));
        app.data.collections[0].vars.push(EnvVar::with_phase_ref(
            "PHASE_REF_VAR".to_string(),
            "phase_val".to_string(),
            "From Phase folder".to_string(),
            Some(PhaseVarRef {
                app_id: "app1".to_string(),
                app_name: "backend_api".to_string(),
                env_id: "env1".to_string(),
                env_name: "production".to_string(),
                path: "/payments".to_string(),
                secret_key: "API_SECRET".to_string(),
            }),
        ));
        app.data.collections[0].last_sync_epoch = Some(1_700_000_000);

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_text: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(screen_text.contains("MANUAL_ONLY"));
        assert!(screen_text.contains("Manual"));
        assert!(screen_text.contains("PHASE_REF_VAR"));
        assert!(screen_text.contains("Phase (backend_api/production"));
        assert!(screen_text.contains("Last sync:"));
    }

    #[test]
    fn test_right_panel_key_and_value_alignment_and_value_ellipsis_truncation() {
        let mut app = make_test_app();
        app.show_values = true;
        let long_val = "very_long_unmasked_secret_value_that_exceeds_column_width_1234567890";
        app.data.collections[0].vars.push(EnvVar::new(
            "LONG_VAL_KEY".to_string(),
            long_val.to_string(),
            VarSource::Custom,
        ));

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();

        let rows: Vec<String> = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect();

        let char_col = |row: &str, needle: &str| -> Option<usize> {
            row.find(needle).map(|byte_idx| row[..byte_idx].chars().count())
        };

        let upper_header = rows.iter().find(|r| r.contains("KEY") && r.contains("SOURCE")).expect("upper header");
        let lower_header = rows.iter().find(|r| r.contains("EXPORTED KEY") && r.contains("EFFECTIVE VALUE")).expect("lower header");

        assert_eq!(
            char_col(upper_header, "KEY"),
            char_col(lower_header, "EXPORTED KEY"),
            "Key column must start at same x in upper and lower right panels"
        );
        assert_eq!(
            char_col(upper_header, "VALUE"),
            char_col(lower_header, "EFFECTIVE VALUE"),
            "Value column must align between upper and lower right panels"
        );

        let upper_var_row = rows.iter().find(|r| r.contains("LONG_VAL_KEY") && r.contains("very_long")).expect("upper var row");
        assert!(upper_var_row.contains('…'), "Upper panel unmasked long value should truncate with ellipsis");
        assert!(!upper_var_row.contains("7890"));

        let lower_var_row = rows.iter().rfind(|r| r.contains("LONG_VAL_KEY") && r.contains("very_long")).expect("lower var row");
        assert!(lower_var_row.contains('…'), "Lower panel unmasked long value should truncate with ellipsis");
        assert!(!lower_var_row.contains("7890"));
    }

    #[test]
    fn test_enter_and_double_click_open_var_detail_popup_in_both_panels() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;
        app.data.collections[0].vars.clear();
        app.data.collections[0].vars.push(EnvVar::with_comment(
            "DETAIL_KEY".to_string(),
            "secret_detail_value".to_string(),
            "Detail comment".to_string(),
            VarSource::Custom,
        ));

        // 1. Enter in Vars pane opens VarDetail
        app.focus = FocusPane::Vars;
        app.selected_var = 0;
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(
            &app.modal,
            Modal::VarDetail { key, value, source, comment }
            if key == "DETAIL_KEY" && value == "secret_detail_value" && source == "Manual" && comment == "Detail comment"
        ));

        // Render VarDetail and verify fields & buttons
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("Variable Details"));
        assert!(screen.contains("DETAIL_KEY"));
        assert!(screen.contains("secret_detail_value"));
        assert!(screen.contains("Manual"));
        assert!(screen.contains("Detail comment"));
        assert!(screen.contains("[Copy Key]"));
        assert!(screen.contains("[Copy Value]"));
        assert!(screen.contains("[Close]"));

        // Esc closes VarDetail
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(app.modal, Modal::None));

        // 2. Enter in Effective pane opens VarDetail
        app.focus = FocusPane::Effective;
        app.selected_effective = 0;
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(
            &app.modal,
            Modal::VarDetail { key, value, source, comment }
            if key == "DETAIL_KEY" && value == "secret_detail_value" && source == "Manual" && comment == "Detail comment"
        ));
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(app.modal, Modal::None));

        // 3. Double-click in Vars pane (on key text, right of checkbox) opens VarDetail
        let (_, _, vars_rect, effective_rect, _) = compute_layout_chunks(area);
        let vars_row_y = vars_rect.y + 3; // border(1) + top padding(1) + header(1) = row 0
        let click_vars = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 8,
            row: vars_row_y,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(click_vars);
        assert!(matches!(app.modal, Modal::None), "Single click should only select");
        app.handle_mouse(click_vars);
        assert!(matches!(app.modal, Modal::VarDetail { .. }), "Double click in Vars pane should open VarDetail");
        app.handle_key(KeyEvent::from(KeyCode::Esc));

        // 4. Double-click in Effective pane opens VarDetail
        let eff_row_y = effective_rect.y + 3;
        let click_eff = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: effective_rect.x + 4,
            row: eff_row_y,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(click_eff);
        assert!(matches!(app.modal, Modal::None), "Single click should only select");
        app.handle_mouse(click_eff);
        assert!(matches!(app.modal, Modal::VarDetail { .. }), "Double click in Effective pane should open VarDetail");

        // 5. Long value in VarDetail stays single-line and truncates with ellipsis
        app.modal = Modal::VarDetail {
            key: "VERY_LONG_KEY".to_string(),
            value: "a".repeat(120) + "_TAIL_MARKER",
            source: "Manual".to_string(),
            comment: "b".repeat(120) + "_COMMENT_TAIL",
        };
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let detail_rows: Vec<String> = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect();
        let value_row = detail_rows.iter().find(|r| r.contains("Value:")).expect("Value row");
        assert!(value_row.contains('…'), "Long value in VarDetail must truncate with ellipsis");
        assert!(!detail_rows.iter().any(|r| r.contains("_TAIL_MARKER")), "Long value must not wrap onto next line");
    }

    #[test]
    fn test_phase_var_picker_loads_folders_and_vars_immediately_on_env_select() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        app.modal = Modal::PhaseVarPicker {
            is_edit: false,
            original_index: None,
            var_key: String::new(),
            prev_value: String::new(),
            prev_comment: String::new(),
            existing_phase_ref: None,
            apps: vec![PhaseAppInfo {
                id: "app1".to_string(),
                name: "di2nsino".to_string(),
                environments: vec![
                    crate::phase::PhaseEnvInfo {
                        id: "env_dev".to_string(),
                        name: "Development".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: vec![PhaseSecretItem {
                            key: "DEV_API_KEY".to_string(),
                            value: "dev_val".to_string(),
                            path: "/".to_string(),
                            comment: "Dev key".to_string(),
                        }],
                    },
                    crate::phase::PhaseEnvInfo {
                        id: "env_prod".to_string(),
                        name: "Production".to_string(),
                        identity_key: String::new(),
                        wrapped_seed: String::new(),
                        wrapped_salt: String::new(),
                        cached_secrets: vec![PhaseSecretItem {
                            key: "PROD_PAYMENT_KEY".to_string(),
                            value: "prod_val".to_string(),
                            path: "/payments".to_string(),
                            comment: "Prod payment".to_string(),
                        }],
                    },
                ],
            }],
            selected_app: 0,
            selected_env: 0,
            loaded_env: None,
            env_secrets: Vec::new(),
            folders: Vec::new(),
            selected_folder: 0,
            selected_secret: 0,
            picker_step: 0,
            error: None,
        };

        // Compute the inner top-right ("2. Select Environment") panel bounds for mouse click
        let popup = get_modal_rect(&app.modal, area);
        let block_inner = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .padding(Padding::new(1, 1, 1, 0))
            .inner(popup);
        let picker_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(4),
                Constraint::Length(1),
            ])
            .split(block_inner);
        let grid_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(picker_chunks[0]);
        let top_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(grid_rows[0]);

        // Click first environment ("Development") directly without touching bottom panels
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: top_cols[1].x + 2,
            row: top_cols[1].y + 1,
            modifiers: KeyModifiers::NONE,
        });

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen_dev: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(matches!(app.modal, Modal::PhaseVarPicker { picker_step: 1, selected_env: 0, .. }));
        assert!(screen_dev.contains("DEV_API_KEY"), "Folders & variables must display immediately after selecting Env");

        // Pressing Down in step 1 selects "Production" and immediately refreshes folders & variables below
        app.handle_key(KeyEvent::from(KeyCode::Down));
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer2 = terminal.backend().buffer();
        let screen_prod: String = (0..buffer2.area.height)
            .map(|y| (0..buffer2.area.width).map(|x| buffer2[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(matches!(app.modal, Modal::PhaseVarPicker { picker_step: 1, selected_env: 1, .. }));
        assert!(screen_prod.contains("/payments"));
        assert!(screen_prod.contains("PROD_PAYMENT_KEY"));
    }

    #[test]
    fn test_toggle_individual_var_keyboard_mouse_and_context_menu_across_collection_types() {
        let mut app = make_test_app();
        let area = Rect::new(0, 0, 120, 30);
        app.last_area = area;

        // Collection 0 (default, Custom/Manual) has one manual var and one Phase-ref var
        app.data.collections[0].vars.clear();
        app.data.collections[0].vars.push(EnvVar::new(
            "MANUAL_VAR".to_string(),
            "manual_val".to_string(),
            VarSource::Custom,
        ));
        app.data.collections[0].vars.push(EnvVar::with_phase_ref(
            "CUSTOM_PHASE_REF".to_string(),
            "ref_val".to_string(),
            String::new(),
            Some(PhaseVarRef {
                app_id: "app1".to_string(),
                app_name: "api".to_string(),
                env_id: "env1".to_string(),
                env_name: "prod".to_string(),
                path: "/".to_string(),
                secret_key: "REF".to_string(),
            }),
        ));

        // Collection 1 is a Phase.dev collection with two variables (one overrides MANUAL_VAR if enabled)
        let phase_coll = Collection::new_phase(
            "phase_prod".to_string(),
            PhaseBinding {
                app_id: "app1".to_string(),
                app_name: "api".to_string(),
                env_id: "env1".to_string(),
                env_name: "prod".to_string(),
                export_all_paths: true,
            },
            vec![
                ("MANUAL_VAR".to_string(), "from_phase".to_string(), String::new()),
                ("PHASE_ONLY".to_string(), "p_val".to_string(), String::new()),
            ],
        );
        app.data.collections.push(phase_coll);

        // 1. Toggle manual var OFF with Space in Vars pane -> Effective falls back to phase_prod's MANUAL_VAR
        app.focus = FocusPane::Vars;
        app.selected_collection = 0;
        app.selected_var = 0;
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(!app.data.collections[0].vars[0].enabled);

        let eff = app.data.compute_effective_vars();
        let map: std::collections::HashMap<_, _> = eff.iter().map(|v| (v.key.as_str(), v)).collect();
        assert_eq!(map["MANUAL_VAR"].value, "from_phase");
        assert_eq!(map["MANUAL_VAR"].winning_owner, "phase_prod");

        // Pressing Ctrl+E on MANUAL_VAR in Effective pane targets the winning Phase.dev var (blocked from manual edit), NOT the disabled custom var
        app.focus = FocusPane::Effective;
        app.selected_effective = eff.iter().position(|v| v.key == "MANUAL_VAR").unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(app.is_error_status);
        app.status_message.clear();

        // 2. Toggle Phase-ref var OFF via mouse click on checkbox [✓] in Vars pane
        app.focus = FocusPane::Vars;
        app.selected_collection = 0;
        let (_, _, vars_rect, _, _) = compute_layout_chunks(area);
        let row1_y = vars_rect.y + 4; // row 0 is +3, row 1 is +4
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: vars_rect.x + 5,
            row: row1_y,
            modifiers: KeyModifiers::NONE,
        });
        assert!(!app.data.collections[0].vars[1].enabled);
        assert!(matches!(app.modal, Modal::None));

        // 3. Toggle variable inside Phase.dev collection using context menu & Space
        app.selected_collection = 1;
        app.selected_var = 1; // PHASE_ONLY
        app.open_context_menu_for_pane(FocusPane::Vars, 10, 10);
        let menu = app.context_menu.as_ref().expect("context menu open");
        assert!(menu.items.iter().any(|i| i.label == "Disable Variable" && i.action == ContextAction::ToggleVar));
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(app.context_menu.is_none());
        assert!(!app.data.collections[1].vars[1].enabled);

        // Render and verify checkboxes appear in Vars pane
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen: String = (0..buffer.area.height)
            .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("[✓] MANUAL_VAR"));
        assert!(screen.contains("[ ] PHASE_ONLY"));

        // 4. Disabling phase_prod collection disables ALL its variables regardless of individual states
        app.focus = FocusPane::Collections;
        app.selected_collection = 1;
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(!app.data.collections[1].enabled);
        assert!(app.data.compute_effective_vars().is_empty());

        // Re-enabling phase_prod restores ONLY individually enabled MANUAL_VAR (PHASE_ONLY remains OFF)
        app.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(app.data.collections[1].enabled);
        let eff_re = app.data.compute_effective_vars();
        assert_eq!(eff_re.len(), 1);
        assert_eq!(eff_re[0].key, "MANUAL_VAR");
    }
}
