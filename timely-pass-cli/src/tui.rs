use anyhow::Result;
use arboard::Clipboard;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap, Tabs},
    Frame, Terminal,
};
use std::{io, path::PathBuf, time::{Duration, Instant}};
use timely_pass_sdk::store::{Credential, SecretStore, SecretType, AuditEntry};
use timely_pass_sdk::policy::{Policy, Hook, Period};
use timely_pass_sdk::crypto::generate_random_bytes;
use crate::commands::{prompt_passphrase, open_store_helper};
use chrono::Utc;

// --- States ---

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Credentials,
    Policies,
    Audit,
}

enum AppMode {
    Normal,
    Search,
    Add(AddState),
    Rotate(RotateState),
    Delete(String), // ID to delete
    PolicyWizard(PolicyWizardState),
    PolicyDelete(String),
}

struct PolicyWizardState {
    id: String,
    timezone: String,
    clock_skew: String,
    max_attempts: String,
    single_use: bool,
    enabled: bool,
    hooks: Vec<Hook>,
    selected_hook_index: usize,
    focus: PolicyWizardFocus,
    // Hook creation state
    hook_wizard: Option<HookWizardState>,
}

impl Default for PolicyWizardState {
    fn default() -> Self {
        Self {
            id: String::new(),
            timezone: "UTC".to_string(),
            clock_skew: "0".to_string(),
            max_attempts: "".to_string(),
            single_use: false,
            enabled: true,
            hooks: Vec::new(),
            selected_hook_index: 0,
            focus: PolicyWizardFocus::Id,
            hook_wizard: None,
        }
    }
}

enum PolicyWizardFocus {
    Id,
    Timezone,
    ClockSkew,
    MaxAttempts,
    SingleUse,
    Enabled,
    HooksList,
    AddHookBtn,
    SaveBtn,
}

struct HookWizardState {
    hook_type: HookType,
    start_time: String,
    end_time: String,
    duration: String,
    focus: HookWizardFocus,
}

impl Default for HookWizardState {
    fn default() -> Self {
        Self {
            hook_type: HookType::OnlyBefore,
            start_time: "".to_string(),
            end_time: "".to_string(),
            duration: "0".to_string(),
            focus: HookWizardFocus::Type,
        }
    }
}

enum HookWizardFocus {
    Type,
    StartTime,
    EndTime,
    Duration,
    SaveBtn,
    CancelBtn,
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum HookType {
    OnlyBefore,
    OnlyAfter,
    OnlyWithin,
    OnlyFor,
}

struct AddState {
    id: String,
    secret: String,
    secret_type: SecretType,
    focus: AddFocus,
}

impl Default for AddState {
    fn default() -> Self {
        Self {
            id: String::new(),
            secret: String::new(),
            secret_type: SecretType::Password,
            focus: AddFocus::Id,
        }
    }
}

enum AddFocus {
    Id,
    Type,
    Secret,
}

struct RotateState {
    id: String,
    secret: String,
}

struct App {
    store: SecretStore,
    all_items: Vec<String>,
    filtered_items: Vec<String>,
    state: ListState,
    should_quit: bool,
    selected_cred: Option<Credential>,
    selected_policy: Option<Policy>,
    selected_audit_entry: Option<AuditEntry>,
    
    // Search
    search_query: String,
    
    // Modes
    mode: AppMode,
    tab: Tab,
    
    // Secret Visibility
    show_secret: bool,
    clipboard: Option<Clipboard>,
    
    // Status
    status_message: Option<String>,
    status_time: Option<Instant>,
}

impl App {
    fn new(store: SecretStore) -> App {
        let mut app = App {
            store,
            all_items: Vec::new(),
            filtered_items: Vec::new(),
            state: ListState::default(),
            should_quit: false,
            selected_cred: None,
            selected_policy: None,
            selected_audit_entry: None,
            search_query: String::new(),
            mode: AppMode::Normal,
            tab: Tab::Credentials,
            show_secret: false,
            clipboard: Clipboard::new().ok(),
            status_message: None,
            status_time: None,
        };
        app.refresh_list();
        app
    }
    
    fn refresh_list(&mut self) {
        let items: Vec<String> = match self.tab {
            Tab::Credentials => {
                let mut ids: Vec<String> = self.store.list_credentials().into_iter().map(|c| c.id.clone()).collect();
                ids.sort();
                ids
            },
            Tab::Policies => {
                let mut ids: Vec<String> = self.store.list_policies().into_iter().map(|p| p.id.clone()).collect();
                ids.sort();
                ids
            },
            Tab::Audit => {
                // For audit, we might want to show latest first
                self.store.get_audit_logs().iter().rev().take(100).map(|l| {
                    format!("[{}] {} {} ({})", l.timestamp.format("%Y-%m-%d %H:%M:%S"), l.action, l.target_id, l.details)
                }).collect()
            }
        };
        
        self.all_items = items;
        self.update_filter();
    }
    
    pub fn set_status(&mut self, msg: &str) {
        self.status_message = Some(msg.to_string());
        self.status_time = Some(Instant::now());
    }
    
    pub fn update_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_items = self.all_items.clone();
        } else {
            let query = self.search_query.to_lowercase();
            self.filtered_items = self.all_items
                .iter()
                .filter(|id| id.to_lowercase().contains(&query))
                .cloned()
                .collect();
        }
        
        // Reset selection if invalid
        if self.filtered_items.is_empty() {
            self.state.select(None);
            self.selected_cred = None;
        } else {
            // Try to keep selection or select first
            if let Some(selected_idx) = self.state.selected() {
                 if selected_idx >= self.filtered_items.len() {
                      self.state.select(Some(0));
                 }
            } else {
                self.state.select(Some(0));
            }
            self.update_selection();
        }
    }
    
    pub fn on_down(&mut self) {
        if self.filtered_items.is_empty() { return; }
        
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.filtered_items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.update_selection();
    }

    pub fn on_up(&mut self) {
        if self.filtered_items.is_empty() { return; }

        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.update_selection();
    }
    
    pub fn on_home(&mut self) {
        if !self.filtered_items.is_empty() {
            self.state.select(Some(0));
            self.update_selection();
        }
    }
    
    pub fn on_end(&mut self) {
        if !self.filtered_items.is_empty() {
            self.state.select(Some(self.filtered_items.len() - 1));
            self.update_selection();
        }
    }
    
    fn update_selection(&mut self) {
        if let Some(i) = self.state.selected() {
            if let Some(id) = self.filtered_items.get(i) {
                match self.tab {
                    Tab::Credentials => {
                        self.selected_cred = self.store.get_credential(id).cloned();
                        self.show_secret = false;
                    },
                    Tab::Policies => {
                        self.selected_policy = self.store.get_policy(id).cloned();
                    },
                    Tab::Audit => {
                        if self.search_query.is_empty() {
                            let logs = self.store.get_audit_logs();
                            // filtered_items corresponds to reversed logs (up to 100)
                            if i < logs.len() {
                                let idx = logs.len() - 1 - i;
                                self.selected_audit_entry = logs.get(idx).cloned();
                            }
                        } else {
                            self.selected_audit_entry = None;
                        }
                    }
                }
            }
        } else {
            self.selected_cred = None;
            self.selected_policy = None;
            self.selected_audit_entry = None;
        }
    }
    
    pub fn copy_secret(&mut self) {
        let (secret_data, cred_id) = if let Some(cred) = &self.selected_cred {
             (cred.secret.data.clone(), cred.id.clone())
        } else {
             return;
        };

        if let Some(cb) = &mut self.clipboard {
            let content = match String::from_utf8(secret_data.clone()) {
                Ok(s) => s,
                Err(_) => hex::encode(&secret_data),
            };
            
            if let Err(e) = cb.set_text(content) {
                self.set_status(&format!("Clipboard error: {}", e));
            } else {
                self.set_status("Secret copied to clipboard!");
                
                if let Err(e) = self.store.increment_usage(&cred_id) {
                     self.set_status(&format!("Error updating usage: {}", e));
                } else {
                     self.selected_cred = self.store.get_credential(&cred_id).cloned();
                }
            }
        } else {
            self.set_status("Clipboard not available");
        }
    }
    
    pub fn toggle_secret(&mut self) {
        self.show_secret = !self.show_secret;
        if self.show_secret {
             let cred_id = if let Some(cred) = &self.selected_cred {
                 Some(cred.id.clone())
             } else {
                 None
             };

             if let Some(id) = cred_id {
                 if let Err(e) = self.store.increment_usage(&id) {
                      self.set_status(&format!("Error updating usage: {}", e));
                 } else {
                     self.selected_cred = self.store.get_credential(&id).cloned();
                 }
             }
        }
    }

    // --- Actions ---

    fn delete_current(&mut self) {
        if let Some(cred) = &self.selected_cred {
            self.mode = AppMode::Delete(cred.id.clone());
        }
    }

    fn confirm_delete(&mut self) {
        if let AppMode::Delete(id) = &self.mode {
            if let Err(e) = self.store.remove_credential(id) {
                self.set_status(&format!("Error removing credential: {}", e));
            } else {
                self.set_status(&format!("Credential '{}' removed.", id));
                self.refresh_list();
            }
        }
        self.mode = AppMode::Normal;
    }

    fn start_add(&mut self) {
        self.mode = AppMode::Add(AddState::default());
    }

    fn confirm_add(&mut self) {
        if let AppMode::Add(state) = &self.mode {
            if state.id.is_empty() {
                self.set_status("ID cannot be empty");
                return;
            }
            
            let secret_bytes = if state.secret.is_empty() {
                generate_random_bytes(32)
            } else {
                state.secret.as_bytes().to_vec()
            };

            let cred = Credential::new(state.id.clone(), state.secret_type.clone(), secret_bytes);
            if let Err(e) = self.store.add_credential(cred) {
                self.set_status(&format!("Error adding credential: {}", e));
            } else {
                self.set_status(&format!("Credential '{}' added.", state.id));
                self.refresh_list();
                self.mode = AppMode::Normal;
            }
        }
    }
    
    fn start_rotate(&mut self) {
        if let Some(cred) = &self.selected_cred {
            self.mode = AppMode::Rotate(RotateState {
                id: cred.id.clone(),
                secret: String::new(),
            });
        }
    }

    fn confirm_rotate(&mut self) {
        if let AppMode::Rotate(state) = &self.mode {
            let new_secret_bytes = if state.secret.is_empty() {
                generate_random_bytes(32)
            } else {
                state.secret.as_bytes().to_vec()
            };

            if let Some(mut cred) = self.store.get_credential(&state.id).cloned() {
                cred.secret.data = new_secret_bytes;
                cred.updated_at = Utc::now();
                
                if let Err(e) = self.store.add_credential(cred) {
                     self.set_status(&format!("Error rotating credential: {}", e));
                } else {
                     self.set_status(&format!("Credential '{}' rotated.", state.id));
                     self.refresh_list();
                }
            } else {
                self.set_status("Credential not found during rotate");
            }
        }
        self.mode = AppMode::Normal;
    }

    fn switch_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.search_query.clear();
        self.state.select(None);
        self.refresh_list();
    }

    fn start_add_policy(&mut self) {
        self.mode = AppMode::PolicyWizard(PolicyWizardState::default());
    }

    fn start_edit_policy(&mut self) {
        if let Some(policy) = &self.selected_policy {
             let state = PolicyWizardState {
                 id: policy.id.clone(),
                 timezone: policy.timezone.clone().unwrap_or_default(),
                 clock_skew: policy.clock_skew_secs.to_string(),
                 max_attempts: policy.max_attempts.map(|n| n.to_string()).unwrap_or_default(),
                 single_use: policy.single_use,
                 enabled: policy.enabled,
                 hooks: policy.hooks.clone(),
                 selected_hook_index: 0,
                 focus: PolicyWizardFocus::Id,
                 hook_wizard: None,
             };
             self.mode = AppMode::PolicyWizard(state);
        }
    }

    fn delete_current_policy(&mut self) {
        if let Some(policy) = &self.selected_policy {
            self.mode = AppMode::PolicyDelete(policy.id.clone());
        }
    }
    
    fn toggle_policy_enabled(&mut self) {
        if let Some(mut policy) = self.selected_policy.clone() {
            policy.enabled = !policy.enabled;
            policy.version += 1;
            
            if let Err(e) = self.store.add_policy(policy.clone()) {
                self.set_status(&format!("Error updating policy: {}", e));
            } else {
                let status = if policy.enabled { "enabled" } else { "disabled" };
                self.set_status(&format!("Policy '{}' {}.", policy.id, status));
                self.refresh_list();
            }
        }
    }

    fn confirm_delete_policy(&mut self) {
        if let AppMode::PolicyDelete(id) = &self.mode {
             if let Err(e) = self.store.remove_policy(id) {
                 self.set_status(&format!("Error removing policy: {}", e));
             } else {
                 self.set_status(&format!("Policy '{}' removed.", id));
                 self.refresh_list();
             }
        }
        self.mode = AppMode::Normal;
    }

    fn save_policy_wizard(&mut self) {
        if let AppMode::PolicyWizard(state) = &self.mode {
            if state.id.is_empty() {
                self.set_status("Policy ID cannot be empty");
                return;
            }
            
            let clock_skew = state.clock_skew.parse::<u64>().unwrap_or(0);
            let max_attempts = if state.max_attempts.is_empty() { None } else { state.max_attempts.parse::<u32>().ok() };
            
            let policy = Policy {
                id: state.id.clone(),
                hooks: state.hooks.clone(),
                timezone: if state.timezone.is_empty() { None } else { Some(state.timezone.clone()) },
                clock_skew_secs: clock_skew,
                max_attempts,
                single_use: state.single_use,
                enabled: state.enabled,
                version: 1,
            };
            
            if let Err(e) = self.store.add_policy(policy) {
                self.set_status(&format!("Error saving policy: {}", e));
            } else {
                self.set_status(&format!("Policy '{}' saved.", state.id));
                self.refresh_list();
                self.mode = AppMode::Normal;
            }
        }
    }

    fn export_current(&mut self) {
        let (content, default_name) = match self.tab {
            Tab::Credentials => {
                if let Some(cred) = &self.selected_cred {
                    match serde_json::to_string_pretty(cred) {
                        Ok(s) => (s, format!("{}.json", cred.id)),
                        Err(e) => {
                             self.set_status(&format!("Serialization error: {}", e));
                             return;
                        }
                    }
                } else { return; }
            },
            Tab::Policies => {
                if let Some(policy) = &self.selected_policy {
                    match serde_json::to_string_pretty(policy) {
                        Ok(s) => (s, format!("{}.json", policy.id)),
                        Err(e) => {
                             self.set_status(&format!("Serialization error: {}", e));
                             return;
                        }
                    }
                } else { return; }
            },
            Tab::Audit => {
                match serde_json::to_string_pretty(&self.store.get_audit_logs()) {
                    Ok(s) => (s, "audit_logs.json".to_string()),
                    Err(e) => {
                         self.set_status(&format!("Serialization error: {}", e));
                         return;
                    }
                }
            }
        };

        let path = PathBuf::from(&default_name);
        match std::fs::write(&path, content) {
            Ok(_) => self.set_status(&format!("Exported to {}", default_name)),
            Err(e) => self.set_status(&format!("Export error: {}", e)),
        }
    }

    fn start_add_hook(&mut self) {
        if let AppMode::PolicyWizard(state) = &mut self.mode {
            state.hook_wizard = Some(HookWizardState::default());
        }
    }

    fn cancel_hook_wizard(&mut self) {
        if let AppMode::PolicyWizard(state) = &mut self.mode {
            state.hook_wizard = None;
        }
    }

    fn save_hook_wizard(&mut self) {
        if let AppMode::PolicyWizard(state) = &mut self.mode {
            if let Some(hook_wizard) = &state.hook_wizard {
                // Helper to parse time
                let parse_time = |s: &str| -> Option<chrono::DateTime<Utc>> {
                    if s.is_empty() { return None; }
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                };

                let start = parse_time(&hook_wizard.start_time);
                let end = parse_time(&hook_wizard.end_time);
                let duration = hook_wizard.duration.parse::<u64>().unwrap_or(0);

                let hook = match hook_wizard.hook_type {
                    HookType::OnlyBefore => {
                         // Expects deadline (end_time)
                         if let Some(deadline) = end.or(start) {
                             Some(Hook::OnlyBefore { period: Period::Instant { value: deadline } })
                         } else { None }
                    },
                    HookType::OnlyAfter => {
                         // Expects start time
                         if let Some(start_time) = start {
                             Some(Hook::OnlyAfter { period: Period::Instant { value: start_time } })
                         } else { None }
                    },
                    HookType::OnlyWithin => {
                         // Expects start and end
                         if let (Some(s), Some(e)) = (start, end) {
                             Some(Hook::OnlyWithin { period: Period::Range { start: s, end: e } })
                         } else { None }
                    },
                    HookType::OnlyFor => {
                         // Expects duration
                         if duration > 0 {
                             Some(Hook::OnlyFor { duration_secs: duration })
                         } else { None }
                    },
                };
                
                if let Some(h) = hook {
                    state.hooks.push(h);
                    if !state.hooks.is_empty() {
                        state.selected_hook_index = state.hooks.len() - 1;
                    }
                    state.hook_wizard = None;
                } else {
                    // Could set error status here, but for now just don't close if invalid
                    self.set_status("Invalid hook parameters (check date format RFC3339)");
                }
            }
        }
    }
}

pub async fn run(store_path: PathBuf) -> Result<()> {
    println!("Initializing TUI...");
    let passphrase = prompt_passphrase(false)?;
    let store = open_store_helper(&store_path, &passphrase)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(store);
    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match &mut app.mode {
                        AppMode::Normal => {
                             match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                                KeyCode::Char('j') | KeyCode::Down => app.on_down(),
                                KeyCode::Char('k') | KeyCode::Up => app.on_up(),
                                KeyCode::Home => app.on_home(),
                                KeyCode::End => app.on_end(),
                                KeyCode::Char('/') => {
                                    app.mode = AppMode::Search;
                                    app.status_message = None;
                                }
                                KeyCode::Char('1') => app.switch_tab(Tab::Credentials),
                                KeyCode::Char('2') => app.switch_tab(Tab::Policies),
                                KeyCode::Char('3') => app.switch_tab(Tab::Audit),

                                KeyCode::Char('c') => if app.tab == Tab::Credentials { app.copy_secret() },
                                
                                KeyCode::Char('a') => {
                                    match app.tab {
                                        Tab::Credentials => app.start_add(),
                                        Tab::Policies => app.start_add_policy(),
                                        _ => {}
                                    }
                                },
                                KeyCode::Char('d') | KeyCode::Delete => {
                                    match app.tab {
                                        Tab::Credentials => app.delete_current(),
                                        Tab::Policies => app.delete_current_policy(),
                                        _ => {}
                                    }
                                },
                                KeyCode::Char('e') => {
                                    if app.tab == Tab::Policies {
                                        app.toggle_policy_enabled();
                                    }
                                },
                                KeyCode::Char('E') => app.export_current(),
                                KeyCode::Char('r') => if app.tab == Tab::Credentials { app.start_rotate() },
                                KeyCode::Enter => {
                                    match app.tab {
                                        Tab::Credentials => app.toggle_secret(),
                                        Tab::Policies => app.start_edit_policy(),
                                        _ => {}
                                    }
                                },
                                _ => {}
                            }
                        },
                        AppMode::Search => {
                            match key.code {
                                KeyCode::Esc => {
                                    app.mode = AppMode::Normal;
                                    app.search_query.clear();
                                    app.update_filter();
                                }
                                KeyCode::Enter => {
                                    app.mode = AppMode::Normal;
                                }
                                KeyCode::Backspace => {
                                    app.search_query.pop();
                                    app.update_filter();
                                }
                                KeyCode::Char(c) => {
                                    app.search_query.push(c);
                                    app.update_filter();
                                }
                                _ => {}
                            }
                        },
                        AppMode::Delete(_) => {
                            match key.code {
                                KeyCode::Char('y') | KeyCode::Enter => app.confirm_delete(),
                                KeyCode::Char('n') | KeyCode::Esc => app.mode = AppMode::Normal,
                                _ => {}
                            }
                        },
                        AppMode::PolicyDelete(_) => {
                            match key.code {
                                KeyCode::Char('y') | KeyCode::Enter => app.confirm_delete_policy(),
                                KeyCode::Char('n') | KeyCode::Esc => app.mode = AppMode::Normal,
                                _ => {}
                            }
                        },
                        AppMode::Add(state) => {
                             match key.code {
                                KeyCode::Esc => app.mode = AppMode::Normal,
                                KeyCode::Tab => {
                                    state.focus = match state.focus {
                                        AddFocus::Id => AddFocus::Type,
                                        AddFocus::Type => AddFocus::Secret,
                                        AddFocus::Secret => AddFocus::Id,
                                    }
                                },
                                KeyCode::Enter => {
                                    app.confirm_add();
                                },
                                KeyCode::Backspace => {
                                    match state.focus {
                                        AddFocus::Id => { state.id.pop(); },
                                        AddFocus::Secret => { state.secret.pop(); },
                                        _ => {}
                                    }
                                },
                                KeyCode::Left | KeyCode::Right => {
                                    if let AddFocus::Type = state.focus {
                                        state.secret_type = match state.secret_type {
                                            SecretType::Password => SecretType::Key,
                                            SecretType::Key => SecretType::Token,
                                            SecretType::Token => SecretType::Password,
                                        };
                                    }
                                },
                                KeyCode::Char(c) => {
                                    match state.focus {
                                        AddFocus::Id => state.id.push(c),
                                        AddFocus::Secret => state.secret.push(c),
                                        _ => {}
                                    }
                                }
                                _ => {}
                             }
                        },
                        AppMode::Rotate(state) => {
                            match key.code {
                                KeyCode::Esc => app.mode = AppMode::Normal,
                                KeyCode::Enter => app.confirm_rotate(),
                                KeyCode::Backspace => { state.secret.pop(); },
                                KeyCode::Char(c) => state.secret.push(c),
                                _ => {}
                            }
                        },
                        AppMode::PolicyWizard(state) => {
                            if let Some(hook_wizard) = &mut state.hook_wizard {
                                // --- Hook Wizard Input ---
                                match key.code {
                                    KeyCode::Esc => app.cancel_hook_wizard(),
                                    KeyCode::Tab => {
                                        hook_wizard.focus = match hook_wizard.focus {
                                            HookWizardFocus::Type => HookWizardFocus::StartTime,
                                            HookWizardFocus::StartTime => HookWizardFocus::EndTime,
                                            HookWizardFocus::EndTime => HookWizardFocus::Duration,
                                            HookWizardFocus::Duration => HookWizardFocus::SaveBtn,
                                            HookWizardFocus::SaveBtn => HookWizardFocus::CancelBtn,
                                            HookWizardFocus::CancelBtn => HookWizardFocus::Type,
                                        }
                                    },
                                    KeyCode::Enter => {
                                        match hook_wizard.focus {
                                            HookWizardFocus::SaveBtn => app.save_hook_wizard(),
                                            HookWizardFocus::CancelBtn => app.cancel_hook_wizard(),
                                            _ => {}
                                        }
                                    },
                                    KeyCode::Left | KeyCode::Right => {
                                        if let HookWizardFocus::Type = hook_wizard.focus {
                                            hook_wizard.hook_type = match hook_wizard.hook_type {
                                                HookType::OnlyBefore => HookType::OnlyAfter,
                                                HookType::OnlyAfter => HookType::OnlyWithin,
                                                HookType::OnlyWithin => HookType::OnlyFor,
                                                HookType::OnlyFor => HookType::OnlyBefore,
                                            };
                                        }
                                    },
                                    KeyCode::Backspace => {
                                        match hook_wizard.focus {
                                            HookWizardFocus::StartTime => { hook_wizard.start_time.pop(); },
                                            HookWizardFocus::EndTime => { hook_wizard.end_time.pop(); },
                                            HookWizardFocus::Duration => { hook_wizard.duration.pop(); },
                                            _ => {}
                                        }
                                    },
                                    KeyCode::Char(c) => {
                                        match hook_wizard.focus {
                                            HookWizardFocus::StartTime => hook_wizard.start_time.push(c),
                                            HookWizardFocus::EndTime => hook_wizard.end_time.push(c),
                                            HookWizardFocus::Duration => hook_wizard.duration.push(c),
                                            _ => {}
                                        }
                                    },
                                    _ => {}
                                }
                            } else {
                                 // --- Policy Wizard Input ---
                                 match key.code {
                                     KeyCode::Esc => app.mode = AppMode::Normal,
                                     KeyCode::Tab => {
                                         state.focus = match state.focus {
                                             PolicyWizardFocus::Id => PolicyWizardFocus::Timezone,
                                             PolicyWizardFocus::Timezone => PolicyWizardFocus::ClockSkew,
                                             PolicyWizardFocus::ClockSkew => PolicyWizardFocus::MaxAttempts,
                                             PolicyWizardFocus::MaxAttempts => PolicyWizardFocus::SingleUse,
                                             PolicyWizardFocus::SingleUse => PolicyWizardFocus::Enabled,
                                             PolicyWizardFocus::Enabled => PolicyWizardFocus::HooksList,
                                             PolicyWizardFocus::HooksList => PolicyWizardFocus::AddHookBtn,
                                             PolicyWizardFocus::AddHookBtn => PolicyWizardFocus::SaveBtn,
                                             PolicyWizardFocus::SaveBtn => PolicyWizardFocus::Id,
                                         }
                                     },
                                     KeyCode::Enter => {
                                         match state.focus {
                                             PolicyWizardFocus::SaveBtn => app.save_policy_wizard(),
                                             PolicyWizardFocus::SingleUse => state.single_use = !state.single_use,
                                             PolicyWizardFocus::Enabled => state.enabled = !state.enabled,
                                             PolicyWizardFocus::AddHookBtn => app.start_add_hook(),
                                             _ => {}
                                         }
                                     },
                                     KeyCode::Up => {
                                         if let PolicyWizardFocus::HooksList = state.focus {
                                             if state.selected_hook_index > 0 {
                                                 state.selected_hook_index -= 1;
                                             }
                                         }
                                     },
                                     KeyCode::Down => {
                                         if let PolicyWizardFocus::HooksList = state.focus {
                                             if !state.hooks.is_empty() && state.selected_hook_index < state.hooks.len() - 1 {
                                                 state.selected_hook_index += 1;
                                             }
                                         }
                                     },
                                     KeyCode::Backspace => {
                                         match state.focus {
                                             PolicyWizardFocus::Id => { state.id.pop(); },
                                             PolicyWizardFocus::Timezone => { state.timezone.pop(); },
                                             PolicyWizardFocus::ClockSkew => { state.clock_skew.pop(); },
                                             PolicyWizardFocus::MaxAttempts => { state.max_attempts.pop(); },
                                             PolicyWizardFocus::HooksList => {
                                                 if !state.hooks.is_empty() && state.selected_hook_index < state.hooks.len() {
                                                     state.hooks.remove(state.selected_hook_index);
                                                     if state.selected_hook_index >= state.hooks.len() && !state.hooks.is_empty() {
                                                         state.selected_hook_index = state.hooks.len() - 1;
                                                     }
                                                 }
                                             },
                                             _ => {}
                                         }
                                     },
                                     KeyCode::Char(c) => {
                                         match state.focus {
                                             PolicyWizardFocus::Id => state.id.push(c),
                                             PolicyWizardFocus::Timezone => state.timezone.push(c),
                                             PolicyWizardFocus::ClockSkew => state.clock_skew.push(c),
                                             PolicyWizardFocus::MaxAttempts => state.max_attempts.push(c),
                                             _ => {}
                                         }
                                     }
                                     _ => {}
                                 }
                             }
                        }
                    }
                }
            }
        }
        
        if let Some(time) = app.status_time {
            if time.elapsed() > Duration::from_secs(3) {
                app.status_message = None;
                app.status_time = None;
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // Header (Tabs)
                Constraint::Min(0),    // Main Content
                Constraint::Length(1), // Footer
            ]
            .as_ref(),
        )
        .split(size);

    // --- Header (Tabs) ---
    let titles = vec!["Credentials (1)", "Policies (2)", "Audit (3)"];
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Timely Pass"))
        .select(match app.tab {
            Tab::Credentials => 0,
            Tab::Policies => 1,
            Tab::Audit => 2,
        })
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    // --- Main Content ---
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(chunks[1]);

    // List View (Left)
    let list_title = match app.tab {
        Tab::Credentials => "Credentials",
        Tab::Policies => "Policies",
        Tab::Audit => "Audit Log",
    };
    
    let items: Vec<ListItem> = app
        .filtered_items
        .iter()
        .map(|i| {
            ListItem::new(Line::from(vec![Span::raw(i)]))
        })
        .collect();
        
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(list_title))
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.state);

    // Detail View (Right)
    let detail_block = Block::default().borders(Borders::ALL).title("Details");
    match app.tab {
        Tab::Credentials => {
            let detail_text = if let Some(cred) = &app.selected_cred {
                let created = cred.created_at.to_rfc3339();
                let updated = cred.updated_at.to_rfc3339();
                let type_str = format!("{:?}", cred.secret.type_);
                let policy_str = cred.policy_id.clone().unwrap_or_else(|| "None".to_string());
                let counter = cred.usage_counter;
                
                let secret_display = if app.show_secret {
                    match String::from_utf8(cred.secret.data.clone()) {
                        Ok(s) => s,
                        Err(_) => format!("(Binary Data: {} bytes)", cred.secret.data.len()),
                    }
                } else {
                    "****************".to_string()
                };
                
                let secret_color = if app.show_secret { Color::Red } else { Color::DarkGray };
                
                vec![
                    Line::from(vec![Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&cred.id)]),
                    Line::from(""),
                    Line::from(vec![Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(type_str)]),
                    Line::from(vec![Span::styled("Policy: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(policy_str)]),
                    Line::from(vec![Span::styled("Usage Count: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(counter.to_string())]),
                    Line::from(""),
                    Line::from(vec![Span::styled("Created: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(created)]),
                    Line::from(vec![Span::styled("Updated: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(updated)]),
                    Line::from(""),
                    Line::from(vec![Span::styled("Secret: ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(secret_display, Style::default().fg(secret_color))]),
                ]
            } else {
                vec![Line::from("No credential selected")]
            };
            let detail = Paragraph::new(detail_text).block(detail_block).wrap(Wrap { trim: true });
            f.render_widget(detail, main_chunks[1]);
        },
        Tab::Policies => {
            let detail_text = if let Some(policy) = &app.selected_policy {
                 let timezone = policy.timezone.as_deref().unwrap_or("UTC");
                 let max_attempts = policy.max_attempts.map(|n| n.to_string()).unwrap_or_else(|| "Unlimited".to_string());
                 
                 let mut lines = vec![
                    Line::from(vec![Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&policy.id)]),
                    Line::from(vec![Span::styled("Version: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(policy.version.to_string())]),
                    Line::from(vec![Span::styled("Timezone: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(timezone)]),
                    Line::from(vec![Span::styled("Clock Skew: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(format!("{}s", policy.clock_skew_secs))]),
                    Line::from(vec![Span::styled("Max Attempts: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(max_attempts)]),
                    Line::from(vec![Span::styled("Single Use: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(if policy.single_use { "Yes" } else { "No" })]),
                    Line::from(vec![Span::styled("Enabled: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(if policy.enabled { "Yes" } else { "No" })]),
                    Line::from(""),
                    Line::from(Span::styled("Hooks:", Style::default().add_modifier(Modifier::BOLD))),
                 ];
                 
                 if policy.hooks.is_empty() {
                     lines.push(Line::from("  No hooks defined"));
                 } else {
                     for (i, hook) in policy.hooks.iter().enumerate() {
                         lines.push(Line::from(format!("  {}. {:?}", i + 1, hook)));
                     }
                 }
                 lines
            } else {
                vec![Line::from("No policy selected")]
            };
            let detail = Paragraph::new(detail_text).block(detail_block).wrap(Wrap { trim: true });
            f.render_widget(detail, main_chunks[1]);
        },
        Tab::Audit => {
             let detail_text = if let Some(entry) = &app.selected_audit_entry {
                 vec![
                     Line::from(vec![Span::styled("Timestamp: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(entry.timestamp.to_rfc3339())]),
                     Line::from(vec![Span::styled("Action: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&entry.action)]),
                     Line::from(vec![Span::styled("Target Type: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&entry.target_type)]),
                     Line::from(vec![Span::styled("Target ID: ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(&entry.target_id)]),
                     Line::from(""),
                      Line::from(Span::styled("Details:", Style::default().add_modifier(Modifier::BOLD))),
                      Line::from(entry.details.as_str()),
                      Line::from(""),
                      // Hash display removed until implemented
                      // Line::from(Span::styled("Hash:", Style::default().add_modifier(Modifier::BOLD))),
                      // Line::from(entry.hash.as_str()),
                  ]
             } else {
                 vec![Line::from("Select an entry to view details (Search disables detail view)")]
             };
             let detail = Paragraph::new(detail_text).block(detail_block).wrap(Wrap { trim: true });
             f.render_widget(detail, main_chunks[1]);
        }
    }

    // --- Footer ---
    let footer_text = if let Some(msg) = &app.status_message {
        format!("STATUS: {}", msg)
    } else {
        match app.mode {
            AppMode::Normal => match app.tab {
                Tab::Credentials => "q: Quit | a: Add | d: Delete | r: Rotate | /: Search | Enter: Reveal | c: Copy | E: Export".to_string(),
                Tab::Policies => "q: Quit | a: Add | d: Delete | e: En/Dis | Enter: Edit | /: Search | E: Export".to_string(),
                Tab::Audit => "q: Quit | /: Search | E: Export Log".to_string(),
            },
            AppMode::Search => "Esc: Cancel | Enter: Done".to_string(),
            AppMode::Delete(_) => "y: Confirm Delete | n/Esc: Cancel".to_string(),
            AppMode::PolicyDelete(_) => "y: Confirm Delete | n/Esc: Cancel".to_string(),
            AppMode::Add(_) => "Tab: Next | Enter: Save | Esc: Cancel".to_string(),
            AppMode::Rotate(_) => "Enter: Save | Esc: Cancel".to_string(),
            AppMode::PolicyWizard(_) => "Tab: Next | Enter: Action | Esc: Cancel".to_string(),
        }
    };
    
    let footer_style = if app.status_message.is_some() {
        Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    };
    
    let footer = Paragraph::new(footer_text).style(footer_style);
    f.render_widget(footer, chunks[2]);

    // --- Popups ---
    match &app.mode {
        AppMode::Delete(id) => {
             let block = Block::default().title("Confirm Delete").borders(Borders::ALL);
             let area = centered_rect(60, 20, size);
             f.render_widget(Clear, area);
             f.render_widget(block, area);
             let text = Paragraph::new(format!("Are you sure you want to delete credential '{}'?\n\n(y) Yes   (n) No", id))
                .alignment(Alignment::Center).wrap(Wrap { trim: true });
             f.render_widget(text, centered_rect(50, 10, size));
        },
        AppMode::PolicyDelete(id) => {
             let block = Block::default().title("Confirm Policy Delete").borders(Borders::ALL);
             let area = centered_rect(60, 20, size);
             f.render_widget(Clear, area);
             f.render_widget(block, area);
             let text = Paragraph::new(format!("Are you sure you want to delete policy '{}'?\n\n(y) Yes   (n) No", id))
                .alignment(Alignment::Center).wrap(Wrap { trim: true });
             f.render_widget(text, centered_rect(50, 10, size));
        },
        AppMode::Add(state) => {
             let block = Block::default().title("Add Credential").borders(Borders::ALL);
             let area = centered_rect(60, 40, size);
             f.render_widget(Clear, area);
             f.render_widget(block, area);
             let layout = Layout::default().direction(Direction::Vertical).margin(2)
                .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)].as_ref()).split(area);
             let id_style = if let AddFocus::Id = state.focus { Style::default().fg(Color::Yellow) } else { Style::default() };
             let type_style = if let AddFocus::Type = state.focus { Style::default().fg(Color::Yellow) } else { Style::default() };
             let secret_style = if let AddFocus::Secret = state.focus { Style::default().fg(Color::Yellow) } else { Style::default() };
             f.render_widget(Paragraph::new(state.id.as_str()).block(Block::default().borders(Borders::ALL).title("ID")).style(id_style), layout[0]);
             f.render_widget(Paragraph::new(format!("{:?}", state.secret_type)).block(Block::default().borders(Borders::ALL).title("Type (<- ->)")).style(type_style), layout[1]);
             f.render_widget(Paragraph::new(state.secret.as_str()).block(Block::default().borders(Borders::ALL).title("Secret (Empty=Auto)")).style(secret_style), layout[2]);
        },
        AppMode::Rotate(state) => {
             let block = Block::default().title("Rotate Credential").borders(Borders::ALL);
             let area = centered_rect(60, 20, size);
             f.render_widget(Clear, area);
             f.render_widget(block, area);
             let layout = Layout::default().direction(Direction::Vertical).margin(2).constraints([Constraint::Length(3), Constraint::Min(0)].as_ref()).split(area);
             f.render_widget(Paragraph::new(state.secret.as_str()).block(Block::default().borders(Borders::ALL).title("New Secret (Empty=Auto)")).style(Style::default().fg(Color::Yellow)), layout[0]);
        },
        AppMode::PolicyWizard(state) => {
             let block = Block::default().title("Policy Wizard").borders(Borders::ALL);
             let area = centered_rect(80, 80, size);
             f.render_widget(Clear, area);
             f.render_widget(block, area);
             
             let layout = Layout::default().direction(Direction::Vertical).margin(1)
                .constraints([
                    Constraint::Length(3), // ID
                    Constraint::Length(3), // Timezone
                    Constraint::Length(3), // Clock Skew
                    Constraint::Length(3), // Max Attempts
                    Constraint::Length(3), // Single Use
                    Constraint::Length(3), // Enabled
                    Constraint::Min(5),    // Hooks List
                    Constraint::Length(3), // Add Hook Btn
                    Constraint::Length(3), // Save Btn
                ].as_ref()).split(area);
                
             let f_style = |focus: bool| if focus { Style::default().fg(Color::Yellow) } else { Style::default() };
             
             f.render_widget(Paragraph::new(state.id.as_str()).block(Block::default().borders(Borders::ALL).title("Policy ID")).style(f_style(matches!(state.focus, PolicyWizardFocus::Id))), layout[0]);
             f.render_widget(Paragraph::new(state.timezone.as_str()).block(Block::default().borders(Borders::ALL).title("Timezone (e.g. UTC)")).style(f_style(matches!(state.focus, PolicyWizardFocus::Timezone))), layout[1]);
             f.render_widget(Paragraph::new(state.clock_skew.as_str()).block(Block::default().borders(Borders::ALL).title("Clock Skew (secs)")).style(f_style(matches!(state.focus, PolicyWizardFocus::ClockSkew))), layout[2]);
             f.render_widget(Paragraph::new(state.max_attempts.as_str()).block(Block::default().borders(Borders::ALL).title("Max Attempts (Empty=Unlimited)")).style(f_style(matches!(state.focus, PolicyWizardFocus::MaxAttempts))), layout[3]);
             f.render_widget(Paragraph::new(if state.single_use { "Yes" } else { "No" }).block(Block::default().borders(Borders::ALL).title("Single Use (Enter to toggle)")).style(f_style(matches!(state.focus, PolicyWizardFocus::SingleUse))), layout[4]);
             f.render_widget(Paragraph::new(if state.enabled { "Yes" } else { "No" }).block(Block::default().borders(Borders::ALL).title("Enabled (Enter to toggle)")).style(f_style(matches!(state.focus, PolicyWizardFocus::Enabled))), layout[5]);
             
             // Hooks List
             let hooks_items: Vec<ListItem> = state.hooks.iter().enumerate().map(|(i, h)| {
                 let content = format!("{}. {:?}", i + 1, h);
                 let style = if i == state.selected_hook_index {
                     Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                 } else {
                     Style::default()
                 };
                 ListItem::new(content).style(style)
             }).collect();
             let hooks_list = List::new(hooks_items)
                .block(Block::default().borders(Borders::ALL).title("Hooks (Backspace to delete selected)"))
                .style(f_style(matches!(state.focus, PolicyWizardFocus::HooksList)));
             f.render_widget(hooks_list, layout[6]);

             let add_hook_style = if matches!(state.focus, PolicyWizardFocus::AddHookBtn) { Style::default().bg(Color::Yellow).fg(Color::Black) } else { Style::default() };
             f.render_widget(Paragraph::new(" [ ADD HOOK ] ").alignment(Alignment::Center).style(add_hook_style), layout[7]);

             let btn_style = if matches!(state.focus, PolicyWizardFocus::SaveBtn) { Style::default().bg(Color::Yellow).fg(Color::Black) } else { Style::default() };
             f.render_widget(Paragraph::new(" [ SAVE POLICY ] ").alignment(Alignment::Center).style(btn_style), layout[8]);

             // Hook Wizard Popup
             if let Some(hook_wizard) = &state.hook_wizard {
                 let hw_area = centered_rect(60, 60, size);
                 f.render_widget(Clear, hw_area);
                 f.render_widget(Block::default().title("Add Hook").borders(Borders::ALL), hw_area);
                 
                 let hw_layout = Layout::default().direction(Direction::Vertical).margin(1)
                    .constraints([
                        Constraint::Length(3), // Type
                        Constraint::Length(3), // Start
                        Constraint::Length(3), // End
                        Constraint::Length(3), // Duration
                        Constraint::Length(3), // Save
                        Constraint::Length(3), // Cancel
                    ].as_ref()).split(hw_area);

                 let hw_style = |focus: bool| if focus { Style::default().fg(Color::Yellow) } else { Style::default() };

                 f.render_widget(Paragraph::new(format!("{:?}", hook_wizard.hook_type)).block(Block::default().borders(Borders::ALL).title("Type (<- ->)")).style(hw_style(matches!(hook_wizard.focus, HookWizardFocus::Type))), hw_layout[0]);
                 f.render_widget(Paragraph::new(hook_wizard.start_time.as_str()).block(Block::default().borders(Borders::ALL).title("Start Time (RFC3339/Empty)")).style(hw_style(matches!(hook_wizard.focus, HookWizardFocus::StartTime))), hw_layout[1]);
                 f.render_widget(Paragraph::new(hook_wizard.end_time.as_str()).block(Block::default().borders(Borders::ALL).title("End Time (RFC3339/Empty)")).style(hw_style(matches!(hook_wizard.focus, HookWizardFocus::EndTime))), hw_layout[2]);
                 f.render_widget(Paragraph::new(hook_wizard.duration.as_str()).block(Block::default().borders(Borders::ALL).title("Duration Secs (0=None)")).style(hw_style(matches!(hook_wizard.focus, HookWizardFocus::Duration))), hw_layout[3]);
                 
                 let save_style = if matches!(hook_wizard.focus, HookWizardFocus::SaveBtn) { Style::default().bg(Color::Yellow).fg(Color::Black) } else { Style::default() };
                 f.render_widget(Paragraph::new(" [ ADD ] ").alignment(Alignment::Center).style(save_style), hw_layout[4]);

                 let cancel_style = if matches!(hook_wizard.focus, HookWizardFocus::CancelBtn) { Style::default().bg(Color::Red).fg(Color::White) } else { Style::default() };
                 f.render_widget(Paragraph::new(" [ CANCEL ] ").alignment(Alignment::Center).style(cancel_style), hw_layout[5]);
             }
        },
        _ => {}
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1]);

    layout[1]
}
