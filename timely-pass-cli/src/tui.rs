use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{io, path::PathBuf, time::Duration};
use timely_pass_sdk::store::{Credential, SecretStore};
use crate::commands::{prompt_passphrase, open_store_helper};

struct App {
    store: SecretStore,
    items: Vec<String>,
    state: ListState,
    should_quit: bool,
    selected_cred: Option<Credential>,
}

impl App {
    fn new(store: SecretStore) -> App {
        let mut items: Vec<String> = store.list_credentials().into_iter().map(|c| c.id.clone()).collect();
        items.sort(); // Sort alphabetically
        
        let mut state = ListState::default();
        if !items.is_empty() {
            state.select(Some(0));
        }
        
        let selected_cred = if !items.is_empty() {
            store.get_credential(&items[0]).cloned()
        } else {
            None
        };

        App {
            store,
            items,
            state,
            should_quit: false,
            selected_cred,
        }
    }
    
    pub fn on_down(&mut self) {
        if self.items.is_empty() { return; }
        
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
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
        if self.items.is_empty() { return; }

        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.update_selection();
    }
    
    fn update_selection(&mut self) {
        if let Some(i) = self.state.selected() {
            if let Some(id) = self.items.get(i) {
                self.selected_cred = self.store.get_credential(id).cloned();
            }
        }
    }
}

pub async fn run(store_path: PathBuf) -> Result<()> {
    // 1. Initialize store (prompt for password first, outside TUI)
    println!("Initializing TUI...");
    let passphrase = prompt_passphrase(false)?;
    let store = open_store_helper(&store_path, &passphrase)?;

    // 2. Setup Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 3. Create App
    let mut app = App::new(store);

    // 4. Run Loop
    let res = run_app(&mut terminal, &mut app);

    // 5. Restore Terminal
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

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Char('j') | KeyCode::Down => app.on_down(),
                        KeyCode::Char('k') | KeyCode::Up => app.on_up(),
                        _ => {}
                    }
                }
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
                Constraint::Length(3), // Title
                Constraint::Min(0),    // Main content
                Constraint::Length(1), // Footer
            ]
            .as_ref(),
        )
        .split(size);

    let title = Paragraph::new("Timely Pass - Secure Time-Based Store")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);
    
    // Main Content: Split into List and Details
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(chunks[1]);
        
    // Left: Credential List
    let items: Vec<ListItem> = app
        .items
        .iter()
        .map(|i| {
            ListItem::new(Line::from(vec![Span::raw(i)]))
        })
        .collect();
        
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Credentials"))
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.state);
    
    // Right: Details
    let detail_text = if let Some(cred) = &app.selected_cred {
        let created = cred.created_at.to_rfc3339();
        let updated = cred.updated_at.to_rfc3339();
        let type_str = format!("{:?}", cred.secret.type_);
        let policy_str = cred.policy_id.clone().unwrap_or_else(|| "None".to_string());
        let counter = cred.usage_counter;
        
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
            Line::from(vec![Span::styled("Press 'Enter' to reveal secret (Not Implemented)", Style::default().fg(Color::DarkGray))]),
        ]
    } else {
        vec![Line::from("No credential selected")]
    };
    
    let detail = Paragraph::new(detail_text)
        .block(Block::default().borders(Borders::ALL).title("Details"))
        .wrap(Wrap { trim: true });
    f.render_widget(detail, main_chunks[1]);
    
    // Footer
    let footer = Paragraph::new("q: Quit | j/k: Navigate | Esc: Quit")
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(footer, chunks[2]);
}
