//! AgentGuard TUI — Terminal User Interface.
//!
//! Dashboard interactivo basado en ratatui + crossterm.
//! Se comunica con el daemon vía IPC Unix socket.
//!
//! Controles: 1-4 tabs, q quit, r refresh.

mod app;
mod ipc;
mod theme;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    Frame, Terminal,
};

use app::{AppState, Tab};
use ipc::IpcClient;

#[derive(Debug)]
struct Args {
    socket: Option<PathBuf>,
}

impl Args {
    fn parse() -> Self {
        let mut socket = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-s" | "--socket" => socket = args.next().map(PathBuf::from),
                _ => {}
            }
        }
        Self { socket }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let socket_path = args.socket.unwrap_or_else(ipc::default_socket_path);

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let client = IpcClient::new(socket_path);
    let mut state = AppState::new();

    // Initial data fetch
    state.refresh(&client);

    // Main render loop
    let res = run_loop(&mut terminal, &mut state, &client);

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res?;
    Ok(())
}

fn run_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &mut AppState,
    client: &IpcClient,
) -> Result<()> {
    let tick_rate = Duration::from_millis(250);
    let refresh_rate = Duration::from_secs(5);
    let mut last_refresh = std::time::Instant::now();

    loop {
        terminal.draw(|f| render_frame(f, state))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('1') => state.current_tab = Tab::Dashboard,
                        KeyCode::Char('2') => state.current_tab = Tab::Zones,
                        KeyCode::Char('3') => state.current_tab = Tab::Incidents,
                        KeyCode::Char('4') => state.current_tab = Tab::Snapshots,
                        KeyCode::Char('r') => {
                            state.refresh(client);
                            state.set_status("Data refreshed".into());
                        }
                        KeyCode::Tab => {
                            let idx = state.current_tab.clone() as usize;
                            let next = (idx + 1) % Tab::all().len();
                            state.current_tab = Tab::all()[next].clone();
                        }
                        KeyCode::Char('p') => {
                            match client.pause(30) {
                                Ok(()) => state.set_status("Protection paused for 30 min".into()),
                                Err(e) => state.set_error(format!("Pause failed: {e}")),
                            }
                            state.refresh(client);
                        }
                        KeyCode::Right | KeyCode::Char('n') => {
                            let idx = state.current_tab.clone() as usize;
                            let next = (idx + 1) % Tab::all().len();
                            state.current_tab = Tab::all()[next].clone();
                        }
                        KeyCode::Left => {
                            let idx = state.current_tab.clone() as usize;
                            let prev = if idx == 0 {
                                Tab::all().len() - 1
                            } else {
                                idx - 1
                            };
                            state.current_tab = Tab::all()[prev].clone();
                        }
                        _ => {}
                    }
                }
            }
        }

        // Auto-refresh each 5s
        if last_refresh.elapsed() >= refresh_rate {
            state.refresh(client);
            last_refresh = std::time::Instant::now();
        }
    }
}

fn render_frame(f: &mut Frame, state: &AppState) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tabs
            Constraint::Min(1),    // content
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    ui::render_tabs(f, state, main_chunks[0]);
    ui::render_tab(f, state, main_chunks[1]);
    ui::render_status_bar(f, state, main_chunks[2]);
}
