use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use termion::event::Key;
use termion::input::{MouseTerminal, TermRead};
use termion::raw::IntoRawMode;
use termion::screen::AlternateScreen;
use tui::backend::{Backend, TermionBackend};
use tui::layout::{Alignment, Constraint, Corner, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::widgets::{Block, Borders, List, Paragraph, SelectableList, Tabs, Text, Widget};
use tui::{Frame, Terminal};

use crate::utils::printer::Printable;
use crate::utils::rpc_client::HttpRpcClient;

pub struct TuiSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> TuiSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> TuiSubCommand<'a> {
        TuiSubCommand { rpc_client }
    }

    pub fn start(self) -> Result<Box<dyn Printable>, String> {
        let stdout = io::stdout()
            .into_raw_mode()
            .map_err(|err| err.to_string())?;
        let stdout = MouseTerminal::from(stdout);
        let stdout = AlternateScreen::from(stdout);
        let backend = TermionBackend::new(stdout);
        let mut terminal = Terminal::new(backend).map_err(|err| err.to_string())?;
        terminal.hide_cursor().map_err(|err| err.to_string())?;

        let events = Events::new();
        let mut menu_active = true;

        // App
        let mut app = App {
            tabs: TabsState::new(vec!["Summary       ", "Recent Blocks ", "Peers         "]),
        };

        // Main loop
        loop {
            terminal
                .draw(|mut f| {
                    let size = f.size();
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                        .split(size);
                    let body_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Length(17), Constraint::Min(1)].as_ref())
                        .split(chunks[1]);
                    let menu_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Min(6), Constraint::Length(6)].as_ref())
                        .split(body_chunks[0]);

                    let banner_block = Block::default().borders(Borders::ALL);
                    let texts = [
                        Text::raw("<"),
                        Text::styled("testnet", Style::default().fg(Color::Green)),
                        Text::raw("> "),
                        Text::styled(
                            "CKB",
                            Style::default().fg(Color::Blue).modifier(Modifier::BOLD),
                        ),
                        Text::raw(" "),
                        Text::raw("0.13.0-pre (v0.12.2-76-g39c05149 2019-05-22)"),
                    ];
                    Paragraph::new(texts.iter())
                        .block(banner_block)
                        .alignment(Alignment::Left)
                        .render(&mut f, chunks[0]);

                    // Menu
                    let mut menu_block = Block::default().borders(Borders::ALL).title("Menu");
                    let mut highlight_style = Style::default()
                        // .bg(Color::LightBlue)
                        .fg(Color::Black)
                        .modifier(Modifier::BOLD);
                    if menu_active {
                        menu_block = menu_block
                            .border_style(Style::default().fg(Color::Green))
                            .title_style(Style::default().modifier(Modifier::BOLD));
                        highlight_style = highlight_style.bg(Color::LightYellow);
                    }
                    SelectableList::default()
                        .block(menu_block)
                        .items(&app.tabs.titles)
                        .select(Some(app.tabs.index))
                        .highlight_style(highlight_style)
                        .render(&mut f, menu_chunks[0]);
                    // Menu doc
                    let docs = vec![
                        Text::raw("\n"),
                        Text::styled("Quit : ", Style::default().modifier(Modifier::BOLD)),
                        Text::raw("Q"),
                        Text::raw("\n"),
                        Text::styled("Help : ", Style::default().modifier(Modifier::BOLD)),
                        Text::raw("?"),
                        Text::raw("\n"),
                    ];
                    Paragraph::new(docs.iter())
                        .block(Block::default().title("Help").borders(Borders::ALL))
                        .alignment(Alignment::Center)
                        .render(&mut f, menu_chunks[1]);

                    // Content
                    let mut content_block = Block::default()
                        .title(app.tabs.titles[app.tabs.index].trim())
                        .borders(Borders::ALL);
                    if !menu_active {
                        content_block = content_block
                            .border_style(Style::default().fg(Color::Green))
                            .title_style(Style::default().modifier(Modifier::BOLD));
                    }
                    match app.tabs.index {
                        0 => render_summary(&mut content_block, &mut f, body_chunks[1]),
                        1 => content_block.render(&mut f, body_chunks[1]),
                        2 => content_block.render(&mut f, body_chunks[1]),
                        _ => {}
                    }
                })
                .map_err(|err| err.to_string())?;

            match events.next().map_err(|err| err.to_string())? {
                Event::Input(input) => match input {
                    Key::Char('q') => {
                        break;
                    }
                    Key::Left | Key::Char('h') => {
                        menu_active = true;
                    }
                    Key::Right | Key::Char('l') => {
                        menu_active = false;
                    }
                    Key::Down | Key::Char('j') => {
                        if menu_active {
                            app.tabs.next();
                        }
                    }
                    Key::Up | Key::Char('k') => {
                        if menu_active {
                            app.tabs.previous();
                        }
                    }
                    _ => {}
                },
                Event::Tick => {}
            }
        }
        Ok(Box::new("".to_owned()))
    }
}

fn render_summary<B: Backend>(block: &mut Block, frame: &mut Frame<B>, area: Rect) {
    block.render(frame, area);
}

pub enum Event<I> {
    Input(I),
    Tick,
}

/// A small event handler that wrap termion input and tick events. Each event
/// type is handled in its own thread and returned to a common `Receiver`
pub struct Events {
    rx: mpsc::Receiver<Event<Key>>,
    _input_handle: thread::JoinHandle<()>,
    _tick_handle: thread::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub exit_key: Key,
    pub tick_rate: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            exit_key: Key::Char('q'),
            tick_rate: Duration::from_millis(250),
        }
    }
}

impl Events {
    pub fn new() -> Events {
        Events::with_config(Config::default())
    }

    pub fn with_config(config: Config) -> Events {
        let (tx, rx) = mpsc::channel();
        let input_handle = {
            let tx = tx.clone();
            thread::spawn(move || {
                let stdin = io::stdin();
                for evt in stdin.keys() {
                    match evt {
                        Ok(key) => {
                            if let Err(_) = tx.send(Event::Input(key)) {
                                return;
                            }
                            if key == config.exit_key {
                                return;
                            }
                        }
                        Err(_) => {}
                    }
                }
            })
        };
        let tick_handle = {
            let tx = tx.clone();
            thread::spawn(move || {
                let tx = tx.clone();
                loop {
                    if tx.send(Event::Tick).is_err() {
                        return;
                    }
                    thread::sleep(config.tick_rate);
                }
            })
        };
        Events {
            rx,
            _input_handle: input_handle,
            _tick_handle: tick_handle,
        }
    }

    pub fn next(&self) -> Result<Event<Key>, mpsc::RecvError> {
        self.rx.recv()
    }
}

struct App<'a> {
    tabs: TabsState<'a>,
}

pub struct TabsState<'a> {
    pub titles: Vec<&'a str>,
    pub index: usize,
}

impl<'a> TabsState<'a> {
    pub fn new(titles: Vec<&'a str>) -> TabsState {
        TabsState { titles, index: 0 }
    }
    pub fn next(&mut self) {
        self.index = (self.index + 1) % self.titles.len();
    }

    pub fn previous(&mut self) {
        if self.index > 0 {
            self.index -= 1;
        } else {
            self.index = self.titles.len() - 1;
        }
    }
}
