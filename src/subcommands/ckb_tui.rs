use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ckb_core::header::Header;
use ckb_util::RwLock;
use jsonrpc_types::{BlockView, ChainInfo, Node, TxPoolInfo};
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

pub struct TuiSubCommand {
    url: String,
}

impl TuiSubCommand {
    pub fn new(url: String) -> TuiSubCommand {
        TuiSubCommand { url }
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
        let state = Arc::new(RwLock::new(State::default()));
        start_rpc_thread(self.url, Arc::clone(&state));
        // App
        let mut app = App {
            menu_active: true,
            tabs: TabsState::new(vec!["Summary", "Recent Blocks", "Peers"]),
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
                        Text::raw(" <"),
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
                    if app.menu_active {
                        menu_block = menu_block
                            .border_style(Style::default().fg(Color::Green))
                            .title_style(Style::default().modifier(Modifier::BOLD));
                        highlight_style = highlight_style.bg(Color::LightYellow);
                    }
                    SelectableList::default()
                        .block(menu_block)
                        .items(&app.tabs.fixed_titles())
                        .select(Some(app.tabs.index))
                        .highlight_style(highlight_style)
                        .render(&mut f, menu_chunks[0]);
                    // Menu doc
                    let docs = vec![
                        Text::raw("\n"),
                        Text::styled("Quit ", Style::default().modifier(Modifier::BOLD)),
                        Text::raw(": Q"),
                        Text::raw("\n"),
                        Text::styled("Help ", Style::default().modifier(Modifier::BOLD)),
                        Text::raw(": ?"),
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
                    if !app.menu_active {
                        content_block = content_block
                            .border_style(Style::default().fg(Color::Green))
                            .title_style(Style::default().modifier(Modifier::BOLD));
                    }
                    let content_context = ContentContext {
                        block: content_block,
                        frame: &mut f,
                        rect: body_chunks[1],
                    };
                    match app.tabs.index {
                        0 => render_summary(&state.read(), content_context),
                        1 => {}
                        2 => {}
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
                        app.menu_active = true;
                    }
                    Key::Right | Key::Char('l') => {
                        app.menu_active = false;
                    }
                    Key::Down | Key::Char('j') => {
                        if app.menu_active {
                            app.tabs.next();
                        }
                    }
                    Key::Up | Key::Char('k') => {
                        if app.menu_active {
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

fn render_summary<B: Backend>(state: &State, ctx: ContentContext<B>) {
    let SummaryInfo {
        chain,
        tip,
        tx_pool,
        peer_count,
    } = state.summary();
    let mut lines = vec![Text::raw("\n")];
    let mut push_pair = |name: &str, content_opt: Option<String>, style_opt: Option<Style>| {
        lines.push(Text::styled(
            format!("{} ", name),
            Style::default().modifier(Modifier::BOLD),
        ));

        let content = content_opt.unwrap_or("<unknown>".to_string());
        if let Some(style) = style_opt {
            lines.push(Text::raw(": "));
            lines.push(Text::styled(content, style));
        } else {
            lines.push(Text::raw(format!(": {}", content)));
        }
        lines.push(Text::raw("\n"));
    };

    let chain_name = chain.as_ref().map(|info| info.chain.to_string());
    let epoch = chain.as_ref().map(|info| info.epoch.0.to_string());
    let difficulty = chain.as_ref().map(|info| info.difficulty.to_string());
    let ibd = chain
        .as_ref()
        .map(|info| info.is_initial_block_download.to_string());
    let warnings = chain.as_ref().and_then(|info| {
        if info.warnings.is_empty() {
            None
        } else {
            Some(info.warnings.to_string())
        }
    });
    let tip_info = tip
        .as_ref()
        .map(|block| format!("{} => {}", block.header.number(), block.header.hash()));
    let tx_pool_info = tx_pool.map(|info| {
        format!(
            "pending={}, proposed={}, orphan={}",
            info.pending.0, info.proposed.0, info.orphan.0,
        )
    });
    let peers_count = Some(format!("{}", peer_count));

    let tip_style = tip.as_ref().and_then(|block| {
        if ts_now().saturating_sub(block.got_at) < 2000 {
            Some(Style::default().fg(Color::Black).bg(Color::LightBlue))
        } else {
            None
        }
    });
    let warn_style = Style::default().fg(Color::Yellow).modifier(Modifier::BOLD);
    push_pair(" Chain     ", chain_name, None);
    push_pair(" Epoch     ", epoch, None);
    push_pair(" Difficulty", difficulty, None);
    push_pair(" IBD       ", ibd, None);
    push_pair(" Tip Block ", tip_info, tip_style);
    push_pair(" TxPool    ", tx_pool_info, None);
    push_pair(" Peers     ", peers_count, None);
    if warnings.is_some() {
        push_pair(" Warnings  ", warnings, Some(warn_style));
    }

    Paragraph::new(lines.iter())
        .block(ctx.block)
        .alignment(Alignment::Left)
        .render(ctx.frame, ctx.rect);
}

fn ts_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

struct ContentContext<'a, 'b, B: Backend> {
    block: Block<'a>,
    frame: &'a mut Frame<'b, B>,
    rect: Rect,
}

fn start_rpc_thread(url: String, state: Arc<RwLock<State>>) {
    let mut rpc_client = HttpRpcClient::from_uri(url.as_str());
    thread::spawn(move || loop {
        let chain_info = rpc_client.get_blockchain_info().call().unwrap();
        let tx_pool_info = rpc_client.tx_pool_info().call().unwrap();
        let peers = rpc_client.get_peers().call().unwrap();
        let tip_header: Header = rpc_client.get_tip_header().call().unwrap().into();
        let new_block = {
            if state
                .read()
                .tip_header
                .as_ref()
                .map(|header| header.hash() != tip_header.hash())
                .unwrap_or(true)
            {
                rpc_client
                    .get_block(tip_header.hash().clone())
                    .call()
                    .unwrap()
                    .0
            } else {
                None
            }
        };
        {
            let mut state_mut = state.write();
            state_mut.tip_header = Some(tip_header);
            state_mut.chain = Some(chain_info);
            state_mut.tx_pool = Some(tx_pool_info);
            state_mut.peers = peers.0;
            if let Some(block) = new_block {
                let number = block.header.inner.number.0;
                state_mut.blocks.insert(number, block.into());
            }
        }
        thread::sleep(Duration::from_secs(1));
    });
}

struct App {
    menu_active: bool,
    tabs: TabsState,
}

#[derive(Default)]
pub struct State {
    blocks: BTreeMap<u64, BlockInfo>,
    tip_header: Option<Header>,
    peers: Vec<Node>,
    chain: Option<ChainInfo>,
    tx_pool: Option<TxPoolInfo>,
}

impl State {
    pub fn summary(&self) -> SummaryInfo {
        SummaryInfo {
            tip: self.blocks.values().last().cloned(),
            chain: self.chain.as_ref().map(|info| ChainInfo {
                chain: info.chain.clone(),
                median_time: info.median_time.clone(),
                epoch: info.epoch.clone(),
                difficulty: info.difficulty.clone(),
                is_initial_block_download: info.is_initial_block_download,
                warnings: info.warnings.clone(),
            }),
            tx_pool: self.tx_pool.clone(),
            peer_count: self.peers.len(),
        }
    }
}

pub struct SummaryInfo {
    chain: Option<ChainInfo>,
    tip: Option<BlockInfo>,
    tx_pool: Option<TxPoolInfo>,
    peer_count: usize,
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    header: Header,
    got_at: u64,
    uncle_count: usize,
    commit_tx_count: usize,
    proposal_tx_count: usize,
    input_count: usize,
    output_count: usize,
    cellbase_capacity: u64,
}

impl From<BlockView> for BlockInfo {
    fn from(view: BlockView) -> BlockInfo {
        let header = view.header.into();
        let uncle_count = view.uncles.len();
        let commit_tx_count = view.transactions.len();
        let proposal_tx_count = view.proposals.len();
        let cellbase_capacity = view.transactions[0].inner.outputs[0].capacity.0.as_u64();
        let mut input_count = 0;
        let mut output_count = 0;
        for tx in &view.transactions {
            input_count += tx.inner.inputs.len();
            output_count += tx.inner.outputs.len();
        }
        let got_at = ts_now();
        BlockInfo {
            header,
            got_at,
            uncle_count,
            commit_tx_count,
            proposal_tx_count,
            input_count,
            output_count,
            cellbase_capacity,
        }
    }
}

pub struct TabsState {
    pub titles: Vec<String>,
    pub index: usize,
}

impl TabsState {
    pub fn new(titles: Vec<&str>) -> TabsState {
        let titles = titles.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        TabsState { titles, index: 0 }
    }
    pub fn fixed_titles(&self) -> Vec<String> {
        let max_length = self
            .titles
            .iter()
            .map(|title| title.len())
            .max()
            .unwrap_or(0)
            + 1;
        self.titles
            .iter()
            .map(|title| format!("{:^width$}", title, width = max_length))
            .collect::<Vec<_>>()
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
