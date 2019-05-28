mod state;
mod util;
mod widgets;

use std::io;
use std::sync::Arc;

use ckb_util::RwLock;
use termion::event::Key;
use termion::input::MouseTerminal;
use termion::raw::IntoRawMode;
use termion::screen::AlternateScreen;
use tui::backend::{Backend, TermionBackend};
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::widgets::{Block, Borders, Paragraph, SelectableList, Text, Widget};
use tui::{Frame, Terminal};

use crate::utils::printer::Printable;
use state::{start_rpc_thread, State, SummaryInfo};
use util::{ts_now, App, Event, Events, TabsState};
use widgets::List;

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

                    let banner_context = RenderContext {
                        block: Block::default().borders(Borders::ALL),
                        frame: &mut f,
                        rect: chunks[0],
                    };
                    render_bannar(&state.read(), banner_context);

                    let menu_context = RenderContext {
                        block: Block::default().borders(Borders::ALL),
                        frame: &mut f,
                        rect: body_chunks[0],
                    };
                    render_menu(&app, menu_context);

                    // Content
                    let mut content_block = Block::default()
                        .title(app.tabs.titles[app.tabs.index].trim())
                        .borders(Borders::ALL);
                    if !app.menu_active {
                        content_block = content_block
                            .border_style(Style::default().fg(Color::Green))
                            .title_style(Style::default().modifier(Modifier::BOLD));
                    }
                    let content_context = RenderContext {
                        block: content_block,
                        frame: &mut f,
                        rect: body_chunks[1],
                    };
                    match app.tabs.index {
                        0 => render_summary(&state.read(), content_context),
                        1 => render_blocks(&state.read(), content_context),
                        2 => render_peers(&state.read(), content_context),
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

struct RenderContext<'a, 'b, B: Backend> {
    block: Block<'a>,
    frame: &'a mut Frame<'b, B>,
    rect: Rect,
}

fn render_bannar<B: Backend>(state: &State, ctx: RenderContext<B>) {
    let chain_name = state
        .chain
        .as_ref()
        .map(|info| info.chain.to_string())
        .unwrap_or("<unknown>".to_string());
    let version = state
        .local_node
        .as_ref()
        .map(|info| info.version.to_string())
        .unwrap_or("<unknown>".to_string());
    let texts = [
        Text::raw(" <"),
        Text::styled(chain_name, Style::default().fg(Color::Green)),
        Text::raw("> "),
        Text::styled(
            "CKB",
            Style::default().fg(Color::Blue).modifier(Modifier::BOLD),
        ),
        Text::raw(" "),
        Text::raw(version),
    ];
    Paragraph::new(texts.iter())
        .block(ctx.block)
        .alignment(Alignment::Left)
        .render(ctx.frame, ctx.rect);
}

fn render_menu<B: Backend>(app: &App, ctx: RenderContext<B>) {
    let menu_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(6)].as_ref())
        .split(ctx.rect);

    // Menu
    let mut menu_block = ctx.block.title("Menu");
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
        .render(ctx.frame, menu_chunks[0]);
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
        .render(ctx.frame, menu_chunks[1]);
}

fn render_summary<B: Backend>(state: &State, ctx: RenderContext<B>) {
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

fn render_blocks<B: Backend>(state: &State, ctx: RenderContext<B>) {
    let blocks = state.blocks.values().rev().flat_map(|block| {
        let header = &block.header;
        vec![
            Text::styled(
                format!("{} => {:#x}", header.number(), header.hash(),),
                Style::default().modifier(Modifier::BOLD),
            ),
            Text::raw(format!(
                "  commited={}, proposed={}, uncles={}",
                block.commit_tx_count, block.proposal_tx_count, block.uncle_count,
            )),
        ]
    });
    List::new(blocks)
        .block(ctx.block)
        .render(ctx.frame, ctx.rect);
}

fn render_peers<B: Backend>(state: &State, ctx: RenderContext<B>) {
    let peers = state.peers.iter().flat_map(|node| {
        let direction = if node.is_outbound.unwrap_or(true) {
            "outbound"
        } else {
            "inbound"
        };
        vec![
            Text::raw(format!("{}:", node.node_id,)),
            Text::raw(format!(
                "  {}, {}, version({})",
                node.version, direction, node.addresses[0].address,
            )),
        ]
    });
    List::new(peers)
        .block(ctx.block)
        .render(ctx.frame, ctx.rect);
}
