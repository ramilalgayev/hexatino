use std::cmp;
use std::io::{stdout, Write};
use std::time::Duration;

use chrono::Local;
use crossterm::{
    cursor,
    event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    style::{Color, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{select, FutureExt, StreamExt};
use textwrap::{wrap, Options};
use tokio::io::BufReader;
use tokio::sync::mpsc;

use crate::chat::Message;
use crypto_box::{PublicKey, SecretKey};
use crate::error::Result;

pub const MAX_INPUT_LINES: usize = 10;

#[derive(Default)]
struct InputState {
    text: String,
    cursor: usize,
}

impl InputState {
    fn insert(&mut self, ch: char) {
        self.text.insert(self.cursor, ch);
        self.cursor += 1;
    }

    fn delete_left(&mut self) {
        if self.cursor > 0 {
            self.text.remove(self.cursor - 1);
            self.cursor -= 1;
        }
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.text.len() {
            self.cursor += 1;
        }
    }

    fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    fn height(&self, cols: usize) -> usize {
        let label_len = 7; // "Input: "
        let available = cols.saturating_sub(label_len);
        if available == 0 {
            return 1;
        }
        let char_count = self.text.chars().count();
        cmp::min(MAX_INPUT_LINES, cmp::max(1, (char_count + available - 1) / available))
    }
}

pub struct UIState {
    messages: Vec<String>,
    input: InputState,
    seq: u64,
    scroll_offset: usize,
    peer_disconnected: bool, // Track if peer has disconnected
}

impl UIState {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: InputState::default(),
            seq: 1,
            scroll_offset: 0,
            peer_disconnected: false,
        }
    }

    fn input_height(&self, cols: usize) -> usize {
        self.input.height(cols)
    }
}

fn wrap_message(message: &str, width: usize) -> Vec<String> {
    let opts = Options::new(width).subsequent_indent("    ");
    wrap(message, &opts).into_iter().map(|l| l.into_owned()).collect()
}

fn wrapped_history(state: &UIState, width: usize) -> Vec<(String, Option<Color>)> {
    let mut lines = Vec::new();
    for raw in &state.messages {
        let color = if raw.starts_with("You") {
            Some(Color::Green)
        } else if raw.starts_with("Peer") {
            Some(Color::Yellow)
        } else {
            None
        };
        for line in wrap_message(raw, width) {
            lines.push((line, color));
        }
    }
    lines
}

fn render_header() -> Result<()> {
    let (cols, _) = terminal::size()?;
    let header = " P2P Chat ";
    let padded = format!("{:^width$}", header, width = cols as usize);
    let mut stdout = stdout();
    execute!(
        stdout,
        cursor::MoveTo(0, 0),
        Clear(ClearType::CurrentLine),
        SetForegroundColor(Color::White),
        SetBackgroundColor(Color::Blue)
    )?;
    write!(stdout, "{}", padded)?;
    execute!(stdout, ResetColor)?;
    stdout.flush()?;
    Ok(())
}

fn render_messages(state: &UIState, input_height: usize) -> Result<()> {
    let (cols, rows) = terminal::size()?;
    let mut stdout = stdout();
    let area_height = rows as usize - input_height - 1;
    let wrapped = wrapped_history(state, cols as usize);
    let total = wrapped.len();

    let start = if total > area_height {
        cmp::max(0, total.saturating_sub(area_height) - state.scroll_offset)
    } else {
        0
    };

    for row in 1..(rows - input_height as u16) {
        execute!(stdout, cursor::MoveTo(0, row), Clear(ClearType::CurrentLine))?;
    }

    for (i, (line, color)) in wrapped[start..].iter().enumerate() {
        if i >= area_height {
            break;
        }
        execute!(stdout, cursor::MoveTo(0, (i + 1) as u16))?;
        if let Some(col) = color {
            execute!(stdout, SetForegroundColor(*col))?;
        }
        let display_line = if line.len() > cols as usize {
            &line[..cols as usize]
        } else {
            line
        };
        write!(stdout, "{}", display_line)?;
        execute!(stdout, ResetColor)?;
    }
    stdout.flush()?;
    Ok(())
}

fn render_input(input: &InputState, peer_disconnected: bool) -> Result<()> {
    let (cols, rows) = terminal::size()?;
    let input_height = input.height(cols as usize);
    let label = if peer_disconnected {
        "Press Esc to close: "
    } else {
        "Input: "
    };
    let available = cols as usize - label.len();
    let mut stdout = stdout();

    let clear_height = cmp::min(MAX_INPUT_LINES, input_height);
    for i in 0..clear_height {
        execute!(
            stdout,
            cursor::MoveTo(0, rows - clear_height as u16 + i as u16),
            Clear(ClearType::CurrentLine)
        )?;
    }

    let chars: Vec<char> = input.text.chars().collect();
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos < chars.len() {
        let end = cmp::min(pos + available, chars.len());
        lines.push(chars[pos..end].iter().collect::<String>());
        pos += available;
    }
    if lines.is_empty() {
        lines.push(String::new());
    }

    let cursor_line = input.cursor / available;
    let cursor_col = input.cursor % available;

    for (i, line) in lines.iter().enumerate().take(input_height) {
        execute!(
            stdout,
            cursor::MoveTo(0, rows - input_height as u16 + i as u16)
        )?;
        if i == 0 {
            execute!(stdout, SetForegroundColor(Color::Magenta))?;
            write!(stdout, "{}", label)?;
        } else {
            write!(stdout, "{}", " ".repeat(label.len()))?;
        }
        write!(stdout, "{}", line)?;
    }

    let target_row = rows - input_height as u16 + cursor_line as u16;
    let target_col = label.len() as u16 + cursor_col as u16;
    execute!(stdout, cursor::MoveTo(target_col, target_row), cursor::Show, ResetColor)?;
    stdout.flush()?;
    Ok(())
}

pub async fn run_ui<R, W>(
    reader: BufReader<R>,
    writer: W,
    peer_public: PublicKey,
    our_secret: SecretKey,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (net_in_tx, mut net_in_rx) = mpsc::channel::<Message>(100);
    let (net_out_tx, net_out_rx) = mpsc::channel::<Message>(100);

    let recv_handle = tokio::spawn(crate::chat::network_receiver(
        reader,
        peer_public.clone(),
        our_secret.clone(),
        net_in_tx.clone(),
    ));
    let send_handle = tokio::spawn(crate::chat::network_sender(
        writer,
        peer_public,
        our_secret,
        net_out_rx,
    ));

    terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    let mut state = UIState::new();
    render_header()?;
    let input_height = state.input_height(terminal::size()?.0 as usize);
    render_messages(&state, input_height)?;
    render_input(&state.input, state.peer_disconnected)?;

    let mut events = EventStream::new().fuse();
    let mut should_exit = false;

    while !should_exit {
        select! {
            ev = events.next().fuse() => {
                if let Some(Ok(event)) = ev {
                    match event {
                        Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                net_out_tx.send(Message::Exit).await.ok();
                                state.messages.push("You left the chat (Ctrl+C).".into());
                                should_exit = true;
                            }
                            KeyCode::Char(c) if !state.peer_disconnected => {
                                state.input.insert(c);
                                let input_height = state.input_height(terminal::size()?.0 as usize);
                                render_messages(&state, input_height)?;
                                render_input(&state.input, state.peer_disconnected)?;
                            }
                            KeyCode::Backspace if !state.peer_disconnected => {
                                state.input.delete_left();
                                let input_height = state.input_height(terminal::size()?.0 as usize);
                                render_messages(&state, input_height)?;
                                render_input(&state.input, state.peer_disconnected)?;
                            }
                            KeyCode::Left if !state.peer_disconnected => {
                                state.input.move_left();
                                render_input(&state.input, state.peer_disconnected)?;
                            }
                            KeyCode::Right if !state.peer_disconnected => {
                                state.input.move_right();
                                render_input(&state.input, state.peer_disconnected)?;
                            }
                            KeyCode::Enter if !state.peer_disconnected => {
                                let trimmed = state.input.text.trim().to_string();
                                if !trimmed.is_empty() {
                                    if trimmed.starts_with("/exit") {
                                        net_out_tx.send(Message::Exit).await.ok();
                                        state.messages.push("You left the chat.".into());
                                        state.scroll_offset = 0;
                                        should_exit = true;
                                    } else {
                                        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                        let chat = Message::ChatMessage {
                                            seq: state.seq,
                                            msg: trimmed.clone(),
                                            timestamp: timestamp.clone(),
                                        };
                                        state.seq += 1;
                                        state.messages.push(format!("You [{}]: {}", timestamp, trimmed));
                                        state.scroll_offset = 0;
                                        let input_height = state.input_height(terminal::size()?.0 as usize);
                                        render_messages(&state, input_height)?;
                                        net_out_tx.send(chat).await.ok();
                                    }
                                }
                                state.input.clear();
                                let input_height = state.input_height(terminal::size()?.0 as usize);
                                render_messages(&state, input_height)?;
                                render_input(&state.input, state.peer_disconnected)?;
                            }
                            KeyCode::Esc => {
                                if state.peer_disconnected {
                                    should_exit = true; // Exit only if peer is disconnected and Esc is pressed
                                } else {
                                    net_out_tx.send(Message::Exit).await.ok();
                                    state.messages.push("You left the chat.".into());
                                    should_exit = true;
                                }
                            }
                            KeyCode::Up => {
                                let wrapped = wrapped_history(&state, terminal::size()?.0 as usize);
                                let area_height = terminal::size()?.1 as usize - state.input_height(terminal::size()?.0 as usize) - 1;
                                if state.scroll_offset < wrapped.len().saturating_sub(area_height) {
                                    state.scroll_offset += 1;
                                    render_messages(&state, state.input_height(terminal::size()?.0 as usize))?;
                                }
                            }
                            KeyCode::Down => {
                                if state.scroll_offset > 0 {
                                    state.scroll_offset -= 1;
                                    render_messages(&state, state.input_height(terminal::size()?.0 as usize))?;
                                }
                            }
                            _ => {}
                        },
                        Event::Resize(_, _) => {
                            state.scroll_offset = 0;
                            render_header()?;
                            let input_height = state.input_height(terminal::size()?.0 as usize);
                            render_messages(&state, input_height)?;
                            render_input(&state.input, state.peer_disconnected)?;
                        }
                        _ => {}
                    }
                }
            }
            msg = net_in_rx.recv().fuse() => {
                match msg {
                    Some(Message::ChatMessage { seq: _, msg, timestamp }) => {
                        state.messages.push(format!("Peer [{}]: {}", timestamp, msg));
                        state.scroll_offset = 0;
                        let input_height = state.input_height(terminal::size()?.0 as usize);
                        render_messages(&state, input_height)?;
                        render_input(&state.input, state.peer_disconnected)?;
                    }
                    Some(Message::Exit) => {
                        state.messages.push("Peer has exited. Press Esc to close.".into());
                        state.peer_disconnected = true;
                        let input_height = state.input_height(terminal::size()?.0 as usize);
                        render_messages(&state, input_height)?;
                        render_input(&state.input, state.peer_disconnected)?;
                    }
                    Some(Message::HandshakeConfirm) => {}
                    None => {
                        state.messages.push("Peer has disconnected. Press Esc to close.".into());
                        state.peer_disconnected = true;
                        let input_height = state.input_height(terminal::size()?.0 as usize);
                        render_messages(&state, input_height)?;
                        render_input(&state.input, state.peer_disconnected)?;
                    }
                }
            }
        }
    }

    // Cleanup terminal
    tokio::time::sleep(Duration::from_millis(200)).await;
    execute!(stdout, LeaveAlternateScreen, cursor::Show)?;
    terminal::disable_raw_mode()?;
    println!("Chat closing...");

    // Drop the sender to signal receiver task to exit
    drop(net_in_tx);

    // Abort and wait for tasks to finish
    recv_handle.abort();
    send_handle.abort();
    let _ = recv_handle.await;
    let _ = send_handle.await;

    Ok(())
}