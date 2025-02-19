mod crypto_utils;
mod network;

use crypto_box::{PublicKey, SecretKey};
use crypto_utils::{decrypt_message, encrypt_message, fingerprint, KeyPair};
use network::{receive_message, receive_public_key, send_message, send_public_key};

use anyhow::Result;
use chrono::Local;
use crossterm::{
    cursor,
    event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    style::{Color, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{select, FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::io::{stdout, Write};
use std::time::Duration;
use textwrap::{wrap, Options};
use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// Maximum amount of lines allowed:
const MAX_INPUT_LINES: usize = 10;

// -----------------------------------------------------------------------------
// Message definitions.
#[derive(Serialize, Deserialize, Debug)]
enum Message {
    HandshakeConfirm,
    ChatMessage {
        seq: u64,
        msg: String,
        timestamp: String,
    },
    Exit,
}

// -----------------------------------------------------------------------------
// Input state: now only tracks the text and the cursor position.
struct InputState {
    text: String,
    cursor: usize,
}

impl InputState {
    fn new() -> Self {
        Self {
            text: String::new(),
            cursor: 0,
        }
    }
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
}

// -----------------------------------------------------------------------------
// UI state: holds chat message history, input state, outgoing message sequence,
// and scroll offset for the message area.
struct UIState {
    messages: Vec<String>, // each message already formatted (e.g. "You [timestamp]: ..." )
    input: InputState,
    seq: u64,
    scroll_offset: usize,
}

impl UIState {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: InputState::new(),
            seq: 1,
            scroll_offset: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Wrap a message into lines that fit within the given width.
fn wrap_message(message: &str, width: usize) -> Vec<String> {
    let opts = Options::new(width).subsequent_indent("    ");
    wrap(message, &opts).into_iter().map(|l| l.into_owned()).collect()
}

// Convert message history into wrapped lines with an associated color.
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

// -----------------------------------------------------------------------------
// Render the header.
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

// -----------------------------------------------------------------------------
// Render the message area (rows 1 to rows - input_height - 1) using scroll offset.
fn render_messages(state: &UIState, input_height: usize) -> Result<()> {
    let (cols, rows) = terminal::size()?;
    let mut stdout = stdout();
    let area_height = (rows as usize).saturating_sub(input_height + 1);
    let wrapped = wrapped_history(state, cols as usize);
    let total = wrapped.len();
    let start = if total > area_height + state.scroll_offset {
        total - area_height - state.scroll_offset
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
        } else {
            execute!(stdout, ResetColor)?;
        }
        let display_line = if line.len() > cols as usize {
            &line[..cols as usize]
        } else {
            line
        };
        writeln!(stdout, "{}", display_line)?;
        execute!(stdout, ResetColor)?;
    }
    stdout.flush()?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Render the input area at the bottom. The input text is wrapped if necessary.
// The label and input are rendered in magenta, and the terminal cursor is moved
// to the correct position.
fn render_input(input: &InputState) -> Result<()> {
    let (cols, rows) = terminal::size()?;
    let label = "Input: ";
    let available = cols as usize - label.len();

    // Always clear the bottom MAX_INPUT_LINES lines.
    let mut stdout = stdout();
    for i in 0..MAX_INPUT_LINES {
        execute!(
            stdout,
            cursor::MoveTo(0, rows - MAX_INPUT_LINES as u16 + i as u16),
            Clear(ClearType::CurrentLine)
        )?;
    }

    // Wrap the input text into lines.
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
    // Determine cursor's line and column.
    let cursor_line = input.cursor / available;
    let cursor_col = input.cursor % available;

    // Render only as many lines as needed.
    let input_height = lines.len();
    for i in 0..input_height {
        execute!(
            stdout,
            cursor::MoveTo(0, rows - input_height as u16 + i as u16)
        )?;
        if i == 0 {
            // Render label in magenta.
            execute!(stdout, SetForegroundColor(Color::Magenta))?;
            write!(stdout, "{}", label)?;
        } else {
            write!(stdout, "{}", " ".repeat(label.len()))?;
        }
        write!(stdout, "{}", lines[i])?;
    }
    // Position the terminal cursor.
    let target_row = rows - input_height as u16 + cursor_line as u16;
    let target_col = label.len() as u16 + cursor_col as u16;
    execute!(stdout, cursor::MoveTo(target_col, target_row), SetForegroundColor(Color::Magenta))?;
    // Ensure the cursor is visible.
    execute!(stdout, cursor::Show)?;
    execute!(stdout, ResetColor)?;
    stdout.flush()?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Clean up the terminal.
fn cleanup_terminal() -> Result<()> {
    let mut stdout = stdout();
    execute!(stdout, LeaveAlternateScreen, cursor::Show)?;
    terminal::disable_raw_mode()?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Network receiver: reads from the network, decrypts, deserializes, and sends
// Message values over an mpsc channel.
async fn network_receiver<R>(
    mut reader: BufReader<R>,
    peer_public: PublicKey,
    our_secret: SecretKey,
    net_in_tx: mpsc::Sender<Message>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match receive_message(&mut reader).await {
            Ok(packet) => match decrypt_message(&packet, &peer_public, &our_secret).await {
                Ok(plaintext) => {
                    if let Ok(msg) = bincode::deserialize::<Message>(&plaintext) {
                        if net_in_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Network receiver error: {:?}", e);
                    break;
                }
            },
            Err(e) => {
                eprintln!("Network receiver error: {:?}", e);
                break;
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Network sender: waits for outgoing Message values from an mpsc channel,
// serializes, encrypts, and sends them.
async fn network_sender<W>(
    mut writer: W,
    peer_public: PublicKey,
    our_secret: SecretKey,
    mut net_out_rx: mpsc::Receiver<Message>,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(msg) = net_out_rx.recv().await {
        let serialized = match bincode::serialize(&msg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Serialization error: {:?}", e);
                continue;
            }
        };
        let packet = match encrypt_message(&serialized, &peer_public, &our_secret).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Encryption error: {:?}", e);
                continue;
            }
        };
        if let Err(e) = send_message(&mut writer, &packet).await {
            eprintln!("Network sender error: {:?}", e);
            break;
        }
    }
    let _ = writer.shutdown().await;
}

// -----------------------------------------------------------------------------
// run_ui: Takes over the terminal (alternate screen, raw mode), processes keyboard
// and resize events, supports scrolling, and handles incoming network messages.
// When an exit command is triggered, it cleans up, prints "Chat closing..." on the
// restored terminal, and exits the entire process.
async fn run_ui<R, W>(
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
    let recv_handle = tokio::spawn(network_receiver(
        reader,
        peer_public.clone(),
        our_secret.clone(),
        net_in_tx,
    ));
    let send_handle = tokio::spawn(network_sender(
        writer,
        peer_public,
        our_secret,
        net_out_rx,
    ));
    terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    render_header()?;
    let mut ui_state = UIState::new();
    render_messages(&ui_state, ui_state.input_text_height())?;
    render_input(&ui_state.input)?;
    let mut events = EventStream::new().fuse();
    loop {
        select! {
            maybe_event = events.next().fuse() => {
                if let Some(Ok(event)) = maybe_event {
                    match event {
                        Event::Key(key_event) => {
                            if key_event.kind != KeyEventKind::Press {
                                continue;
                            }
                            if key_event.code == KeyCode::Char('c') && key_event.modifiers.contains(KeyModifiers::CONTROL) {
                                let _ = net_out_tx.send(Message::Exit).await;
                                ui_state.messages.push("You left the chat (Ctrl+C).".into());
                                break;
                            }
                            match key_event.code {
                                KeyCode::Char(c) => {
                                    ui_state.input.insert(c);
                                    render_input(&ui_state.input)?;
                                },
                                KeyCode::Backspace => {
                                    ui_state.input.delete_left();
                                    render_input(&ui_state.input)?;
                                },
                                KeyCode::Left => {
                                    ui_state.input.move_left();
                                    render_input(&ui_state.input)?;
                                },
                                KeyCode::Right => {
                                    ui_state.input.move_right();
                                    render_input(&ui_state.input)?;
                                },
                                KeyCode::Enter => {
                                    let trimmed = ui_state.input.text.trim();
                                    if !trimmed.is_empty() {
                                        if trimmed.starts_with("/exit") {
                                            let _ = net_out_tx.send(Message::Exit).await;
                                            ui_state.messages.push("You left the chat.".into());
                                            ui_state.scroll_offset = 0; // reset scrolling so message is fully visible
                                            render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                                            break;
                                        } else {
                                            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                            let chat = Message::ChatMessage {
                                                seq: ui_state.seq,
                                                msg: trimmed.to_string(),
                                                timestamp: timestamp.clone(),
                                            };
                                            ui_state.seq += 1;
                                            ui_state.messages.push(format!("You [{}]: {}", timestamp, trimmed));
                                            ui_state.scroll_offset = 0; // reset scroll offset
                                            render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                                            let _ = net_out_tx.send(chat).await;
                                        }
                                    }
                                    ui_state.input.text.clear();
                                    ui_state.input.cursor = 0;
                                    render_input(&ui_state.input)?;
                                },                                                              
                                KeyCode::Esc => {
                                    let _ = net_out_tx.send(Message::Exit).await;
                                    ui_state.messages.push("You left the chat.".into());
                                    break;
                                },
                                KeyCode::Up => {
                                    let wrapped = wrapped_history(&ui_state, terminal::size()?.0 as usize);
                                    let (_cols, rows) = terminal::size()?;
                                    let area_height = rows as usize - 3;
                                    if ui_state.scroll_offset < wrapped.len().saturating_sub(area_height) {
                                        ui_state.scroll_offset += 1;
                                        render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                                    }
                                },
                                KeyCode::Down => {
                                    if ui_state.scroll_offset > 0 {
                                        ui_state.scroll_offset -= 1;
                                        render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                                    }
                                },
                                _ => {}
                            }
                        },
                        Event::Resize(_, _) => {
                            ui_state.scroll_offset = 0;
                            render_header()?;
                            render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                            render_input(&ui_state.input)?;
                        },
                        _ => {}
                    }
                }
            },
            maybe_net = net_in_rx.recv().fuse() => {
                if let Some(net_msg) = maybe_net {
                    match net_msg {
                        Message::ChatMessage { seq: _, msg, timestamp } => {
                            ui_state.messages.push(format!("Peer [{}]: {}", timestamp, msg));
                            ui_state.scroll_offset = 0; // reset scroll offset to show newest messages
                            render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                            render_input(&ui_state.input)?;
                        },
                        Message::Exit => {
                            ui_state.messages.push("Peer left the chat.".into());
                            render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                            break;
                        },
                        _ => {}
                    }
                } else {
                    ui_state.messages.push("Network connection lost.".into());
                    render_messages(&ui_state, cmp::max(1, ui_state.input_text_height()))?;
                    break;
                }
            },
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup_terminal()?;
    println!("Chat closing...");
    let _ = recv_handle.await;
    let _ = send_handle.await;
    std::process::exit(0);
}

// Helper: compute how many lines the input occupies.
impl UIState {
    fn input_text_height(&self) -> usize {
        let label_len = 7; // "Input: "
        if let Ok((cols, _)) = terminal::size() {
            let available = cols as usize - label_len;
            let len = self.input.text.len();
            cmp::max(1, (len + available - 1) / available)
        } else {
            1
        }
    }
}

// -----------------------------------------------------------------------------
// handle_connection_and_run_ui: Performs handshake, fingerprint authentication,
// then launches the interactive UI.
async fn handle_connection_and_run_ui(stream: TcpStream, is_server: bool) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;
    let keypair = KeyPair::new();
    let our_public = keypair.public.as_bytes();
    let peer_public_bytes = if is_server {
        println!("Waiting for peer's public key...");
        let pk = receive_public_key(&mut reader).await?;
        println!("Received peer's public key.");
        send_public_key(&mut writer, our_public).await?;
        println!("Sent our public key.");
        pk
    } else {
        send_public_key(&mut writer, our_public).await?;
        println!("Sent our public key.");
        println!("Waiting for peer's public key...");
        let pk = receive_public_key(&mut reader).await?;
        println!("Received peer's public key.");
        pk
    };
    let peer_public = PublicKey::from_slice(&peer_public_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid peer public key"))?;
    let fp = fingerprint(peer_public.as_bytes());
    println!("Peer key fingerprint: {}", fp);
    println!("Do you trust this key? (yes/no): ");
    let mut answer = String::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    stdin.read_line(&mut answer).await?;
    if !answer.trim().eq_ignore_ascii_case("yes") {
        anyhow::bail!("Untrusted peer public key");
    }
    println!("Handshake confirmed locally. Waiting for peer to confirm handshake...");
    let handshake_msg = Message::HandshakeConfirm;
    let serialized = bincode::serialize(&handshake_msg)?;
    let packet = encrypt_message(&serialized, &peer_public, &keypair.secret)
        .await
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    send_message(&mut writer, &packet).await?;
    let received_packet = receive_message(&mut reader).await?;
    let decrypted = decrypt_message(&received_packet, &peer_public, &keypair.secret)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to decrypt handshake confirmation: {:?}", e))?;
    let received_msg: Message = bincode::deserialize(&decrypted)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize handshake confirmation: {:?}", e))?;
    match received_msg {
        Message::HandshakeConfirm => {
            println!("Peer confirmed handshake. Launching interactive UI...");
        },
        _ => {
            anyhow::bail!("Unexpected message type during handshake");
        }
    }
    run_ui(reader, writer, peer_public, keypair.secret).await
}

// -----------------------------------------------------------------------------
// Main: Binds to the specified address and either accepts an inbound connection or
// initiates an outbound connection, then performs handshake and launches the UI.
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: p2p_chat <bind_addr> [peer_addr]");
        return Ok(());
    }
    let bind_addr = &args[1];
    let peer_addr = if args.len() >= 3 { Some(args[2].clone()) } else { None };
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("Listening on {}", bind_addr);
    let outbound = if let Some(p) = peer_addr {
        Some(tokio::spawn(async move { TcpStream::connect(p).await }))
    } else {
        None
    };
    tokio::select! {
        inbound = listener.accept() => {
            let (stream, addr) = inbound?;
            println!("Accepted inbound connection from {:?}", addr);
            handle_connection_and_run_ui(stream, true).await?;
        },
        outbound_result = async {
            if let Some(outbound) = outbound {
                outbound.await?
            } else {
                futures::future::pending::<std::io::Result<TcpStream>>().await
            }
        } => {
            let stream = outbound_result?;
            println!("Outbound connection established");
            handle_connection_and_run_ui(stream, false).await?;
        }
    }
    Ok(())
}