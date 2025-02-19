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
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{select, FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::{stdout, Write};
use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Message types exchanged over the network.
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
// UI state for our interactive terminal.
struct UIState {
    messages: Vec<String>, // message history
    input: String,         // current input buffer
    seq: u64,              // outgoing message sequence number
}

impl UIState {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: String::new(),
            seq: 1,
        }
    }
}

// -----------------------------------------------------------------------------
// Render only the message area (all rows except the bottom one).
fn render_messages(state: &UIState) -> Result<()> {
    let (_cols, rows) = terminal::size()?;
    let mut stdout = stdout();
    // Clear message area.
    for row in 0..(rows - 1) {
        execute!(stdout, cursor::MoveTo(0, row), Clear(ClearType::CurrentLine))?;
    }
    // Show as many recent messages as fit.
    let available = (rows - 1) as usize;
    let msgs = if state.messages.len() > available {
        &state.messages[state.messages.len() - available..]
    } else {
        &state.messages[..]
    };
    for (i, line) in msgs.iter().enumerate() {
        execute!(stdout, cursor::MoveTo(0, i as u16))?;
        writeln!(stdout, "{}", line)?;
    }
    stdout.flush()?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Render the input bar at the bottom.
fn render_input(state: &UIState) -> Result<()> {
    let (_cols, rows) = terminal::size()?;
    let mut stdout = stdout();
    execute!(stdout, cursor::MoveTo(0, rows - 1), Clear(ClearType::CurrentLine))?;
    write!(stdout, "Input: {}", state.input)?;
    stdout.flush()?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Network receiver: continuously reads from the network, decrypts, deserializes,
// and forwards Message values over an mpsc channel.
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
                    eprintln!("Network receiver decryption error: {:?}", e);
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
// run_ui: Takes over the terminal (alternate screen, raw mode) and runs an
// event loop that processes keyboard events (including Ctrl+C) and incoming
// network messages. When an exit condition occurs, it cleans up and then exits
// the entire process.
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

    let mut events = EventStream::new().fuse();
    let mut ui_state = UIState::new();
    render_messages(&ui_state)?;
    render_input(&ui_state)?;

    loop {
        select! {
            maybe_event = events.next().fuse() => {
                if let Some(Ok(Event::Key(key_event))) = maybe_event {
                    // Process only "Press" events.
                    if key_event.kind != KeyEventKind::Press {
                        continue;
                    }
                    // Check for Ctrl+C.
                    if key_event.code == KeyCode::Char('c') && key_event.modifiers.contains(KeyModifiers::CONTROL) {
                        let _ = net_out_tx.send(Message::Exit).await;
                        ui_state.messages.push("You left the chat (Ctrl+C).".into());
                        render_messages(&ui_state)?;
                        break;
                    }
                    match key_event.code {
                        KeyCode::Char(c) => {
                            ui_state.input.push(c);
                            render_input(&ui_state)?;
                        },
                        KeyCode::Backspace => {
                            ui_state.input.pop();
                            render_input(&ui_state)?;
                        },
                        KeyCode::Enter => {
                            let trimmed = ui_state.input.trim();
                            if !trimmed.is_empty() {
                                if trimmed.starts_with("/exit") {
                                    let _ = net_out_tx.send(Message::Exit).await;
                                    ui_state.messages.push("You left the chat.".into());
                                    render_messages(&ui_state)?;
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
                                    render_messages(&ui_state)?;
                                    let _ = net_out_tx.send(chat).await;
                                }
                            }
                            ui_state.input.clear();
                            render_input(&ui_state)?;
                        },
                        KeyCode::Esc => {
                            let _ = net_out_tx.send(Message::Exit).await;
                            ui_state.messages.push("You left the chat.".into());
                            render_messages(&ui_state)?;
                            break;
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
                            render_messages(&ui_state)?;
                            render_input(&ui_state)?;
                        },
                        Message::Exit => {
                            ui_state.messages.push("Peer left the chat.".into());
                            render_messages(&ui_state)?;
                            break;
                        },
                        _ => {}
                    }
                } else {
                    ui_state.messages.push("Network connection lost.".into());
                    render_messages(&ui_state)?;
                    break;
                }
            },
        }
    }

    // Brief pause for final messages.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Clean up terminal.
    execute!(stdout, LeaveAlternateScreen, cursor::Show)?;
    terminal::disable_raw_mode()?;

    let _ = recv_handle.await;
    let _ = send_handle.await;

    // Exit the entire process.
    std::process::exit(0);
}

// -----------------------------------------------------------------------------
// handle_connection_and_run_ui: Performs handshake, fingerprint auth (with
// feedback after you type "yes"), then launches the interactive UI.
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

    // Peer key authentication.
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

    // Handshake confirmation.
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
// Main: Binds to the given address and either accepts an inbound connection or
// initiates an outbound connection, then runs handshake and launches the UI.
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