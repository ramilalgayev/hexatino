// src/main.rs
mod crypto_utils;
mod network;

use crypto_box::PublicKey;
use crypto_utils::{decrypt_message, encrypt_message, KeyPair, fingerprint};
use network::{receive_message, receive_public_key, send_message, send_public_key};

use anyhow::Result;
use crypto_box::SecretKey;
use futures::future;
use serde::{Serialize, Deserialize};
use bincode;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use chrono::Local;

#[derive(Serialize, Deserialize, Debug)]
enum Message {
    HandshakeConfirm,
    ChatMessage {
        seq: u64,
        msg: String,
        timestamp: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Usage: p2p_chat <bind_addr> [peer_addr]
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    let bind_addr = &args[1];
    // Optional peer address for outbound connection.
    let peer_addr = if args.len() >= 3 { Some(args[2].clone()) } else { None };

    // Bind to the specified local address.
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("Listening on {}", bind_addr);

    // If a peer address was given, try an outbound connection.
    let outbound = if let Some(p) = peer_addr {
        Some(tokio::spawn(async move { TcpStream::connect(p).await }))
    } else {
        None
    };

    // Wait for either an inbound connection or the outbound connection to succeed.
    tokio::select! {
        inbound = listener.accept() => {
            let (stream, addr) = inbound?;
            println!("Accepted inbound connection from {:?}", addr);
            // For an inbound connection, we act as a server.
            handle_connection(stream, true).await?;
        }
        outbound_result = async {
            if let Some(outbound) = outbound {
                outbound.await?
            } else {
                // If no peer address was provided, wait forever.
                future::pending::<std::io::Result<TcpStream>>().await
            }
        } => {
            let stream = outbound_result?;
            println!("Outbound connection established");
            // For an outbound connection, we act as a client.
            handle_connection(stream, false).await?;
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Usage: p2p_chat <bind_addr> [peer_addr]");
}

/// Handles the handshake over a TcpStream. For an inbound connection (is_server == true)
/// we wait for the peer's public key then send ours; for an outbound connection we send our
/// public key first then wait.
async fn handle_connection(stream: tokio::net::TcpStream, is_server: bool) -> Result<()> {
    // Use into_split() so that both halves are owned and Send.
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Generate our ephemeral keypair for this session.
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

    // Convert the received bytes into a PublicKey.
    let peer_public = PublicKey::from_slice(&peer_public_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid peer public key"))?;

    // --- Peer Key Authentication ---
    let fp = fingerprint(peer_public.as_bytes());
    println!("Peer key fingerprint: {}", fp);
    println!("Do you trust this key? (yes/no): ");
    let mut answer = String::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    stdin.read_line(&mut answer).await?;
    if !answer.trim().eq_ignore_ascii_case("yes") {
        anyhow::bail!("Untrusted peer public key");
    }
    // --- End Peer Key Authentication ---

    // --- Handshake Confirmation ---
    // Each side sends a handshake confirmation and waits for the peer’s confirmation.
    let handshake_msg = Message::HandshakeConfirm;
    let serialized = bincode::serialize(&handshake_msg)?;
    let packet = encrypt_message(&serialized, &peer_public, &keypair.secret)
        .await
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    send_message(&mut writer, &packet).await?;
    // Wait for handshake confirmation from peer.
    let received_packet = receive_message(&mut reader).await?;
    let decrypted = decrypt_message(&received_packet, &peer_public, &keypair.secret)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to decrypt handshake confirmation: {:?}", e))?;
    let received_msg: Message = bincode::deserialize(&decrypted)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize handshake confirmation: {:?}", e))?;
    match received_msg {
        Message::HandshakeConfirm => {
            println!("Handshake complete. You can start chatting.");
        },
        _ => {
            anyhow::bail!("Unexpected message type during handshake");
        }
    }
    // --- End Handshake Confirmation ---

    start_chat(reader, writer, peer_public, keypair.secret).await?;
    
    // Optionally, zeroize the secret key material here if supported:
    // keypair.secret.zeroize();
    
    Ok(())
}

/// Starts the chat session by spawning a task that continuously receives messages,
/// checks sequence numbers for replay protection, and prints them with timestamps.
/// Meanwhile, the main task reads user input, attaches a sequence number and timestamp, and sends messages.
async fn start_chat<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    peer_public: PublicKey,
    our_secret: SecretKey,
) -> Result<()>
where
    R: io::AsyncRead + Unpin + Send + 'static,
    W: io::AsyncWrite + Unpin + Send + 'static,
{
    // Clone keys for the receiving task.
    let peer_public_recv = peer_public.clone();
    let our_secret_recv = our_secret.clone();

    // For replay protection, track the last sequence number received.
    let recv_seq = std::sync::Arc::new(tokio::sync::Mutex::new(0u64));

    // Spawn a task to continuously receive, decrypt, and process messages.
    let recv_seq_clone = recv_seq.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            match receive_message(&mut reader).await {
                Ok(packet) => {
                    match decrypt_message(&packet, &peer_public_recv, &our_secret_recv).await {
                        Ok(plaintext) => {
                            // Deserialize the message.
                            let msg_enum: Message = match bincode::deserialize(&plaintext) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    eprintln!("Failed to deserialize message: {:?}", e);
                                    continue;
                                }
                            };
                            match msg_enum {
                                Message::ChatMessage { seq, msg, timestamp } => {
                                    let mut last_seq = recv_seq_clone.lock().await;
                                    if seq <= *last_seq {
                                        eprintln!("Replay or out-of-order message detected (seq: {})", seq);
                                        continue;
                                    }
                                    *last_seq = seq;
                                    // Clear the current prompt, print the peer's message with timestamp, then reprint the prompt.
                                    print!("\rPeer [{}]: {}\nYou: ", timestamp, msg);
                                    io::stdout().flush().await.unwrap();
                                },
                                _ => {
                                    eprintln!("Unexpected message type received during chat.");
                                }
                            }
                        }
                        Err(e) => eprintln!("Failed to decrypt a message: {:?}", e),
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving message: {:?}", e);
                    break;
                }
            }
        }
    });

    // Sequence number for outgoing messages.
    let mut send_seq = 1u64;

    // Create a BufReader for standard input.
    let stdin = io::stdin();
    let mut stdin_reader = BufReader::new(stdin);
    let mut input_line = String::new();

    loop {
        // Print the prompt.
        print!("You: ");
        io::stdout().flush().await?;
        input_line.clear();
        let bytes_read = stdin_reader.read_line(&mut input_line).await?;
        if bytes_read == 0 {
            // End-of-file (Ctrl-D) or termination.
            break;
        }
        let trimmed = input_line.trim_end();
        // Get current timestamp as formatted string.
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        // Create a chat message with the current sequence number.
        let chat_msg = Message::ChatMessage {
            seq: send_seq,
            msg: trimmed.to_string(),
            timestamp: timestamp.clone(),
        };
        send_seq += 1;
        // Serialize the chat message.
        let serialized = bincode::serialize(&chat_msg)?;
        let packet = encrypt_message(&serialized, &peer_public, &our_secret)
            .await
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        send_message(&mut writer, &packet).await?;
    }

    // Chat loop ended.
    println!("\nChat session ended.");
    // Optionally, wait for the receiver task to finish.
    recv_task.await?;
    
    // Optionally, zeroize the secret key material here:
    // our_secret.zeroize();
    
    Ok(())
}