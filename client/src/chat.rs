use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use crypto_box::{SecretKey, PublicKey};
use crate::crypto::{KeyPair, decrypt_message, encrypt_message};
use crate::error::{Error, Result};
use crate::network::{receive_message, receive_public_key, send_message, send_public_key};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    HandshakeConfirm,
    ChatMessage { seq: u64, msg: String, timestamp: String },
    Exit,
}

pub async fn perform_handshake(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    keypair: &KeyPair,
    is_server: bool,
) -> Result<(BufReader<OwnedReadHalf>, OwnedWriteHalf, PublicKey)> {
    let our_public = keypair.public.as_bytes();
    let peer_public_bytes = if is_server {
        println!("Waiting for peer's public key...");
        let pk = receive_public_key(&mut reader).await?;
        println!("Sent our public key.");
        send_public_key(&mut writer, our_public).await?;
        pk
    } else {
        send_public_key(&mut writer, our_public).await?;
        println!("Waiting for peer's public key...");
        let pk = receive_public_key(&mut reader).await?;
        println!("Received peer's public key.");
        pk
    };

    let peer_public = PublicKey::from_slice(&peer_public_bytes).map_err(|_| Error::InvalidKey)?;
    let fp = crate::crypto::fingerprint(peer_public.as_bytes());
    println!("Peer key fingerprint: {}", fp);
    println!("Do you trust this key? (yes/no): ");

    let mut answer = String::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    stdin.read_line(&mut answer).await?;
    if !answer.trim().eq_ignore_ascii_case("yes") {
        return Err(Error::UntrustedPeer);
    }

    println!("Handshake confirmed locally. Waiting for peer...");
    let handshake_msg = Message::HandshakeConfirm;
    let serialized = bincode::serialize(&handshake_msg)?;
    let packet = encrypt_message(&serialized, &peer_public, &keypair.secret).await?;
    send_message(&mut writer, &packet).await?;

    let received_packet = receive_message(&mut reader).await?;
    let decrypted = decrypt_message(&received_packet, &peer_public, &keypair.secret).await?;
    let received_msg: Message = bincode::deserialize(&decrypted)?;
    match received_msg {
        Message::HandshakeConfirm => println!("Peer confirmed handshake. Starting chat..."),
        _ => return Err(Error::UnexpectedMessage),
    }

    Ok((reader, writer, peer_public))
}

pub async fn network_receiver<R>(
    mut reader: BufReader<R>,
    peer_public: PublicKey,
    our_secret: SecretKey,
    net_in_tx: mpsc::Sender<Message>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    while let Ok(packet) = receive_message(&mut reader).await {
        match decrypt_message(&packet, &peer_public, &our_secret).await {
            Ok(plaintext) => match bincode::deserialize(&plaintext) {
                Ok(msg) => {
                    if net_in_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Deserialization error: {}", e);
                    break;
                }
            },
            Err(e) => {
                eprintln!("Decryption error: {}", e);
                break;
            }
        }
    }
}

pub async fn network_sender<W>(
    mut writer: W,
    peer_public: PublicKey,
    our_secret: SecretKey,
    mut net_out_rx: mpsc::Receiver<Message>,
) where
    W: tokio::io::AsyncWrite + Unpin + tokio::io::AsyncWriteExt,
{
    while let Some(msg) = net_out_rx.recv().await {
        match bincode::serialize(&msg) {
            Ok(serialized) => match encrypt_message(&serialized, &peer_public, &our_secret).await {
                Ok(packet) => {
                    if let Err(e) = send_message(&mut writer, &packet).await {
                        eprintln!("Send error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Encryption error: {}", e);
                    break;
                }
            },
            Err(e) => {
                eprintln!("Serialization error: {}", e);
                continue;
            }
        }
    }
    let _ = writer.shutdown().await;
}