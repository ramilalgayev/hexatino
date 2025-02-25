use anyhow::Result;
use tokio::net::TcpStream;

use client::chat::perform_handshake;
use client::crypto::KeyPair;
use client::ui::run_ui;

async fn handle_connection(stream: TcpStream, is_server: bool) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let reader = tokio::io::BufReader::new(read_half);
    let keypair = KeyPair::new();

    let (reader, writer, peer_public) = perform_handshake(reader, write_half, &keypair, is_server).await?;
    run_ui(reader, writer, peer_public, keypair.secret).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: p2p_chat <bind_addr> [peer_addr]");
        return Ok(());
    }

    let bind_addr = &args[1];
    let peer_addr = args.get(2).cloned();
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("Listening on {}", bind_addr);

    let outbound = peer_addr.map(|addr| tokio::spawn(async move { TcpStream::connect(addr).await }));

    let result = tokio::select! {
        inbound = listener.accept() => {
            let (stream, addr) = inbound?;
            println!("Accepted connection from {:?}", addr);
            handle_connection(stream, true).await
        }
        outbound_result = async {
            if let Some(outbound) = outbound {
                outbound.await?
            } else {
                futures::future::pending::<std::io::Result<TcpStream>>().await
            }
        } => {
            let stream = outbound_result?;
            println!("Outbound connection established");
            handle_connection(stream, false).await
        }
    };

    result?;
    println!("Application shutting down...");
    Ok(())
}