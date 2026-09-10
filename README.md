# Hexatino

A minimal, encrypted peer-to-peer CLI chat client written in Rust.

Hexatino is intentionally small: it gives you a secure, terminal-based chat over TCP without accounts, servers, or configuration files.

## Features

- Peer-to-peer TCP chat
- End-to-end encryption using XSalsa20-Poly1305 (`crypto_box` / `SalsaBox`)
- SHA-256 public key fingerprints in Base58 for manual verification
- Async networking with Tokio
- Compact binary protocol via `bincode`
- Cross-platform terminal UI with `crossterm`

## Requirements

- Rust (stable)
- A terminal that supports ANSI escape sequences

## Build

```bash
git clone https://github.com/ramilalgayev/hexatino.git
cd hexatino
cargo build --release
```

Run with:

```bash
./hexatino <BIND_ADDR> [PEER_ADDR]
```

## Usage

Start a listener:

```bash
./hexatino 0.0.0.0:9000
```

Connect to a peer:

```bash
./hexatino 127.0.0.1:9001 127.0.0.1:9000
```

After connecting, Hexatino displays the peer fingerprint. Verify it over a trusted channel before accepting the connection.

## Security Notes

- Messages are encrypted with authenticated encryption (`SalsaBox`).
- Fingerprint verification is manual and is the main defense against man-in-the-middle attacks.
- This version does not implement forward secrecy.
- Hexatino is early software. Do not rely on it for high-risk communications.

## Status

Version 0.1.0. The protocol and CLI may change.

## Contributing

Issues and pull requests are welcome.

## License

See the repository for license information.
