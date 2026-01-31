# byte_messenger

byte_messenger is a simple, encrypted, peer-to-peer chat application written in Rust. It allows users to host a session or connect to a host securely using ephemeral keys and AES-GCM encryption.

## Features

- 1-to-1 end-to-end encrypted messaging
- Ephemeral key exchange with fingerprint verification
- Cross-platform: Linux and Windows
- Lightweight and self-contained

## Requirements

- Rust (latest stable) installed
- Network access between host and client
- For hosting over VPN, port forwarding may be required

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/216Byte/byte_messenger.git
cd byte_messenger
```

### 2. Build the project

On Linux/macOS:

```bash
cargo build --release
```

On Windows (requires Rust and the `x86_64-pc-windows-gnu` target):

```bash
rustup target add x86_64-p
