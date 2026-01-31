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
git clone <repository-url>
cd byte_messenger
```

### 2. Build the project

On Linux/macOS:

```bash
cargo build --release
```

On Windows (requires Rust and the `x86_64-pc-windows-gnu` target):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

### 3. Run the application

On Linux/macOS:

```bash
./target/release/byte_messenger
```

On Windows:

```bash
.\target\x86_64-pc-windows-gnu\release\byte_messenger.exe
```

### 4. Usage

- When prompted, choose:

```
1 - Host a session
2 - Connect to a host
```

- **Hosting:** The host will display their IP and listening port. Share this with your friend.  
- **Client:** Enter the host’s IP and port when prompted.  

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
