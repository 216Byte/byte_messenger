use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::io::Write; 
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionKey {
    key: [u8; 32],
}

#[tokio::main]
async fn main() -> Result<()> {
    print!("\x1B[2J\x1B[1;1H"); 
    
    println!("===========================================");
    println!("   byte_messenger: Ephemeral P2P Messenger");
    println!("===========================================\n");

    println!("Select Mode:");
    println!("1. HOST (Wait for a friend to connect)");
    println!("2. CONNECT (Join a friend's lobby)");
    print!("\nSelection > ");
    
    std::io::stdout().flush()?;

    let mut mode = String::new();
    std::io::stdin().read_line(&mut mode)?;

    match mode.trim() {
        "1" => run_host().await?,
        "2" => run_client().await?,
        _ => println!("Invalid selection. Exiting."),
    }

    Ok(())
}

async fn run_host() -> Result<()> {
    // ask port
    print!("Enter Port to listen on (default 8080): ");
    std::io::stdout().flush()?;
    
    let mut port_input = String::new();
    std::io::stdin().read_line(&mut port_input)?;
    let port = port_input.trim();
    let port = if port.is_empty() { "8080" } else { port };

    // bind to address
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    println!("\n-------------------------------------------");
    println!("Hosting started!");
    
    // detect local ip
    if let Some(ip) = get_local_ip() {
        println!("Your Local IP: \x1b[32m{}:{}\x1b[0m", ip, port);
        println!("(If over the internet, give your friend your PUBLIC IP)");
    } else {
        println!("Listening on port {}. Share your IP:{} with your friend.", port, port);
    }
    println!("-------------------------------------------");
    println!("Waiting for connection...\n");

    let (socket, addr) = listener.accept().await?;
    println!("Incoming connection from: {}", addr);
    
    handle_connection(socket).await
}

async fn run_client() -> Result<()> {
    // ask full address
    print!("Enter Friend's Address (e.g., 192.168.1.5:8080): ");
    std::io::stdout().flush()?;
    
    let mut addr = String::new();
    std::io::stdin().read_line(&mut addr)?;
    let addr = addr.trim();
    
    println!("Connecting to {}...", addr);
    let socket = TcpStream::connect(addr).await?;
    println!("Connected!");

    handle_connection(socket).await
}

async fn handle_connection(mut socket: TcpStream) -> Result<()> {
    // generate ephemeral key pair
    let my_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&my_secret);

    // send pub key
    let my_pub_bytes = my_public.as_bytes();
    socket.write_all(my_pub_bytes).await?;

    // receive remote public key
    let mut remote_pub_bytes = [0u8; 32];
    socket.read_exact(&mut remote_pub_bytes).await?;
    let remote_public = PublicKey::from(remote_pub_bytes);

    // verification
    let fingerprint = Sha256::digest(remote_pub_bytes);
    println!("\nSECURITY CHECK");
    println!("Confirm this Fingerprint matches your friend's screen:");
    println!("\x1b[33m{}\x1b[0m", hex::encode(fingerprint)); // Yellow text
    println!("-------------------------------------------\n");

    // ECDH
    let shared_secret = my_secret.diffie_hellman(&remote_public);
    let session_key = SessionKey {
        key: *shared_secret.as_bytes(), 
    };

    println!("Encrypted Tunnel Established. Chat is live.\n");
    chat_loop(socket, Arc::new(session_key)).await
}

async fn chat_loop(socket: TcpStream, key: Arc<SessionKey>) -> Result<()> {
    let (mut rd, mut wr) = socket.into_split();
    let key_clone = key.clone();

    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024]; 
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(n) if n == 0 => return,
                Ok(n) => n,
                Err(_) => return,
            };

            let encrypted_msg = &buf[..n];
            if encrypted_msg.len() < 12 { continue; }
            
            let nonce_bytes = &encrypted_msg[..12];
            let ciphertext = &encrypted_msg[12..];

            let cipher = Aes256Gcm::new(&key_clone.key.into());
            let nonce = Nonce::from_slice(nonce_bytes);

            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    // clears the "you" prompt line
                    print!("\r\x1b[36mFriend:\x1b[0m {}\nYou: ", String::from_utf8_lossy(&plaintext));
                    std::io::stdout().flush().unwrap();
                }
                Err(_) => println!("\r[Decryption Failed - Message Tampered]"),
            }
        }
    });

    // handles messages
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    
    loop {
        print!("You: ");
        std::io::stdout().flush()?;
        
        line.clear();
        let bytes_read = stdin.read_line(&mut line).await?;
        if bytes_read == 0 { break; } // EOF

        let plaintext = line.trim().as_bytes();
        if plaintext.is_empty() { continue; }

        let cipher = Aes256Gcm::new(&key.key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
        
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(nonce.as_slice());
        packet.extend_from_slice(&ciphertext);

        if wr.write_all(&packet).await.is_err() {
            println!("Connection lost.");
            break;
        }
    }

    recv_task.abort();
    Ok(())
}

// to help the user find their local IP
fn get_local_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // don't actually connect, its just  to determine it
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}
