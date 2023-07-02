use std::{error::Error, pin::Pin, path::PathBuf, io::{self, ErrorKind}};

use channel::{open_receiver, open_initiator};
use types::{KeyChecker, KeyProvider, DhPubKey};
use clap::{Command, arg};
use tokio::{net::{TcpListener, TcpStream}, io::{split, BufReader, AsyncBufReadExt, DuplexStream, AsyncWriteExt}, fs::{File, OpenOptions}, sync::mpsc};
use utils::{read_or_create_key, PriorityLineRequest, start_console_listener, read_pub_key};

use crate::utils::priority_read_line;

mod channel;
mod types;
mod utils;

#[derive(thiserror::Error, Debug)]
enum KeyRejectionError {
    #[error("{0}")]
    UserRejection(String),
}

#[derive(Clone)]
struct FileKeyChecker {
    known_keys: PathBuf,
    last_key_store: Option<PathBuf>,
    terminal_handler: PriorityLineRequest,
}

impl KeyChecker for FileKeyChecker {
    fn check(&mut self, key: DhPubKey, proof: Vec<u8>) -> Pin<Box<dyn Send + std::future::Future<Output = Result<(), Box<dyn Error + Send>>>>> {
        let known_path = self.known_keys.clone();
        let last_path = self.last_key_store.clone();
        let line_req = self.terminal_handler.clone();
        Box::pin(async move {
            let keyhex = hex::encode(key);

            println!("Key is: {keyhex}");
            println!("Proof: {}", String::from_utf8(proof).unwrap_or_else(|_| "unknown".into()));

            if known_path.exists() {
                let reader = BufReader::new(File::open(&known_path).await.map_err(|x| Box::new(x) as Box<_>)?);
                let mut lines: tokio::io::Lines<BufReader<File>> = reader.lines();

                while let Some(line) = lines.next_line().await.map_err(|x| Box::new(x) as Box<_>)? {
                    if line == keyhex {
                        return Ok(())
                    }
                }
            }

            let res = loop {
                println!("Accept? (y/n)");
                let line = priority_read_line(line_req.clone()).await.expect("Error reading line");
                match line.trim().to_lowercase().as_str() {
                    "y" | "yes" | "t" | "true" => break true,
                    "n" | "no" | "f" | "false" => break false,
                    _ => {},
                }
            };
            if !res {
                return Err(Box::new(KeyRejectionError::UserRejection("Key not accepted".to_owned())) as Box<_>)
            }
            let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(known_path)
                    .await
                    .expect("Error opening known_key file while appending key");

            let to_write = keyhex + "\n";
            file.write_all(to_write.as_bytes()).await.expect("Couldn't write to known keys");

            if let Some(last_path) = last_path {
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(last_path)
                    .await
                    .expect("Error opening last_key file");

                file.write_all(to_write.as_bytes()).await.expect("Couldn't write to last_key file");
            }

            Ok(())
        })
    }
}

struct StaticKeyProvider(Vec<u8>);

impl KeyProvider for StaticKeyProvider {
    fn provide_proof(&mut self) -> Pin<Box<dyn Send + std::future::Future<Output = Result<Vec<u8>, Box<dyn Error + Send>>>>> {
        let data = self.0.clone();
        Box::pin(async move {
            Ok(data)
        })
    }
}

async fn stream_to_terminal(stream: DuplexStream, mut term: mpsc::Receiver<Result<String, io::Error>>) {
    let (recv, mut send) = split(stream);

    let sender = tokio::spawn(async move {
        while let Some(line) = term.recv().await {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };
            let line = line + "\n";
            let res = send.write_all(line.as_bytes()).await;
            if let Err(e) = res {
                eprintln!("Error writing to duplex: {}", e);
                break
            }
        }
    });

    let recv = BufReader::new(recv);
    let mut lines = recv.lines();
    while let Some(line) = lines.next_line().await.expect("Error reading line from stdin") {
        println!(">{line}");
    }
    sender.await.expect("Error waiting for sender thread");
}

async fn run_client(addr: &str) {
    let (key, created) = read_or_create_key("keys/client_key").await.expect("Reading server key");

    eprintln!("# Connecting to: {addr}");
    let socket = TcpStream::connect(addr).await.expect("Error connecting to server");

    if created {
        eprintln!("# Could not load static key from file, new key generated");
    } else {
        eprintln!("# Loaded previous static key from file");
    }
    eprintln!("# Static: {}", hex::encode(key.public));

    let (term, prior) = start_console_listener();
    let key_policy = Box::new(FileKeyChecker {
        known_keys: "keys/client_keys_known".into(),
        last_key_store: Some("keys/server_last_key".into()),
        terminal_handler: prior,
    });
    let last_server_key = match read_pub_key("keys/server_last_key").await {
        Ok(x) => {
            eprintln!("# Using loaded server last key: {}", hex::encode(x));
            Some(x)
        }
        Err(e) => {
            eprintln!("# Cannot load server last key: {}", e);
            eprintln!("# Starting XXfallback protocol");
            None
        }
    };
    let key_provider = Box::new(StaticKeyProvider(b"client data proof".to_vec()));

    let (stream, handshake_handle) = open_initiator(socket, key,  last_server_key, key_policy.clone(), Some(key_provider), true);

    tokio::spawn(async {
        match handshake_handle.await {
            Ok(Ok(())) => eprintln!("# Handshake completed successfully"),
            Ok(Err(e)) => eprintln!("# Handshake error: {e}"),
            Err(e) => eprintln!("# Error waiting for handshake: {e}"),
        }
    });

    stream_to_terminal(stream, term).await;
}

async fn run_server(addr: &str) {
    let (key, created) = read_or_create_key("keys/server_key").await.expect("Reading server key");
    let listener = TcpListener::bind(addr).await.expect("Error binding address");

    if created {
        eprintln!("# Could not load static key from file, new key generated");
    } else {
        eprintln!("# Loaded previous static key from file");
    }
    eprintln!("# Static: {}", hex::encode(key.public));
    eprintln!("# Listening on: {addr}");

    let (socket, _addr) = listener.accept().await.expect("Error connecting to client");
    let (term, prior) = start_console_listener();
    let key_policy = Box::new(FileKeyChecker {
        known_keys: "keys/server_keys_known".into(),
        last_key_store: None,
        terminal_handler: prior
    });
    let key_provider = Box::new(StaticKeyProvider(b"server data proof".to_vec()));

    let (stream, handshake_handle) = open_receiver(socket, key,  key_policy.clone(), Some(key_provider), true);

    tokio::spawn(async {
        match handshake_handle.await {
            Ok(Ok(())) => eprintln!("# Handshake completed successfully"),
            Ok(Err(e)) => eprintln!("# Handshake error: {e}"),
            Err(e) => eprintln!("# Error waiting for handshake: {e}"),
        }
    });
    stream_to_terminal(stream, term).await;
}

#[tokio::main]
async fn main() {
    let matches = Command::new("noisychan")
        .arg(arg!(-s --server "Server mode"))
        .arg(arg!(-a --address <ADDRESS> "Address").default_value("127.0.0.1:9898"))
        .get_matches();

    // Create keys folder.
    match tokio::fs::create_dir("keys").await {
        Ok(()) => {},
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {},
        Err(e) => {
            panic!("Error creating user directory, {}", e);
        }
    }

    let addr = matches.get_one::<String>("address").unwrap();

    if matches.get_flag("server") {
        run_server(addr).await;
    } else {
        run_client(addr).await;
    }
    println!("all done.");
}
