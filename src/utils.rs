use std::{path::Path, io::stdin};

use noise_protocol::{DH, DhKeyPair};
use noise_rust_crypto::{X25519, sensitive::Sensitive};
use tokio::{io::{self, AsyncReadExt, AsyncWriteExt}, fs::OpenOptions, sync::{mpsc, oneshot}};

use crate::types::{DhKey, NoiseKeyPair, DhPubKey};



pub async fn read_or_create_key(path: impl AsRef<Path>) -> Result<(NoiseKeyPair, bool), io::Error> {
    let path = path.as_ref();
    let res = OpenOptions::new()
        .read(true)
        .open(path)
        .await;

    Ok(match res {
        Ok(mut x) => {
            let mut key: DhKey = Sensitive::from(Default::default());
            let mut hex_key = vec![0u8; key.len() * 2];
            x.read_exact(&mut hex_key).await?;
            let hex_key = String::from_utf8(hex_key).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid hex key"))?;
            hex::decode_to_slice(hex_key, key.as_mut_slice()).unwrap();
            (DhKeyPair::from_private::<X25519>(key), false)
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = X25519::genkey(false);
            let hex = hex::encode(key.private.as_slice());
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(path)
                .await?
                .write_all(hex.as_bytes())
                .await?;
            (key, true)
        }
        Err(e) => return Err(e),
    })
}

pub async fn read_pub_key(path: impl AsRef<Path>) -> Result<DhPubKey, io::Error> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .await?;
    let mut key: DhPubKey =Default::default();
    let mut hex_key = vec![0u8; key.len() * 2];
    file.read_exact(&mut hex_key).await?;
    let hex_key = String::from_utf8(hex_key).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid hex key"))?;
    hex::decode_to_slice(hex_key, key.as_mut_slice()).unwrap();
    Ok(key)
}

pub type PriorityLineRequest = mpsc::Sender<oneshot::Sender<Result<String, io::Error>>>;

pub fn start_console_listener() -> (mpsc::Receiver<Result<String, io::Error>>, PriorityLineRequest) {
    let (lines_send, lines_recv) = mpsc::channel(1);
    let (priority_send, mut priority_recv) = mpsc::channel::<oneshot::Sender<Result<String, io::Error>>>(1);

    tokio::task::spawn_blocking(move || {
        for line in stdin().lines() {

            match priority_recv.try_recv() {
                Ok(x) => {
                    let _ = x.send(line);
                },
                Err(_) => match lines_send.blocking_send(line) {
                    Ok(_) => {},
                    Err(_) => break,
                }
            }

        }

    });

    (lines_recv, priority_send)
}

pub async fn priority_read_line(sender: PriorityLineRequest) -> Result<String, io::Error> {
    let (send, recv) = oneshot::channel();
    sender.send(send).await.expect("Priority line receiver closed");
    recv.await.unwrap()
}
