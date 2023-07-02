use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncWrite, AsyncWriteExt, AsyncReadExt, self, DuplexStream, split};
use std::io::Write;

use crate::types::{DhPubKey, HandshakeError, SocketLike};


pub const MESSAGE_FINAL_SIZE: usize = 1024;
pub const TAG_LEN: usize = 16;
pub const MAX_PAYLOAD_SIZE: usize = 1024 - TAG_LEN - 2;// Payload is ALWAYS encrypted

pub type NoiseHandshakeState = noise_protocol::HandshakeState<
    noise_rust_crypto::X25519,
    noise_rust_crypto::ChaCha20Poly1305,
    noise_rust_crypto::Blake2s,
>;
pub type NoiseCipherState = noise_protocol::CipherState<noise_rust_crypto::ChaCha20Poly1305>;

fn pad_payload<'a>(payload: &[u8], out: &'a mut [u8], handshake: &NoiseHandshakeState) -> &'a [u8] {
    let overhead = handshake.get_next_message_overhead();
    if payload.len() > MESSAGE_FINAL_SIZE - 2 - overhead {
        panic!("Message too long");
    }
    let to_send = &mut out[..MESSAGE_FINAL_SIZE - overhead];
    let mut writer = &mut *to_send;
    writer.write_all((payload.len() as u16).to_ne_bytes().as_slice()).unwrap();
    writer.write_all(payload).unwrap();
    // Don't really care about the rest, let's fill it with 0
    writer.fill(0);

    to_send
}

fn unpad_payload(payload: &[u8]) -> &[u8] {
    assert!(payload.len() > 2);
    let size = u16::from_ne_bytes(payload[0..2].try_into().unwrap()) as usize;
    &payload[2..size+2]
}


pub struct ScratchPad<S: SocketLike> {
    pub socket: S,
    pub buffer: [u8; MESSAGE_FINAL_SIZE],
    pub cipher_buffer: [u8; MESSAGE_FINAL_SIZE],
}

impl<S: SocketLike> ScratchPad<S> {
    pub fn new(socket: S) -> Self {
        ScratchPad {
            socket,
            buffer: [0u8; MESSAGE_FINAL_SIZE],
            cipher_buffer: [0u8; MESSAGE_FINAL_SIZE],
        }
    }

    pub async fn pad_and_send_from_ciph(&mut self, handshake: &mut NoiseHandshakeState, len: usize) -> Result<(), HandshakeError> {
        handshake.write_message(pad_payload(&self.cipher_buffer[..len], &mut self.buffer, handshake), &mut self.cipher_buffer)?;
        self.socket.write_all(&self.cipher_buffer).await?;
        Ok(())
    }

    pub async fn pad_and_send(&mut self, handshake: &mut NoiseHandshakeState, data: &[u8]) -> Result<(), HandshakeError> {
        handshake.write_message(pad_payload(data, &mut self.buffer, handshake), &mut self.cipher_buffer)?;
        self.socket.write_all(&self.cipher_buffer).await?;
        Ok(())
    }

    pub async fn read<'a>(&'a mut self, handshake: &mut NoiseHandshakeState) -> Result<&'a [u8], HandshakeError> {
        self.socket.read_exact(&mut self.cipher_buffer).await?;
        self.read_no_io(handshake)
    }

    pub fn read_no_io<'a>(&'a mut self, handshake: &mut NoiseHandshakeState) -> Result<&'a [u8], HandshakeError> {
        let data = &mut self.buffer[..MESSAGE_FINAL_SIZE - handshake.get_next_message_overhead()];
        handshake.read_message(&self.cipher_buffer, data)?;
        Ok(unpad_payload(data))
    }

    pub fn read_key(&self, key: &mut DhPubKey) {
        let len = key.len();
        key.copy_from_slice(&self.cipher_buffer[0..len]);
    }

    pub async fn send_key(&mut self, key: &DhPubKey) -> Result<(), HandshakeError> {
        self.cipher_buffer[..key.len()].copy_from_slice(key);
        OsRng.fill_bytes(&mut self.cipher_buffer[key.len()..]);
        self.socket.write_all(&self.cipher_buffer).await?;
        Ok(())
    }

}

pub enum ZRTTStatus {
    Resend(Vec<u8>),
    Ignore,
}

pub async fn encode_and_send<S: AsyncWrite + Unpin>(write: &mut S, cipher: &mut NoiseCipherState, buffer: &mut [u8], read_len: usize) -> io::Result<()> {
    buffer[0..2].copy_from_slice(&(read_len as u16).to_ne_bytes());
    buffer[2+read_len..].fill(0);
    let size = cipher.encrypt_in_place(buffer, buffer.len() - TAG_LEN);
    assert_eq!(size, MESSAGE_FINAL_SIZE);

    write.write_all(buffer).await
}


pub async fn start_transport<S: SocketLike>(stream: DuplexStream, socket: S, mut send_cipher: NoiseCipherState, mut recv_cipher: NoiseCipherState, rttd: ZRTTStatus) {
    let (mut read, mut write) = split(socket);

    let (mut stream_read, mut stream_write) = split(stream);

    let first_data_to_send = match rttd {
        ZRTTStatus::Resend(x) => {
            // x is data that needs to be re-sent
            Some(x)
        },
        ZRTTStatus::Ignore => None,
    };

    // inbound
    tokio::spawn(async move {
        let mut buffer = [0u8; MESSAGE_FINAL_SIZE];
        loop {
            if read.read_exact(&mut buffer).await.is_err() {
                eprintln!("Read error");
                return;
            }
            let size = match recv_cipher.decrypt_in_place(&mut buffer, MESSAGE_FINAL_SIZE) {
                Ok(size) => size,
                Err(_) => {
                    eprintln!("Decryption error");
                    break;
                }, // Decryption error
            };
            let data = &buffer[..size];
            let read_len = u16::from_ne_bytes(data[0..2].try_into().unwrap()) as usize;
            if stream_write.write_all(&data[2..read_len+2]).await.is_err() {
                eprintln!("Error writing to duplex stream");
                break
            }
        }
    });
    // outbound
    tokio::spawn(async move {
        let mut buffer = [0u8; MESSAGE_FINAL_SIZE];

        if let Some(data) = first_data_to_send {
            buffer[2..data.len() + 2].copy_from_slice(&data);
            if encode_and_send(&mut write, &mut send_cipher, buffer.as_mut_slice(), data.len()).await.is_err() {
                return
            }
        }

        loop {
            let read_len = match stream_read.read(&mut buffer[2..MAX_PAYLOAD_SIZE+2]).await {
                Err(_) => break,
                Ok(x) => x,
            };
            if encode_and_send(&mut write, &mut send_cipher, buffer.as_mut_slice(), read_len).await.is_err() {
                break
            }
        }
    });
}
