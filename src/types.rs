use std::{error::Error, io, pin::Pin, future::Future};

use noise_protocol::DhKeyPair;
use noise_rust_crypto::sensitive::Sensitive;
use tokio::io::{AsyncWrite, AsyncRead};

pub type DhKey = Sensitive<[u8; 32]>;
pub type DhPubKey = [u8; 32];
pub type NoiseKeyPair = DhKeyPair<DhKey, DhPubKey>;

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("noise error: {0}")]
    NoiseError(#[from] noise_protocol::Error),
    #[error("io error: {0}")]
    IoError(#[from] io::Error),
    #[error("key checker error: {0}")]
    KeyCheckerError(Box<dyn Error + Send>),
    #[error("key provider error: {0}")]
    KeyProviderError(Box<dyn Error + Send>),
    #[error("Local failure waiting for 0rtt data: {0}")]
    ZeroRttLocalFailure(io::Error),
}

pub type DynKeyChecker = Box<dyn Send + KeyChecker>;
pub type DynKeyProvider = Box<dyn Send + KeyProvider>;

pub trait KeyChecker {
    fn check(&mut self, key: DhPubKey, proof: Vec<u8>) -> Pin<Box<dyn Send + Future<Output = Result<(), Box<dyn Error + Send>>>>>;
}

impl<F: FnMut(DhPubKey, Vec<u8>) -> Pin<Box<dyn Send + Future<Output = Result<(), Box<dyn Error + Send>>>>>> KeyChecker for F {
    fn check(&mut self, key: DhPubKey, proof: Vec<u8>) -> Pin<Box<dyn Send + Future<Output = Result<(), Box<dyn Error + Send>>>>> {
        self(key, proof)
    }
}


pub trait KeyProvider {
    fn provide_proof(&mut self) -> Pin<Box<dyn Send + Future<Output = Result<Vec<u8>, Box<dyn Error + Send>>>>>;
}

impl<F: FnMut() -> Pin<Box<dyn Send + Future<Output = Result<Vec<u8>, Box<dyn Error + Send>>>>>> KeyProvider for F {
    fn provide_proof(&mut self) -> Pin<Box<dyn Send + Future<Output = Result<Vec<u8>, Box<dyn Error + Send>>>>> {
        self()
    }
}


pub trait SocketLike: AsyncRead + AsyncWrite + 'static + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + 'static + Send + Unpin> SocketLike for T {}
