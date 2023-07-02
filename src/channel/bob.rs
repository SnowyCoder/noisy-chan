use noise_protocol::{HandshakeStateBuilder, patterns, ErrorKind};
use tokio::{io::{DuplexStream, AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt}, task::JoinHandle};

use crate::{types::{SocketLike, NoiseKeyPair, DynKeyChecker, DynKeyProvider, HandshakeError, DhPubKey}, channel::common::ZRTTStatus};

use super::common::{ScratchPad, MESSAGE_FINAL_SIZE, start_transport, NoiseCipherState};



struct CommunicatorBob<S: SocketLike> {
    local_static: NoiseKeyPair,
    key_checker: DynKeyChecker,
    key_provider: Option<DynKeyProvider>,
    scratchpad: ScratchPad<S>,
    stream: DuplexStream,
    is_0rtt: bool,
}


impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> CommunicatorBob<S> {
    async fn start_bob(&mut self) -> Result<(NoiseCipherState, NoiseCipherState, ZRTTStatus), HandshakeError> {
        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(patterns::noise_ik())
            .set_is_initiator(false)
            .set_is_elligator_encoded(true)
            .set_prologue(&[])
            .set_s(self.local_static.clone());
        let mut handshake = builder.build_handshake_state();

        // 1. try IK
        let data = match self.scratchpad.read(&mut handshake).await {
            Ok(x) => x,
            Err(HandshakeError::NoiseError(e)) if e.kind() == ErrorKind::Decryption => {
                return self.bob_fallback().await;
            },
            Err(e) => return Err(e),
        };
        self.stream.write_all(data).await?;
        let len = if self.is_0rtt {
            self.stream.read(&mut self.scratchpad.cipher_buffer).await?
        } else {
            0
        };
        self.scratchpad.pad_and_send_from_ciph(&mut handshake, len).await?;

        assert!(handshake.completed());
        // Done :3
        let (c1, c2) = handshake.get_ciphers();

        Ok((c1, c2, ZRTTStatus::Ignore))
    }

    async fn bob_fallback(&mut self) -> Result<(NoiseCipherState, NoiseCipherState, ZRTTStatus), HandshakeError> {
        let mut pubkey: DhPubKey = Default::default();
        self.scratchpad.read_key(&mut pubkey);

        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(patterns::noise_xx_fallback())
            .set_is_initiator(true)
            .set_is_elligator_encoded(true)
            .set_prologue(&[])
            .set_s(self.local_static.clone())
            .set_re(pubkey);
        let mut handshake = builder.build_handshake_state();

        let key_data = match self.key_provider.as_mut() {
            Some(prov) => prov.provide_proof().await.map_err(|e| HandshakeError::KeyProviderError(e))?,
            None => Vec::new(),
        };
        //  <- e, ee, s, es
        self.scratchpad.pad_and_send(&mut handshake, &key_data).await?;

        // -> s, se
        let key_data = self.scratchpad.read(&mut handshake).await?;
        self.key_checker.check(handshake.get_rs().unwrap(), key_data.to_vec())
                .await
                .map_err(|e| HandshakeError::KeyCheckerError(e))?;

        // Done :3
        assert!(handshake.completed());
        // Done :3
        let (c1, c2) = handshake.get_ciphers();

        Ok((c1, c2, ZRTTStatus::Ignore))
    }

    async fn run(mut self) -> Result<(), HandshakeError> {
        let res = self.start_bob().await?;

        let (send_cipher, recv_cipher, zrtt_data) = res;

        start_transport(self.stream, self.scratchpad.socket, recv_cipher, send_cipher, zrtt_data).await;

        Ok(())
    }
}

pub fn open_receiver<S: SocketLike>(socket: S, local_static: NoiseKeyPair, key_checker: DynKeyChecker, key_provider: Option<DynKeyProvider>, is_0rtt: bool) -> (DuplexStream, JoinHandle<Result<(), HandshakeError>>) {
    let (client, server) = tokio::io::duplex(MESSAGE_FINAL_SIZE);

    let scratchpad = ScratchPad::new(socket);
    let bob = CommunicatorBob {
        local_static,
        key_checker,
        key_provider,
        scratchpad,
        stream: server,
        is_0rtt
    };

    let handshake_waiter = tokio::spawn(bob.run());

    (client, handshake_waiter)
}
