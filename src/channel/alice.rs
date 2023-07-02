use noise_protocol::{HandshakeStateBuilder, patterns, DH};
use noise_rust_crypto::X25519;
use tokio::{io::{DuplexStream, AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt}, task::JoinHandle};

use crate::types::{SocketLike, DhPubKey, NoiseKeyPair, DynKeyChecker, DynKeyProvider, HandshakeError};

use super::common::{ScratchPad, NoiseCipherState, MAX_PAYLOAD_SIZE, ZRTTStatus, start_transport, MESSAGE_FINAL_SIZE};


struct CommunicatorAlice<S: SocketLike> {
    local_static: NoiseKeyPair,
    remote_public: Option<DhPubKey>,
    key_checker: DynKeyChecker,
    key_provider: Option<DynKeyProvider>,
    local_ephemeral: NoiseKeyPair,
    scratchpad: ScratchPad<S>,
    stream: DuplexStream,
    is_0rtt: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> CommunicatorAlice<S> {
    async fn start_ik(&mut self, remote_public: DhPubKey) -> Result<(NoiseCipherState, NoiseCipherState, ZRTTStatus), HandshakeError> {
        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(patterns::noise_ik())
            .set_is_initiator(true)
            .set_is_elligator_encoded(true)
            .set_prologue(&[])
            .set_s(self.local_static.clone())
            .set_e(self.local_ephemeral.clone())
            .set_rs(remote_public);
        let mut handshake = builder.build_handshake_state();

        let mut rtt_data = Vec::new();

        if self.is_0rtt {
            rtt_data = vec![0u8; MAX_PAYLOAD_SIZE - handshake.get_next_message_overhead()];
            let len = self.stream.read(&mut rtt_data).await.map_err(HandshakeError::ZeroRttLocalFailure)?;
            rtt_data.truncate(len)
        }

        // -> e, es, s, ss
        self.scratchpad.pad_and_send(&mut handshake, &rtt_data).await?;

        // theoretically
        // <- e, ee, se
        let res = self.scratchpad.read(&mut handshake).await;

        match res {
            Ok(data) => {
                // We're done!

                // We don't care if we don't receive anything
                let _ = self.stream.write_all(data).await;

                let (c1, c2) = handshake.get_ciphers();
                Ok((c1, c2, ZRTTStatus::Ignore))
            },
            Err(HandshakeError::NoiseError(e)) if e.kind() == noise_protocol::ErrorKind::Decryption => {
                // Fallback to XXfallback, but we'll need to send 0rtt data later.
                let (c1, c2) = self.continue_fallback(false).await?;
                Ok((c1, c2, ZRTTStatus::Resend(rtt_data)))
            },
            Err(e) => Err(e)
        }
    }

    async fn continue_fallback(&mut self, needs_to_read: bool) -> Result<(NoiseCipherState, NoiseCipherState), HandshakeError> {
        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(patterns::noise_xx_fallback())
            .set_is_initiator(false)
            .set_is_elligator_encoded(true)
            .set_prologue(&[])
            .set_s(self.local_static.clone())
            .set_e(self.local_ephemeral.clone());
        let mut handshake = builder.build_handshake_state();

        if needs_to_read {
            self.scratchpad.socket.read_exact(&mut self.scratchpad.cipher_buffer).await?;
        }
        let keydata = self.scratchpad.read_no_io(&mut handshake)?;

        // This means... check the new key!
        self.key_checker.check(handshake.get_rs().unwrap(), keydata.to_vec())
                .await
                .map_err(|e| HandshakeError::KeyCheckerError(e))?;
        let resp_data = match self.key_provider.as_mut() {
            Some(prov) => prov.provide_proof().await.map_err(|e| HandshakeError::KeyProviderError(e))?,
            None => Vec::new(),
        };

        self.scratchpad.pad_and_send(&mut handshake, &resp_data).await?;

        assert!(handshake.completed());
        // Done :3
        Ok(handshake.get_ciphers())
    }

    async fn start_xx(&mut self) -> Result<(NoiseCipherState, NoiseCipherState, ZRTTStatus), HandshakeError> {
        // send ephemeral
        let epub = &self.local_ephemeral.public;
        self.scratchpad.send_key(epub).await?;

        let (c1, c2) = self.continue_fallback(true).await?;
        Ok((c1, c2, ZRTTStatus::Ignore))
    }

    async fn run(mut self) -> Result<(), HandshakeError> {
        let res = match self.remote_public {
            Some(x) => self.start_ik(x).await?,
            None => self.start_xx().await?,
        };

        let (send_cipher, recv_cipher, zrtt_data) = res;

        start_transport(self.stream, self.scratchpad.socket, send_cipher, recv_cipher, zrtt_data).await;

        Ok(())
    }
}

pub fn open_initiator<S: SocketLike>(socket: S, local_static: NoiseKeyPair, remote_public: Option<DhPubKey>, key_checker: DynKeyChecker, key_provider: Option<DynKeyProvider>, is_0rtt: bool) -> (DuplexStream, JoinHandle<Result<(), HandshakeError>>) {
    let (client, server) = tokio::io::duplex(MESSAGE_FINAL_SIZE);

    let scratchpad = ScratchPad::new(socket);
    let alice = CommunicatorAlice {
        local_static,
        remote_public,
        key_checker,
        key_provider,
        local_ephemeral: X25519::genkey(true),
        scratchpad,
        stream: server,
        is_0rtt
    };

    let handshake_waiter = tokio::spawn(alice.run());


    (client, handshake_waiter)
}
