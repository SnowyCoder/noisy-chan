# noisy-chan

Welcome to noisy-chan, my proof of concept implementation of a Noise pipe with Elligator steganography.

<p align="center">
  <img src="docs/images/icon_project.png" alt="Project logo" width="200px">
</p>


## Demo

```bash
$ wireshark        # Wireshark
$ cargo run -- -s  # First terminal
$ cargo run        # Second terminal
```

## Explaination
This is a demo of a [Noise Pipe](https://noiseprotocol.org/noise.html#noise-pipes) using [Elligator](https://elligator.org/) as a curve encoding to achieve perfect indistinguishability from random noise (as described in [the Noise specification 10.5](https://noiseprotocol.org/noise.html#handshake-indistinguishability)).

In other words? This Proof of Concept implements a secure channel that automatically exchanges static keys, or uses previous static keys if available, supporting also 0-Round-Trip-Time packet encryption. All of this while being completely indistinguishable from random noise.


## Theoretical Security
This should be a 1-to-1 implementation of a [Noise Pipe as described in the Noise specification](https://noiseprotocol.org/noise.html#noise-pipes), so it should be secure against most attacks:
1. When the XXfallback protocol is executed, the first message is vulnerable to Replay attacks and the static key of Bob (with its proof data) is being sent to an unauthenticated partner
2. When the IK protocol is executed with 0RTT enabled, the first 0RTT message is, from Bob's perspective, vulnerable for both KCI and Replay attacks. The message also has forward secrecy only regarding Alice's key, if Bob key gets compromised in the future the whole message can be deciphered. We don't suggest sending nor trusting private information in the 0RTT data, it should also not be used to execute any non-idempotent operation.
3. When the IK protocol is executed with 0RTT enabled, the second 0RTT message (Bob -> Alice) has only weak forward secrecy: An attacker knowing Bob's secret key may execute a XCI attack to Bob, the data sent in the 0RTT response will not have forward secrecy in respect to Alice's key, meaning that if the attacker manages to find Alice's private key in the future, the response could be decoded easily.

Apart from the cases listed above, every connection past the handshake phase should be fully encrypted, authenticated and forward-secrecy secured.

A passive attacker should also be unable to distinguish between a conversation and random noise, so the protocol should be 100% resistant to deep-packet-inspection firewalls. Other side-channel considerations should be taken into account (the library does not consider time side-channel discriminant). In other words, the exchanged data should be indistinguishable from a [padded uniform random blob](https://en.wikipedia.org/wiki/PURB_(cryptography)).

## Active attacker
During the Handshake, Bob (the server) is the first to send its public key to an unauthenticated initiator, this can be used by an active attacker to check whether the server is actually implementing a Noise pipe. The implications of this kind of attack is out of scope for this project.

## Practical Security
Putting the theoretical study behind, this code has been written by an IT student, not a cryptographer, I reimplemented Elligator curve-to-hash and all Noise exchange and padding (the lower-level Noise cryptography is handled by [blckngm's libray](https://github.com/blckngm/noise-rust) with some minor edits to X25519).
No kind of security analysis has been performed, please don't use this in any kind of security-critical application.

# Acknowledgements
The beautiful project icon has been drawn by Giorgia Nizzoli (contacts: [instagram](https://www.instagram.com/gioombra/), [telegram](https://t.me/gioombra)).

A special thanks goes to my professor, Luca Ferretti, that taught "Crittografia Applicata" perfectly.
