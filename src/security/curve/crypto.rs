use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{PeerConfig, ProtocolError, SecurityRole};

#[derive(Clone, PartialEq, Eq)]
struct TrafficKey {
    key: [u8; 32],
    nonce_prefix: [u8; 4],
    seq: u64,
    bytes: u64,
    epoch: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SecureChannel {
    send: TrafficKey,
    recv: TrafficKey,
    transcript_hash: [u8; 32],
    rekey_messages: u64,
    rekey_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct KeySchedule {
    exchange: [u8; 32],
    local_auth: [u8; 32],
    peer_auth: [u8; 32],
}

impl core::fmt::Debug for TrafficKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficKey").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureChannel").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeySchedule").finish_non_exhaustive()
    }
}

impl KeySchedule {
    pub(super) fn client(
        client_eph_secret: [u8; 32],
        client_static_secret: [u8; 32],
        server_eph_public: [u8; 32],
        server_static_public: [u8; 32],
    ) -> Self {
        Self {
            exchange: shared_secret(client_eph_secret, server_eph_public),
            local_auth: shared_secret(client_static_secret, server_eph_public),
            peer_auth: shared_secret(client_eph_secret, server_static_public),
        }
    }

    pub(super) fn server(
        server_eph_secret: [u8; 32],
        server_static_secret: [u8; 32],
        client_eph_public: [u8; 32],
        client_static_public: [u8; 32],
    ) -> Self {
        Self {
            exchange: shared_secret(server_eph_secret, client_eph_public),
            local_auth: shared_secret(server_eph_secret, client_static_public),
            peer_auth: shared_secret(server_static_secret, client_eph_public),
        }
    }

    pub(super) fn parts(&self) -> [&[u8]; 3] {
        [&self.exchange, &self.local_auth, &self.peer_auth]
    }
}

pub(super) fn derive_channel(
    config: &PeerConfig,
    transcript: &[u8],
    client_nonce_seed: [u8; 8],
    server_nonce_seed: [u8; 8],
    schedule: &KeySchedule,
) -> Result<SecureChannel, ProtocolError> {
    let parts = schedule.parts();
    let c2s_key = derive_key(transcript, &parts, b"curve-rs-c2s-key")?;
    let s2c_key = derive_key(transcript, &parts, b"curve-rs-s2c-key")?;
    let c2s_prefix = derive_nonce_prefix(
        transcript,
        &parts,
        b"curve-rs-c2s-prefix",
        client_nonce_seed,
    )?;
    let s2c_prefix = derive_nonce_prefix(
        transcript,
        &parts,
        b"curve-rs-s2c-prefix",
        server_nonce_seed,
    )?;
    let (send_key, recv_key, send_prefix, recv_prefix) = match config.security_role {
        SecurityRole::Client => (c2s_key, s2c_key, c2s_prefix, s2c_prefix),
        SecurityRole::Server => (s2c_key, c2s_key, s2c_prefix, c2s_prefix),
    };
    let curve = config
        .security
        .curve
        .as_ref()
        .ok_or(ProtocolError::MissingCurveConfig)?;

    Ok(SecureChannel {
        send: TrafficKey {
            key: send_key,
            nonce_prefix: send_prefix,
            seq: 0,
            bytes: 0,
            epoch: 0,
        },
        recv: TrafficKey {
            key: recv_key,
            nonce_prefix: recv_prefix,
            seq: 0,
            bytes: 0,
            epoch: 0,
        },
        transcript_hash: sha256(transcript),
        rekey_messages: curve.rekey_messages,
        rekey_bytes: curve.rekey_bytes,
    })
}

pub(super) fn seal_message(
    channel: &mut SecureChannel,
    plaintext: &Bytes,
) -> Result<Bytes, ProtocolError> {
    rotate_if_needed(
        &mut channel.send,
        channel.rekey_messages,
        channel.rekey_bytes,
        channel.transcript_hash,
    )?;

    let seq = channel.send.seq;
    let nonce = message_nonce(channel.send.nonce_prefix, seq);
    let mut buffer = BytesMut::from(plaintext.as_ref());
    let tag = encrypt_in_place(
        &channel.send.key,
        nonce,
        &channel.transcript_hash,
        &mut buffer,
    )?;

    let mut out = BytesMut::with_capacity(8 + buffer.len() + tag.len());
    out.put_u64(seq);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);

    channel.send.seq = channel.send.seq.saturating_add(1);
    channel.send.bytes = channel.send.bytes.saturating_add(plaintext.len() as u64);
    Ok(out.freeze())
}

pub(super) fn open_message(
    channel: &mut SecureChannel,
    payload: Bytes,
) -> Result<Bytes, ProtocolError> {
    if payload.len() < 8 + 16 {
        return Err(ProtocolError::InvalidEncryptedMessage);
    }

    rotate_if_needed(
        &mut channel.recv,
        channel.rekey_messages,
        channel.rekey_bytes,
        channel.transcript_hash,
    )?;

    let mut payload = payload;
    let seq = payload.get_u64();
    if seq != channel.recv.seq {
        return Err(ProtocolError::CurveReplayDetected);
    }

    if payload.len() < 16 {
        return Err(ProtocolError::InvalidEncryptedMessage);
    }
    let cipher_len = payload.len() - 16;
    let mut cipher = BytesMut::from(&payload[..cipher_len]);
    let tag: [u8; 16] = payload[cipher_len..]
        .try_into()
        .map_err(|_| ProtocolError::InvalidEncryptedMessage)?;

    decrypt_in_place(
        &channel.recv.key,
        message_nonce(channel.recv.nonce_prefix, seq),
        &channel.transcript_hash,
        &mut cipher,
        tag,
    )?;

    channel.recv.seq = channel.recv.seq.saturating_add(1);
    channel.recv.bytes = channel.recv.bytes.saturating_add(cipher.len() as u64);
    Ok(cipher.freeze())
}

pub(super) fn control_nonce(label: u8) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[11] = label;
    nonce
}

pub(super) fn derive_key(
    transcript: &[u8],
    parts: &[&[u8]],
    label: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    hkdf_expand_key(&sha256(transcript), parts, label)
}

pub(super) fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    hasher.finalize().into()
}

pub(super) fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::{OsRng, RngCore};

    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub(super) fn public_from_secret(secret: [u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(secret);
    PublicKey::from(&secret).to_bytes()
}

pub(super) fn shared_secret(secret: [u8; 32], peer_public: [u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(peer_public);
    secret.diffie_hellman(&public).to_bytes()
}

pub(super) fn encrypt_aead(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &Bytes,
) -> Result<Bytes, ProtocolError> {
    let mut buffer = BytesMut::from(plaintext.as_ref());
    let tag = encrypt_in_place(key, nonce, aad, &mut buffer)?;
    buffer.extend_from_slice(&tag);
    Ok(buffer.freeze())
}

pub(super) fn decrypt_aead(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &Bytes,
) -> Result<Bytes, ProtocolError> {
    if ciphertext.len() < 16 {
        return Err(ProtocolError::CurveAuthenticationFailed);
    }

    let cipher_len = ciphertext.len() - 16;
    let mut buffer = BytesMut::from(&ciphertext[..cipher_len]);
    let tag: [u8; 16] = ciphertext[cipher_len..]
        .try_into()
        .map_err(|_| ProtocolError::CurveAuthenticationFailed)?;
    decrypt_in_place(key, nonce, aad, &mut buffer, tag)?;
    Ok(buffer.freeze())
}

fn rotate_if_needed(
    key: &mut TrafficKey,
    rekey_messages: u64,
    rekey_bytes: u64,
    transcript_hash: [u8; 32],
) -> Result<(), ProtocolError> {
    let message_limit_hit =
        rekey_messages != 0 && key.seq != 0 && key.seq.is_multiple_of(rekey_messages);
    let byte_limit_hit = rekey_bytes != 0 && key.bytes >= rekey_bytes;
    if !message_limit_hit && !byte_limit_hit {
        return Ok(());
    }

    let mut info = BytesMut::with_capacity(16);
    info.extend_from_slice(&key.nonce_prefix);
    info.put_u64(key.epoch);
    key.key = hkdf_expand_key(
        &transcript_hash,
        &[&key.key, &key.nonce_prefix, &info],
        b"curve-rs-rekey-key",
    )?;
    key.nonce_prefix = derive_nonce_prefix(
        &transcript_hash,
        &[&key.key, &key.nonce_prefix, &info],
        b"curve-rs-rekey-prefix",
        [0; 8],
    )?;
    key.bytes = 0;
    key.epoch = key.epoch.saturating_add(1);
    Ok(())
}

fn message_nonce(prefix: [u8; 4], seq: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn derive_nonce_prefix(
    transcript: &[u8],
    parts: &[&[u8]],
    label: &[u8],
    seed: [u8; 8],
) -> Result<[u8; 4], ProtocolError> {
    let mut material = Vec::with_capacity(parts.len() + 1);
    material.extend_from_slice(parts);
    material.push(&seed);
    hkdf_expand_array(&sha256(transcript), &material, label)
}

fn hkdf_expand_array<const N: usize>(
    salt: &[u8; 32],
    parts: &[&[u8]],
    label: &[u8],
) -> Result<[u8; N], ProtocolError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut ikm = BytesMut::new();
    for part in parts {
        ikm.extend_from_slice(part);
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut out = [0_u8; N];
    hk.expand(label, &mut out)
        .map_err(|_| ProtocolError::CurveHandshake("invalid HKDF output length"))?;
    Ok(out)
}

fn hkdf_expand_key(
    salt: &[u8; 32],
    parts: &[&[u8]],
    label: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    hkdf_expand_array(salt, parts, label)
}

fn encrypt_in_place(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    buffer: &mut BytesMut,
) -> Result<[u8; 16], ProtocolError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag: Tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buffer)
        .map_err(|_| ProtocolError::CurveAuthenticationFailed)?;
    Ok(tag.into())
}

fn decrypt_in_place(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    buffer: &mut BytesMut,
    tag: [u8; 16],
) -> Result<(), ProtocolError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            aad,
            buffer,
            Tag::from_slice(&tag),
        )
        .map_err(|_| ProtocolError::CurveAuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        KeySchedule, SecureChannel, derive_channel, open_message, public_from_secret, seal_message,
    };
    use crate::{
        CurveConfig, CurveKeyPair, LinkScope, PeerConfig, ProtocolError, SecurityConfig,
        SecurityRole, SocketType,
    };

    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("expected Ok(..), got Err({err:?})"),
        }
    }

    fn err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected Err(..), got Ok(..)"),
            Err(err) => err,
        }
    }

    fn sample_channels(
        rekey_messages: u64,
        rekey_bytes: u64,
    ) -> Result<(SecureChannel, SecureChannel), ProtocolError> {
        let client_eph_secret = [1; 32];
        let client_static_secret = [2; 32];
        let server_eph_secret = [3; 32];
        let server_static_secret = [4; 32];

        let client_eph_public = public_from_secret(client_eph_secret);
        let client_static_public = public_from_secret(client_static_secret);
        let server_eph_public = public_from_secret(server_eph_secret);
        let server_static_public = public_from_secret(server_static_secret);

        let client_config =
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(CurveConfig {
                    local_static_keypair: CurveKeyPair::from_secret(client_static_secret),
                    rekey_messages,
                    rekey_bytes,
                    ..CurveConfig::default()
                }));
        let server_config =
            PeerConfig::new(SocketType::Rep, SecurityRole::Server, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(CurveConfig {
                    local_static_keypair: CurveKeyPair::from_secret(server_static_secret),
                    rekey_messages,
                    rekey_bytes,
                    ..CurveConfig::default()
                }));

        let transcript = b"celerity-curve-test-transcript".to_vec();
        let client_schedule = KeySchedule::client(
            client_eph_secret,
            client_static_secret,
            server_eph_public,
            server_static_public,
        );
        let server_schedule = KeySchedule::server(
            server_eph_secret,
            server_static_secret,
            client_eph_public,
            client_static_public,
        );

        Ok((
            derive_channel(
                &client_config,
                &transcript,
                [5; 8],
                [6; 8],
                &client_schedule,
            )?,
            derive_channel(
                &server_config,
                &transcript,
                [5; 8],
                [6; 8],
                &server_schedule,
            )?,
        ))
    }

    #[test]
    fn debug_omits_traffic_and_handshake_keys() {
        let (client, _) = ok(sample_channels(0, 0));
        assert_eq!(format!("{client:?}"), "SecureChannel { .. }");
        assert_eq!(format!("{:?}", client.send), "TrafficKey { .. }");
        let schedule = KeySchedule {
            exchange: [173; 32],
            local_auth: [174; 32],
            peer_auth: [175; 32],
        };
        assert_eq!(format!("{schedule:?}"), "KeySchedule { .. }");
    }

    #[test]
    fn secure_channel_roundtrips_and_rejects_replays() {
        let (mut client, mut server) = ok(sample_channels(0, 0));

        let payload = ok(seal_message(&mut client, &Bytes::from_static(b"hello")));
        assert_eq!(
            ok(open_message(&mut server, payload.clone())),
            Bytes::from_static(b"hello")
        );
        assert_eq!(
            err(open_message(&mut server, payload)),
            ProtocolError::CurveReplayDetected
        );
    }

    #[test]
    fn secure_channel_rekeys_after_message_limit() {
        let (mut client, mut server) = ok(sample_channels(1, 0));

        let first = ok(seal_message(&mut client, &Bytes::from_static(b"one")));
        assert_eq!(
            ok(open_message(&mut server, first)),
            Bytes::from_static(b"one")
        );
        assert_eq!(client.send.epoch, 0);
        assert_eq!(server.recv.epoch, 0);

        let second = ok(seal_message(&mut client, &Bytes::from_static(b"two")));
        assert_eq!(
            ok(open_message(&mut server, second)),
            Bytes::from_static(b"two")
        );
        assert_eq!(client.send.epoch, 1);
        assert_eq!(server.recv.epoch, 1);
    }
}
