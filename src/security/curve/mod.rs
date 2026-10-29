#[cfg(feature = "curve")]
mod crypto;
#[cfg(feature = "curve")]
mod message;

use std::collections::VecDeque;

use bytes::Bytes;
#[cfg(feature = "curve")]
use bytes::{BufMut, BytesMut};

#[cfg(feature = "curve")]
use crypto::{
    KeySchedule, SecureChannel, control_nonce, decrypt_aead, derive_channel, derive_key,
    encrypt_aead, open_message, public_from_secret, random_bytes, seal_message, sha256,
    shared_secret,
};
#[cfg(not(feature = "curve"))]
type SecureChannel = ();
#[cfg(feature = "curve")]
use message::{
    append_transcript, decode_initiate_body, decode_welcome_body, parse_hello, parse_initiate,
    parse_welcome,
};

use crate::wire::Command;
#[cfg(feature = "curve")]
use crate::wire::{
    decode_metadata, encode_command, encode_metadata, encode_outbound_item, encode_raw_frames,
};
use crate::{MetadataMap, OutboundItem, PeerConfig, ProtocolAction, ProtocolError, SecurityRole};

use super::{HandshakeComplete, MechanismDriver};
#[cfg(feature = "curve")]
use super::{curve_config, validate_remote_metadata};

#[cfg_attr(not(feature = "curve"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum CurveStage {
    Hello,
    Welcome,
    Initiate,
    Ready,
    Established,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CurveMechanism {
    stage: CurveStage,
    transcript: Vec<u8>,
    client_eph_secret: Option<[u8; 32]>,
    client_eph_public: Option<[u8; 32]>,
    server_eph_secret: Option<[u8; 32]>,
    server_eph_public: Option<[u8; 32]>,
    client_static_public: Option<[u8; 32]>,
    server_static_public: Option<[u8; 32]>,
    client_nonce_seed: Option<[u8; 8]>,
    server_nonce_seed: Option<[u8; 8]>,
    cookie: Option<[u8; 32]>,
    channel: Option<SecureChannel>,
}

impl core::fmt::Debug for CurveMechanism {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveMechanism")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl CurveMechanism {
    pub(crate) fn new(role: SecurityRole) -> Self {
        Self {
            // Each side begins at the first command it expects to receive or send.
            stage: match role {
                SecurityRole::Client => CurveStage::Hello,
                SecurityRole::Server => CurveStage::Welcome,
            },
            transcript: Vec::new(),
            client_eph_secret: None,
            client_eph_public: None,
            server_eph_secret: None,
            server_eph_public: None,
            client_static_public: None,
            server_static_public: None,
            client_nonce_seed: None,
            server_nonce_seed: None,
            cookie: None,
            channel: None,
        }
    }
}

impl MechanismDriver for CurveMechanism {
    fn on_greeting(
        &mut self,
        config: &PeerConfig,
        _local_metadata: &MetadataMap,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        #[cfg(not(feature = "curve"))]
        {
            let _ = output;
            let _ = config;
            Err(ProtocolError::MechanismUnsupported("CURVE-RS"))
        }

        #[cfg(feature = "curve")]
        {
            if !matches!(config.security_role, SecurityRole::Client) {
                return Ok(None);
            }
            if self.stage != CurveStage::Hello {
                return Err(ProtocolError::CurveHandshake("unexpected greeting state"));
            }

            let curve = curve_config(config)?;
            let client_eph_secret = random_bytes::<32>();
            let client_eph_public = public_from_secret(client_eph_secret);
            let client_nonce_seed = random_bytes::<8>();
            // Clients may pin the expected server key without exposing it in cleartext.
            let server_key_hash = curve.server_public_key.map_or([0; 32], sha256);

            let mut payload = BytesMut::with_capacity(74);
            payload.put_u8(1);
            payload.put_u8(curve.cipher_suite.id());
            payload.extend_from_slice(&client_eph_public);
            payload.extend_from_slice(&server_key_hash);
            payload.extend_from_slice(&client_nonce_seed);
            let payload = payload.freeze();

            append_transcript(&mut self.transcript, b"HELLO", &payload)?;
            self.client_eph_secret = Some(client_eph_secret);
            self.client_eph_public = Some(client_eph_public);
            self.client_nonce_seed = Some(client_nonce_seed);
            self.stage = CurveStage::Welcome;

            output.push_back(ProtocolAction::Write(encode_command(Command::Hello(
                payload,
            ))?));
            Ok(None)
        }
    }

    fn on_command(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        command: Command,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        #[cfg(not(feature = "curve"))]
        {
            let _ = config;
            let _ = local_metadata;
            let _ = command;
            let _ = output;
            Err(ProtocolError::MechanismUnsupported("CURVE-RS"))
        }

        #[cfg(feature = "curve")]
        {
            match (config.security_role, command) {
                (SecurityRole::Server, Command::Hello(payload)) => {
                    self.on_hello(config, &payload, output)?;
                    Ok(None)
                }
                (SecurityRole::Client, Command::Welcome(payload)) => {
                    self.on_welcome(config, local_metadata, &payload, output)?;
                    Ok(None)
                }
                (SecurityRole::Server, Command::Initiate(payload)) => {
                    self.on_initiate(config, local_metadata, &payload, output)
                }
                (SecurityRole::Client, Command::Ready(payload)) => self.on_ready(config, &payload),
                (_, Command::Error(reason)) => Err(ProtocolError::RemoteError(
                    String::from_utf8_lossy(&reason).into_owned(),
                )),
                (_, Command::Ready(_)) => Err(ProtocolError::UnexpectedHandshakeCommand("READY")),
                (_, Command::Subscribe(_)) => {
                    Err(ProtocolError::UnexpectedHandshakeCommand("SUBSCRIBE"))
                }
                (_, Command::Cancel(_)) => Err(ProtocolError::UnexpectedHandshakeCommand("CANCEL")),
                (_, Command::Hello(_)) => Err(ProtocolError::UnexpectedHandshakeCommand("HELLO")),
                (_, Command::Welcome(_)) => {
                    Err(ProtocolError::UnexpectedHandshakeCommand("WELCOME"))
                }
                (_, Command::Initiate(_)) => {
                    Err(ProtocolError::UnexpectedHandshakeCommand("INITIATE"))
                }
                (_, Command::Message(_)) => {
                    Err(ProtocolError::UnexpectedHandshakeCommand("MESSAGE"))
                }
            }
        }
    }

    fn encode_outbound(
        &mut self,
        item: &OutboundItem,
    ) -> Result<Vec<ProtocolAction>, ProtocolError> {
        #[cfg(not(feature = "curve"))]
        {
            let _ = item;
            Err(ProtocolError::MechanismUnsupported("CURVE-RS"))
        }

        #[cfg(feature = "curve")]
        {
            let channel = self.channel.as_mut().ok_or(ProtocolError::PeerNotReady)?;
            let raw_frames = encode_outbound_item(item)?;
            let plaintext = encode_raw_frames(&raw_frames);
            let payload = seal_message(channel, &plaintext)?;
            Ok(vec![ProtocolAction::Write(encode_command(
                Command::Message(payload),
            )?)])
        }
    }

    fn decode_message(&mut self, payload: Bytes) -> Result<Bytes, ProtocolError> {
        #[cfg(not(feature = "curve"))]
        {
            let _ = payload;
            Err(ProtocolError::MechanismUnsupported("CURVE-RS"))
        }

        #[cfg(feature = "curve")]
        {
            let channel = self.channel.as_mut().ok_or(ProtocolError::PeerNotReady)?;
            open_message(channel, payload)
        }
    }
}

#[cfg(feature = "curve")]
impl CurveMechanism {
    fn on_hello(
        &mut self,
        config: &PeerConfig,
        payload: &Bytes,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<(), ProtocolError> {
        if self.stage != CurveStage::Welcome {
            return Err(ProtocolError::CurveHandshake("unexpected HELLO"));
        }

        let curve = curve_config(config)?;
        let hello = parse_hello(payload.clone())?;
        if hello.version != 1 {
            return Err(ProtocolError::CurveHandshake(
                "unsupported CURVE-RS version",
            ));
        }
        if hello.cipher_suite != curve.cipher_suite {
            return Err(ProtocolError::CurveHandshake("cipher suite mismatch"));
        }

        let local_static_public = local_static_public(config)?;
        if hello.server_key_hash != [0; 32] && hello.server_key_hash != sha256(local_static_public)
        {
            return Err(ProtocolError::CurveAuthenticationFailed);
        }

        append_transcript(&mut self.transcript, b"HELLO", payload)?;

        let server_eph_secret = random_bytes::<32>();
        let server_eph_public = public_from_secret(server_eph_secret);
        let server_nonce_seed = random_bytes::<8>();
        let cookie = random_bytes::<32>();
        let shared = shared_secret(server_eph_secret, hello.client_eph_public);
        let welcome_key = derive_key(&self.transcript, &[&shared], b"curve-rs-welcome")?;

        let mut body = BytesMut::with_capacity(73);
        body.put_u8(1);
        body.extend_from_slice(&local_static_public);
        body.extend_from_slice(&cookie);
        body.extend_from_slice(&server_nonce_seed);
        let body = body.freeze();
        let ciphertext = encrypt_aead(
            &welcome_key,
            control_nonce(1),
            &sha256(&self.transcript),
            &body,
        )?;

        let mut welcome = BytesMut::with_capacity(33 + ciphertext.len());
        welcome.put_u8(curve.cipher_suite.id());
        welcome.extend_from_slice(&server_eph_public);
        welcome.extend_from_slice(&ciphertext);
        let welcome = welcome.freeze();

        append_transcript(&mut self.transcript, b"WELCOME", &welcome)?;
        self.client_eph_public = Some(hello.client_eph_public);
        self.client_nonce_seed = Some(hello.client_nonce_seed);
        self.server_eph_secret = Some(server_eph_secret);
        self.server_eph_public = Some(server_eph_public);
        self.server_static_public = Some(local_static_public);
        self.server_nonce_seed = Some(server_nonce_seed);
        self.cookie = Some(cookie);
        self.stage = CurveStage::Initiate;

        output.push_back(ProtocolAction::Write(encode_command(Command::Welcome(
            welcome,
        ))?));
        Ok(())
    }

    fn on_welcome(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        payload: &Bytes,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<(), ProtocolError> {
        if self.stage != CurveStage::Welcome {
            return Err(ProtocolError::CurveHandshake("unexpected WELCOME"));
        }

        let curve = curve_config(config)?;
        let welcome = parse_welcome(payload.clone())?;
        if welcome.cipher_suite != curve.cipher_suite {
            return Err(ProtocolError::CurveHandshake("cipher suite mismatch"));
        }

        let client_eph_secret = self.client_eph_secret.ok_or(ProtocolError::CurveHandshake(
            "missing client ephemeral secret",
        ))?;
        let shared = shared_secret(client_eph_secret, welcome.server_eph_public);
        let welcome_key = derive_key(&self.transcript, &[&shared], b"curve-rs-welcome")?;
        let body = decrypt_aead(
            &welcome_key,
            control_nonce(1),
            &sha256(&self.transcript),
            &welcome.ciphertext,
        )?;
        let welcome_body = decode_welcome_body(body)?;
        // If the caller pinned a server key, enforce it before sending INITIATE.
        if let Some(expected) = curve.server_public_key
            && expected != welcome_body.server_static_public
        {
            return Err(ProtocolError::CurveAuthenticationFailed);
        }

        append_transcript(&mut self.transcript, b"WELCOME", payload)?;

        let local_static_secret = local_static_secret(config)?;
        let local_static_public = local_static_public(config)?;
        let keys = KeySchedule::client(
            client_eph_secret,
            local_static_secret,
            welcome.server_eph_public,
            welcome_body.server_static_public,
        );
        let parts = keys.parts();
        let initiate_key = derive_key(&self.transcript, &parts, b"curve-rs-initiate")?;

        let metadata = encode_metadata(local_metadata)?;
        let metadata_len = u32::try_from(metadata.len())
            .map_err(|_| ProtocolError::CurveHandshake("INITIATE metadata too large"))?;
        let mut body = BytesMut::with_capacity(36 + metadata.len());
        body.extend_from_slice(&welcome_body.cookie);
        body.put_u32(metadata_len);
        body.extend_from_slice(&metadata);
        let body = body.freeze();
        let ciphertext = encrypt_aead(
            &initiate_key,
            control_nonce(2),
            &sha256(&self.transcript),
            &body,
        )?;

        let mut initiate = BytesMut::with_capacity(32 + ciphertext.len());
        initiate.extend_from_slice(&local_static_public);
        initiate.extend_from_slice(&ciphertext);
        let initiate = initiate.freeze();

        append_transcript(&mut self.transcript, b"INITIATE", &initiate)?;
        self.server_eph_public = Some(welcome.server_eph_public);
        self.server_static_public = Some(welcome_body.server_static_public);
        self.server_nonce_seed = Some(welcome_body.server_nonce_seed);
        self.client_static_public = Some(local_static_public);
        self.cookie = Some(welcome_body.cookie);
        self.stage = CurveStage::Ready;

        output.push_back(ProtocolAction::Write(encode_command(Command::Initiate(
            initiate,
        ))?));
        Ok(())
    }

    fn on_initiate(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        payload: &Bytes,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        if self.stage != CurveStage::Initiate {
            return Err(ProtocolError::CurveHandshake("unexpected INITIATE"));
        }

        let initiate = parse_initiate(payload.clone())?;
        let client_eph_public = self.client_eph_public.ok_or(ProtocolError::CurveHandshake(
            "missing client ephemeral public",
        ))?;
        let server_eph_secret = self.server_eph_secret.ok_or(ProtocolError::CurveHandshake(
            "missing server ephemeral secret",
        ))?;
        let local_static_secret = local_static_secret(config)?;
        let keys = KeySchedule::server(
            server_eph_secret,
            local_static_secret,
            client_eph_public,
            initiate.client_static_public,
        );
        let parts = keys.parts();
        let initiate_key = derive_key(&self.transcript, &parts, b"curve-rs-initiate")?;

        let body = decrypt_aead(
            &initiate_key,
            control_nonce(2),
            &sha256(&self.transcript),
            &initiate.ciphertext,
        )?;
        let initiate_body = decode_initiate_body(body)?;
        let expected_cookie = self
            .cookie
            .ok_or(ProtocolError::CurveHandshake("missing cookie"))?;
        if expected_cookie != initiate_body.cookie {
            return Err(ProtocolError::CurveAuthenticationFailed);
        }

        let curve = curve_config(config)?;
        // An empty allowlist means "accept any client key".
        if !curve.allowed_client_keys.is_empty()
            && !curve
                .allowed_client_keys
                .iter()
                .any(|key| key == &initiate.client_static_public)
        {
            return Err(ProtocolError::CurveAuthenticationFailed);
        }

        append_transcript(&mut self.transcript, b"INITIATE", payload)?;
        let peer_socket_type = validate_remote_metadata(config, &initiate_body.metadata)?;
        let ready_key = derive_key(&self.transcript, &parts, b"curve-rs-ready")?;
        let ready_body = encode_metadata(local_metadata)?;
        let ready_payload = encrypt_aead(
            &ready_key,
            control_nonce(3),
            &sha256(&self.transcript),
            &ready_body,
        )?;
        output.push_back(ProtocolAction::Write(encode_command(Command::Ready(
            ready_payload,
        ))?));

        self.client_static_public = Some(initiate.client_static_public);
        self.stage = CurveStage::Established;
        // Switch from handshake keys to the long-lived traffic channel.
        self.channel = Some(derive_channel(
            config,
            &self.transcript,
            self.client_nonce_seed
                .ok_or(ProtocolError::CurveHandshake("missing client nonce seed"))?,
            self.server_nonce_seed
                .ok_or(ProtocolError::CurveHandshake("missing server nonce seed"))?,
            &keys,
        )?);

        Ok(Some(HandshakeComplete {
            peer_socket_type,
            metadata: initiate_body.metadata,
        }))
    }

    fn on_ready(
        &mut self,
        config: &PeerConfig,
        payload: &Bytes,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        if self.stage != CurveStage::Ready {
            return Err(ProtocolError::CurveHandshake("unexpected READY"));
        }

        let client_eph_secret = self.client_eph_secret.ok_or(ProtocolError::CurveHandshake(
            "missing client ephemeral secret",
        ))?;
        let server_eph_public = self.server_eph_public.ok_or(ProtocolError::CurveHandshake(
            "missing server ephemeral public",
        ))?;
        let server_static_public =
            self.server_static_public
                .ok_or(ProtocolError::CurveHandshake(
                    "missing server static public",
                ))?;
        let local_static_secret = local_static_secret(config)?;
        let keys = KeySchedule::client(
            client_eph_secret,
            local_static_secret,
            server_eph_public,
            server_static_public,
        );
        let parts = keys.parts();
        let ready_key = derive_key(&self.transcript, &parts, b"curve-rs-ready")?;
        let body = decrypt_aead(
            &ready_key,
            control_nonce(3),
            &sha256(&self.transcript),
            payload,
        )?;
        let metadata = decode_metadata(body)?;
        let peer_socket_type = validate_remote_metadata(config, &metadata)?;

        self.stage = CurveStage::Established;
        self.channel = Some(derive_channel(
            config,
            &self.transcript,
            self.client_nonce_seed
                .ok_or(ProtocolError::CurveHandshake("missing client nonce seed"))?,
            self.server_nonce_seed
                .ok_or(ProtocolError::CurveHandshake("missing server nonce seed"))?,
            &keys,
        )?);

        Ok(Some(HandshakeComplete {
            peer_socket_type,
            metadata,
        }))
    }
}

#[cfg(feature = "curve")]
fn local_static_secret(config: &PeerConfig) -> Result<[u8; 32], ProtocolError> {
    Ok(curve_config(config)?.local_static_keypair.secret)
}

#[cfg(feature = "curve")]
fn local_static_public(config: &PeerConfig) -> Result<[u8; 32], ProtocolError> {
    Ok(curve_config(config)?.local_static_keypair.public)
}
