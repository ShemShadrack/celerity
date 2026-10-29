//! Sans-IO ZMTP 3.1 primitives with optional Tokio transport adapters.
//!
//! The crate exposes the core peer state machine, messaging-pattern helpers,
//! protocol configuration, and optional Tokio-based socket wrappers.

#[cfg(feature = "tokio")]
pub mod io;
pub mod pattern;
mod peer;
mod security;
mod wire;

use bytes::Bytes;
use thiserror::Error;

pub use pattern::{PatternAction, PubCore, PullCore, PushCore, RepCore, ReqCore, SubCore};
pub use peer::CelerityPeer;

/// An ordered collection of message frames.
pub type Multipart = Vec<Bytes>;

/// The messaging pattern a peer exposes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    /// A publisher that fans messages out to matching subscribers.
    Pub,
    /// A subscriber that receives messages from publishers.
    Sub,
    /// A pipeline sender that load-balances messages across pullers.
    Push,
    /// A pipeline receiver that consumes messages from pushers.
    Pull,
    /// A requester that sends one request at a time and waits for a reply.
    Req,
    /// A responder that receives requests and sends replies.
    Rep,
}

impl SocketType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pub => "PUB",
            Self::Sub => "SUB",
            Self::Push => "PUSH",
            Self::Pull => "PULL",
            Self::Req => "REQ",
            Self::Rep => "REP",
        }
    }

    pub(crate) fn from_bytes(value: &[u8]) -> Result<Self, ProtocolError> {
        match value {
            b"PUB" => Ok(Self::Pub),
            b"SUB" => Ok(Self::Sub),
            b"PUSH" => Ok(Self::Push),
            b"PULL" => Ok(Self::Pull),
            b"REQ" => Ok(Self::Req),
            b"REP" => Ok(Self::Rep),
            _ => Err(ProtocolError::InvalidSocketType(Bytes::copy_from_slice(
                value,
            ))),
        }
    }

    pub(crate) const fn is_compatible_with(self, remote: Self) -> bool {
        matches!(
            (self, remote),
            (Self::Pub, Self::Sub)
                | (Self::Sub, Self::Pub)
                | (Self::Push, Self::Pull)
                | (Self::Pull, Self::Push)
                | (Self::Req, Self::Rep)
                | (Self::Rep, Self::Req)
        )
    }
}

/// The local role played during the security handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityRole {
    /// The initiating side of the handshake.
    Client,
    /// The accepting side of the handshake.
    Server,
}

/// Whether a transport is confined to the local machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkScope {
    /// Loopback TCP or IPC on the same machine.
    Local,
    /// A transport that may traverse a non-local network.
    NonLocal,
}

/// The wire-level security mechanism used by a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityMechanism {
    /// The plaintext NULL mechanism.
    Null,
    /// The authenticated and encrypted CURVE mechanism.
    Curve,
}

impl SecurityMechanism {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Curve => "CURVE-RS",
        }
    }
}

/// Filesystem authorization policy for local IPC endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalAuthPolicy {
    /// Require strict ownership and permission checks on IPC paths.
    FilesystemStrict,
    /// Allow less restrictive local filesystem permissions for IPC paths.
    FilesystemRelaxed,
}

/// The cryptographic suite used for CURVE traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// X25519 key agreement, HKDF-SHA256 derivation, and ChaCha20-Poly1305 AEAD.
    X25519HkdfSha256ChaCha20Poly1305,
}

impl CipherSuite {
    #[cfg_attr(not(feature = "curve"), allow(dead_code))]
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::X25519HkdfSha256ChaCha20Poly1305 => 1,
        }
    }

    #[cfg_attr(not(feature = "curve"), allow(dead_code))]
    pub(crate) fn from_id(id: u8) -> Result<Self, ProtocolError> {
        match id {
            1 => Ok(Self::X25519HkdfSha256ChaCha20Poly1305),
            _ => Err(ProtocolError::UnsupportedCipherSuite(id)),
        }
    }
}

/// Policy toggles applied before a peer is allowed to handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Whether NULL security is allowed for loopback TCP links.
    pub allow_null_loopback: bool,
    /// Whether NULL security is allowed for local IPC links.
    pub allow_null_ipc: bool,
    /// Whether non-local links must use CURVE unless explicitly overridden.
    pub require_curve_non_local: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_null_loopback: true,
            allow_null_ipc: true,
            require_curve_non_local: true,
        }
    }
}

/// A CURVE static keypair. Debug output omits the secret key.
#[derive(Clone, PartialEq, Eq)]
pub struct CurveKeyPair {
    /// The local X25519 secret key bytes.
    pub secret: [u8; 32],
    /// The corresponding X25519 public key bytes.
    pub public: [u8; 32],
}

impl core::fmt::Debug for CurveKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveKeyPair")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl CurveKeyPair {
    /// Builds a keypair from explicit secret and public key bytes.
    #[must_use]
    pub const fn from_parts(secret: [u8; 32], public: [u8; 32]) -> Self {
        Self { secret, public }
    }

    #[cfg(feature = "curve")]
    /// Derives the public key for an X25519 secret key.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_key = StaticSecret::from(secret);
        let public = PublicKey::from(&secret_key);
        Self {
            secret,
            public: public.to_bytes(),
        }
    }

    #[cfg(feature = "curve")]
    /// Generates a random X25519 keypair.
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

/// Configuration for the CURVE security mechanism.
///
/// With the `curve` feature enabled, defaults generate a new random keypair.
/// Set [`Self::local_static_keypair`] to reuse a saved identity. Cloning preserves
/// the keypair. Without `curve`, the default keypair is a nonfunctional placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurveConfig {
    /// The expected server public key pinned by a client, when configured.
    pub server_public_key: Option<[u8; 32]>,
    /// The local static keypair presented during CURVE authentication.
    pub local_static_keypair: CurveKeyPair,
    /// The client keys a CURVE server will accept, if access is restricted.
    pub allowed_client_keys: Vec<[u8; 32]>,
    /// The maximum handshake duration in milliseconds.
    pub handshake_timeout_ms: u64,
    /// Rekey after this many encrypted messages.
    pub rekey_messages: u64,
    /// Rekey after this many encrypted payload bytes.
    pub rekey_bytes: u64,
    /// The cipher suite used for handshake and traffic protection.
    pub cipher_suite: CipherSuite,
}

impl Default for CurveConfig {
    fn default() -> Self {
        #[cfg(feature = "curve")]
        let local_static_keypair = CurveKeyPair::generate();
        #[cfg(not(feature = "curve"))]
        let local_static_keypair = CurveKeyPair::from_parts([0; 32], [0; 32]);

        Self {
            server_public_key: None,
            local_static_keypair,
            allowed_client_keys: Vec::new(),
            handshake_timeout_ms: 5_000,
            rekey_messages: 1_000_000,
            rekey_bytes: 1 << 30,
            cipher_suite: CipherSuite::X25519HkdfSha256ChaCha20Poly1305,
        }
    }
}

impl CurveConfig {
    #[cfg(feature = "curve")]
    /// Replaces the local static keypair with a freshly generated one.
    #[must_use]
    pub fn with_generated_keypair(self) -> Self {
        let mut next = self;
        next.local_static_keypair = CurveKeyPair::generate();
        next
    }

    #[cfg(not(feature = "curve"))]
    /// Returns the configuration unchanged when the `curve` feature is disabled.
    #[must_use]
    pub fn with_generated_keypair(self) -> Self {
        self
    }
}

/// Queue behavior once a high-water mark is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HwmPolicy {
    /// Backpressure senders until space becomes available.
    Block,
    /// Accept the call but drop the newest queued item.
    DropNewest,
}

/// High-water mark limits for inbound and outbound buffering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwmConfig {
    /// Maximum number of inbound messages buffered by the runtime.
    pub inbound_messages: usize,
    /// Maximum number of outbound messages buffered by the runtime.
    pub outbound_messages: usize,
    /// Maximum number of inbound bytes buffered by the runtime.
    pub inbound_bytes: usize,
    /// Maximum number of outbound bytes buffered by the runtime.
    pub outbound_bytes: usize,
    /// Action taken when a limit is reached.
    pub policy: HwmPolicy,
}

impl Default for HwmConfig {
    fn default() -> Self {
        Self {
            inbound_messages: 64,
            outbound_messages: 64,
            inbound_bytes: 1 << 20,
            outbound_bytes: 1 << 20,
            policy: HwmPolicy::Block,
        }
    }
}

/// Security configuration for a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfig {
    /// The active wire-level security mechanism.
    pub mechanism: SecurityMechanism,
    /// Whether remote NULL links are allowed despite policy defaults.
    pub allow_insecure_null: bool,
    /// Policy checks applied before the handshake starts.
    pub policy: SecurityPolicy,
    /// Local filesystem authorization policy for IPC transports.
    pub local_auth: LocalAuthPolicy,
    /// CURVE-specific parameters, when the mechanism is CURVE.
    pub curve: Option<CurveConfig>,
}

impl SecurityConfig {
    /// Creates a security configuration for a mechanism with sensible defaults.
    #[must_use]
    pub fn new(mechanism: SecurityMechanism) -> Self {
        Self {
            mechanism,
            allow_insecure_null: false,
            policy: SecurityPolicy::default(),
            local_auth: LocalAuthPolicy::FilesystemStrict,
            curve: match mechanism {
                SecurityMechanism::Null => None,
                SecurityMechanism::Curve => Some(CurveConfig::default()),
            },
        }
    }

    /// Creates a configuration for the NULL mechanism.
    #[must_use]
    pub fn null() -> Self {
        Self::new(SecurityMechanism::Null)
    }

    /// Creates a configuration for the CURVE mechanism.
    #[must_use]
    pub fn curve() -> Self {
        Self::new(SecurityMechanism::Curve)
    }

    /// Chooses a default mechanism for the transport scope.
    #[must_use]
    pub fn default_for(link_scope: LinkScope) -> Self {
        match link_scope {
            // Local links default to NULL for easier same-host bootstrapping.
            LinkScope::Local => Self::null(),
            LinkScope::NonLocal => Self::curve(),
        }
    }

    /// Enables or disables explicit opt-in for non-local NULL links.
    #[must_use]
    pub fn with_insecure_null(mut self, allow_insecure_null: bool) -> Self {
        self.allow_insecure_null = allow_insecure_null;
        self
    }

    /// Replaces the attached security policy.
    #[must_use]
    pub fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Replaces the local IPC authorization policy.
    #[must_use]
    pub fn with_local_auth_policy(mut self, local_auth: LocalAuthPolicy) -> Self {
        self.local_auth = local_auth;
        self
    }

    /// Replaces the CURVE configuration block.
    #[must_use]
    pub fn with_curve_config(mut self, curve: CurveConfig) -> Self {
        self.curve = Some(curve);
        self
    }
}

/// Case-preserving metadata exchanged during the ZMTP handshake.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataMap {
    entries: Vec<(Bytes, Bytes)>,
}

impl MetadataMap {
    /// Creates an empty metadata map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a metadata entry by name.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidMetadataName`] when `name` is empty,
    /// longer than 255 bytes, or contains unsupported characters.
    pub fn insert(
        &mut self,
        name: impl Into<Bytes>,
        value: impl Into<Bytes>,
    ) -> Result<(), ProtocolError> {
        self.insert_bytes(name.into(), value.into())
    }

    /// Looks up a metadata value using an ASCII case-insensitive string key.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Bytes> {
        self.get_bytes(name.as_bytes())
    }

    /// Looks up a metadata value using an ASCII case-insensitive byte key.
    #[must_use]
    pub fn get_bytes(&self, name: &[u8]) -> Option<&Bytes> {
        self.entries
            .iter()
            // Metadata lookup is case-insensitive even though bytes are preserved.
            .find(|(candidate, _)| candidate.as_ref().eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Iterates over metadata entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&Bytes, &Bytes)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }

    /// Returns the number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no metadata entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn insert_bytes(&mut self, name: Bytes, value: Bytes) -> Result<(), ProtocolError> {
        validate_metadata_name(&name)?;

        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|(candidate, _)| candidate.as_ref().eq_ignore_ascii_case(&name))
        {
            // Reinsertions replace the previous value instead of duplicating the key.
            *existing = (name, value);
        } else {
            self.entries.push((name, value));
        }

        Ok(())
    }

    pub(crate) fn socket_type(&self) -> Result<SocketType, ProtocolError> {
        let value = self
            .get("Socket-Type")
            .ok_or(ProtocolError::MissingMetadata("Socket-Type"))?;
        SocketType::from_bytes(value)
    }
}

fn validate_metadata_name(name: &[u8]) -> Result<(), ProtocolError> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err(ProtocolError::InvalidMetadataName(Bytes::copy_from_slice(
            name,
        )));
    }

    if name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        Ok(())
    } else {
        Err(ProtocolError::InvalidMetadataName(Bytes::copy_from_slice(
            name,
        )))
    }
}

/// Configuration used to build a [`CelerityPeer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// The socket pattern exposed by the local peer.
    pub socket_type: SocketType,
    /// The local security-handshake role.
    pub security_role: SecurityRole,
    /// Whether the transport is local-only or potentially remote.
    pub link_scope: LinkScope,
    /// The configured wire-level security settings.
    pub security: SecurityConfig,
    /// Optional peer identity advertised during the handshake.
    pub identity: Option<Bytes>,
    /// Additional handshake metadata.
    pub metadata: MetadataMap,
    /// High-water mark limits used by the runtime adapters.
    pub hwm: HwmConfig,
}

impl PeerConfig {
    /// Creates a peer configuration with defaults derived from the link scope.
    #[must_use]
    pub fn new(
        socket_type: SocketType,
        security_role: SecurityRole,
        link_scope: LinkScope,
    ) -> Self {
        Self {
            socket_type,
            security_role,
            link_scope,
            security: SecurityConfig::default_for(link_scope),
            identity: None,
            metadata: MetadataMap::new(),
            hwm: HwmConfig::default(),
        }
    }

    /// Replaces the security configuration.
    #[must_use]
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Sets the handshake identity advertised by the peer.
    #[must_use]
    pub fn with_identity(mut self, identity: impl Into<Bytes>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Replaces the additional handshake metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: MetadataMap) -> Self {
        self.metadata = metadata;
        self
    }

    /// Replaces the high-water mark configuration.
    #[must_use]
    pub fn with_hwm(mut self, hwm: HwmConfig) -> Self {
        self.hwm = hwm;
        self
    }

    pub(crate) fn validate_policy(&self) -> Result<(), ProtocolError> {
        // Remote NULL stays fail-closed unless the caller opts in explicitly.
        if self.security.mechanism == SecurityMechanism::Null
            && self.link_scope == LinkScope::NonLocal
            && self.security.policy.require_curve_non_local
            && !self.security.allow_insecure_null
        {
            return Err(ProtocolError::InsecureNullForNonLocal);
        }

        if self.security.mechanism == SecurityMechanism::Curve {
            // CURVE always needs an attached key/config block before we handshake.
            let curve = self
                .security
                .curve
                .as_ref()
                .ok_or(ProtocolError::MissingCurveConfig)?;

            #[cfg(feature = "curve")]
            validate_curve_keypair(&curve.local_static_keypair)?;
            #[cfg(not(feature = "curve"))]
            let _ = curve;
        }

        Ok(())
    }

    pub(crate) fn handshake_metadata(&self) -> Result<MetadataMap, ProtocolError> {
        let mut metadata = MetadataMap::new();
        metadata.insert("Socket-Type", self.socket_type.as_str())?;

        if let Some(identity) = &self.identity {
            metadata.insert("Identity", identity.clone())?;
        }

        for (name, value) in self.metadata.iter() {
            // Reserved handshake keys come from explicit config, not caller metadata.
            if !name.as_ref().eq_ignore_ascii_case(b"Socket-Type")
                && !name.as_ref().eq_ignore_ascii_case(b"Identity")
            {
                metadata.insert(name.clone(), value.clone())?;
            }
        }

        Ok(metadata)
    }
}

/// An item submitted for outbound delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundItem {
    /// A multipart message to encode and send.
    Message(Multipart),
    /// A subscription command for a PUB/SUB pattern.
    Subscribe(Bytes),
    /// A subscription cancellation command for a PUB/SUB pattern.
    Cancel(Bytes),
}

/// An event emitted by the peer state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// The handshake completed and remote metadata is available.
    HandshakeComplete {
        /// The socket type reported by the remote peer.
        peer_socket_type: SocketType,
        /// The metadata reported by the remote peer.
        metadata: MetadataMap,
    },
    /// A complete inbound multipart message.
    Message(Multipart),
    /// A subscription update received from the remote peer.
    Subscription {
        /// `true` to subscribe and `false` to cancel.
        subscribe: bool,
        /// The topic prefix carried by the subscription command.
        topic: Bytes,
    },
}

/// A low-level action produced by the peer state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolAction {
    /// Bytes that should be written to the transport.
    Write(Bytes),
    /// Header and body slices that should be written as one vectored frame.
    WriteVectored {
        /// The encoded ZMTP frame header.
        header: Bytes,
        /// The frame payload bytes.
        body: Bytes,
    },
    /// A synthesized protocol event for the caller.
    Event(PeerEvent),
}

/// A protocol-level failure reported by the sans-IO engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The transport closed and no more progress is possible.
    #[error("connection is closed")]
    ConnectionClosed,
    /// The caller attempted to send traffic before the handshake completed.
    #[error("peer is not ready for traffic")]
    PeerNotReady,
    /// A multipart message did not contain any frames.
    #[error("multipart messages must contain at least one frame")]
    EmptyMessage,
    /// The 64-byte ZMTP greeting had an invalid signature.
    #[error("invalid ZMTP greeting signature")]
    InvalidGreetingSignature,
    /// The remote peer spoke an unsupported ZMTP version.
    #[error("unsupported ZMTP version {major}.{minor}")]
    UnsupportedVersion {
        /// The unsupported major protocol version.
        major: u8,
        /// The unsupported minor protocol version.
        minor: u8,
    },
    /// The greeting filler bytes were not zeroed as required.
    #[error("invalid greeting filler bytes")]
    InvalidGreetingFiller,
    /// The configured mechanism is not supported by this build.
    #[error("unsupported security mechanism {0}")]
    MechanismUnsupported(&'static str),
    /// The remote greeting named an unknown mechanism string.
    #[error("unsupported security mechanism name {0}")]
    UnsupportedMechanismName(String),
    /// The remote peer selected a different mechanism than expected.
    #[error("security mechanism mismatch: expected {expected:?}, got {actual:?}")]
    MechanismMismatch {
        /// The mechanism configured locally.
        expected: SecurityMechanism,
        /// The mechanism advertised by the remote peer.
        actual: SecurityMechanism,
    },
    /// The greeting `as-server` flag was not valid for the selected mechanism.
    #[error("invalid as-server field {0}")]
    InvalidAsServer(u8),
    /// NULL security was attempted on a non-local link without opt-in.
    #[error("NULL security is disabled for non-local links without explicit opt-in")]
    InsecureNullForNonLocal,
    /// CURVE was selected without the required configuration block.
    #[error("missing CURVE configuration")]
    MissingCurveConfig,
    /// The remote peer requested an unsupported cipher suite.
    #[error("unsupported cipher suite id {0}")]
    UnsupportedCipherSuite(u8),
    /// The CURVE handshake failed before traffic keys were established.
    #[error("CURVE handshake failed: {0}")]
    CurveHandshake(&'static str),
    /// CURVE message authentication failed.
    #[error("CURVE authentication failed")]
    CurveAuthenticationFailed,
    /// An encrypted frame was replayed after it had already been accepted.
    #[error("CURVE replay detected")]
    CurveReplayDetected,
    /// The configured CURVE public key does not match the secret key.
    #[error("configured CURVE public key does not match the secret key")]
    InvalidCurveKeyPair,
    /// An encrypted traffic frame could not be decoded.
    #[error("invalid encrypted traffic frame")]
    InvalidEncryptedMessage,
    /// A frame header used unsupported flag bits.
    #[error("invalid frame flags 0x{0:02x}")]
    InvalidFrameFlags(u8),
    /// A command frame incorrectly set the MORE bit.
    #[error("command frames must not set MORE")]
    CommandWithMore,
    /// A long frame length used the reserved sign bit.
    #[error("frame length uses the reserved sign bit")]
    NegativeFrameLength,
    /// A frame length exceeded the limits supported by the platform.
    #[error("frame size {0} exceeds platform limits")]
    FrameTooLarge(u64),
    /// A command frame payload was malformed.
    #[error("invalid command frame")]
    InvalidCommandFrame,
    /// A message frame arrived while the peer was still handshaking.
    #[error("unexpected message frame during handshake")]
    UnexpectedMessageDuringHandshake,
    /// A command arrived in an unexpected handshake state.
    #[error("unexpected command {0} during handshake")]
    UnexpectedHandshakeCommand(&'static str),
    /// A command arrived in an unexpected traffic state.
    #[error("unexpected command {0} during traffic")]
    UnexpectedTrafficCommand(&'static str),
    /// The remote peer reported a fatal error command.
    #[error("remote peer reported fatal error: {0}")]
    RemoteError(String),
    /// A metadata property name was invalid.
    #[error("invalid metadata name {0:?}")]
    InvalidMetadataName(Bytes),
    /// A required metadata property was missing.
    #[error("missing metadata property {0}")]
    MissingMetadata(&'static str),
    /// A handshake metadata value contained an invalid socket type.
    #[error("invalid socket type {0:?}")]
    InvalidSocketType(Bytes),
    /// The remote socket type is incompatible with the local one.
    #[error("incompatible socket types: local {local:?}, remote {remote:?}")]
    IncompatibleSocketTypes {
        /// The socket type configured locally.
        local: SocketType,
        /// The socket type reported by the remote peer.
        remote: SocketType,
    },
    /// A REQ/REP envelope was missing the required empty delimiter frame.
    #[error("missing request envelope delimiter")]
    MissingEnvelopeDelimiter,
    /// A request or reply did not contain any body frames.
    #[error("request messages must contain at least one body frame")]
    MissingBodyFrames,
    /// No peers were available to route a message to.
    #[error("no available peers")]
    NoAvailablePeers,
    /// A REQ socket operation violated its strict send/receive alternation.
    #[error("REQ state violation: {0}")]
    ReqStateViolation(&'static str),
    /// A REP socket operation violated its active-request rules.
    #[error("REP state violation: {0}")]
    RepStateViolation(&'static str),
    /// A cancellation referenced a subscription that was not active.
    #[error("subscription was not active")]
    UnknownSubscription,
}

#[cfg(feature = "curve")]
fn validate_curve_keypair(keypair: &CurveKeyPair) -> Result<(), ProtocolError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(keypair.secret);
    let derived = PublicKey::from(&secret).to_bytes();
    if derived == keypair.public {
        Ok(())
    } else {
        Err(ProtocolError::InvalidCurveKeyPair)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        LinkScope, MetadataMap, PeerConfig, ProtocolError, SecurityConfig, SecurityMechanism,
        SecurityPolicy, SecurityRole, SocketType,
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

    #[test]
    fn curve_debug_hides_secret_keys() {
        #[cfg(feature = "curve")]
        let keypair = super::CurveKeyPair::from_secret([173; 32]);
        #[cfg(not(feature = "curve"))]
        let keypair = super::CurveKeyPair::from_parts([173; 32], [42; 32]);
        let secret = format!("{:?}", keypair.secret);
        let curve = super::CurveConfig {
            local_static_keypair: keypair.clone(),
            ..super::CurveConfig::default()
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve().with_curve_config(curve));
        for debug in [
            format!("{keypair:?}"),
            format!("{config:#?}"),
            format!("{config:?}"),
            format!("{:?}", crate::CelerityPeer::new(config)),
        ] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(&secret));
        }
        assert!(format!("{keypair:?}").contains(&format!("{:?}", keypair.public)));
    }

    #[cfg(feature = "curve")]
    #[test]
    fn default_curve_keypairs_are_unique_and_valid() {
        let first = super::CurveConfig::default();
        let second = super::CurveConfig::default();

        assert_ne!(
            first.local_static_keypair.public,
            second.local_static_keypair.public
        );
        ok(super::validate_curve_keypair(&first.local_static_keypair));
        ok(super::validate_curve_keypair(&second.local_static_keypair));
        assert_eq!(
            first.clone().local_static_keypair,
            first.local_static_keypair
        );
    }

    #[test]
    fn metadata_socket_type_reports_missing_and_invalid_values() {
        let metadata = MetadataMap::new();
        assert_eq!(
            err(metadata.socket_type()),
            ProtocolError::MissingMetadata("Socket-Type")
        );

        let mut metadata = MetadataMap::new();
        ok(metadata.insert("Socket-Type", "PAIR"));
        assert_eq!(
            err(metadata.socket_type()),
            ProtocolError::InvalidSocketType(Bytes::from_static(b"PAIR"))
        );
    }

    #[test]
    fn socket_type_parses_and_matches_push_pull() {
        assert_eq!(ok(SocketType::from_bytes(b"PUSH")), SocketType::Push);
        assert_eq!(ok(SocketType::from_bytes(b"PULL")), SocketType::Pull);
        assert!(SocketType::Push.is_compatible_with(SocketType::Pull));
        assert!(SocketType::Pull.is_compatible_with(SocketType::Push));
        assert!(!SocketType::Push.is_compatible_with(SocketType::Push));
        assert!(!SocketType::Pull.is_compatible_with(SocketType::Pull));
    }

    #[test]
    fn handshake_metadata_uses_canonical_reserved_fields() {
        let mut metadata = MetadataMap::new();
        ok(metadata.insert("Socket-Type", "SUB"));
        ok(metadata.insert("Identity", "shadow"));
        ok(metadata.insert("X-Test", "value"));

        let handshake = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_identity("client-id")
            .with_metadata(metadata)
            .handshake_metadata();
        let handshake = ok(handshake);

        assert_eq!(
            handshake.get("Socket-Type").cloned(),
            Some(Bytes::from_static(b"REQ"))
        );
        assert_eq!(
            handshake.get("Identity").cloned(),
            Some(Bytes::from_static(b"client-id"))
        );
        assert_eq!(
            handshake.get("X-Test").cloned(),
            Some(Bytes::from_static(b"value"))
        );
        assert_eq!(handshake.len(), 3);
    }

    #[test]
    fn validate_policy_requires_curve_config() {
        let mut security = SecurityConfig::curve();
        security.curve = None;
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
            .with_security(security);

        assert_eq!(
            err(config.validate_policy()),
            ProtocolError::MissingCurveConfig
        );
    }

    #[test]
    fn validate_policy_allows_non_local_null_when_requirement_is_disabled() {
        let policy = SecurityPolicy {
            allow_null_loopback: true,
            allow_null_ipc: true,
            require_curve_non_local: false,
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
            .with_security(SecurityConfig::new(SecurityMechanism::Null).with_policy(policy));

        ok(config.validate_policy());
    }
}
