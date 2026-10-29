//! Sans-IO peer state machine for handshake and traffic processing.

use std::collections::VecDeque;

use bytes::Bytes;

use crate::security::{HandshakeComplete, Mechanism};
use crate::wire::{
    Command, FrameFlags, GREETING_SIZE, InputBuffer, decode_command, decode_greeting,
    encode_greeting, greeting_as_server, try_decode_frame,
};
use crate::{
    MetadataMap, OutboundItem, PeerConfig, PeerEvent, ProtocolAction, ProtocolError,
    SecurityMechanism, SecurityRole,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
    Greeting,
    Handshake,
    Traffic,
    Closed,
}

/// A single peer state machine that speaks ZMTP 3.1.
#[derive(Debug)]
pub struct CelerityPeer {
    config: PeerConfig,
    local_metadata: MetadataMap,
    input: InputBuffer,
    mechanism: Mechanism,
    state: PeerState,
    output: VecDeque<ProtocolAction>,
    current_message: Vec<Bytes>,
    current_message_bytes: usize,
    terminal_error: Option<ProtocolError>,
}

impl CelerityPeer {
    /// Creates a peer and emits its opening greeting if configuration allows it.
    pub fn new(config: PeerConfig) -> Self {
        let mechanism = Mechanism::new(&config);
        let mut output = VecDeque::new();
        let mut state = PeerState::Greeting;
        let mut terminal_error = None;
        let mut local_metadata = MetadataMap::new();

        // Fail closed up front if the peer cannot produce a valid opening handshake.
        match config
            .validate_policy()
            .and_then(|()| config.handshake_metadata())
        {
            Ok(metadata) => {
                local_metadata = metadata;
                // Every peer speaks first with its 64-byte ZMTP greeting.
                output.push_back(ProtocolAction::Write(encode_greeting(&config)));
            }
            Err(err) => {
                state = PeerState::Closed;
                terminal_error = Some(err);
            }
        }

        Self {
            config,
            local_metadata,
            input: InputBuffer::default(),
            mechanism,
            state,
            output,
            current_message: Vec::new(),
            current_message_bytes: 0,
            terminal_error,
        }
    }

    /// Feeds raw transport bytes into the peer state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the input violates the handshake, framing, or
    /// message-processing rules for the configured protocol state.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.ensure_open()?;
        for chunk in data.chunks(self.config.limits.max_buffered_bytes.max(1)) {
            self.handle_input_bytes(Bytes::copy_from_slice(chunk))?;
        }
        Ok(())
    }

    /// Feeds owned transport bytes into the peer state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the input violates the handshake, framing, or
    /// message-processing rules for the configured protocol state.
    pub fn handle_input_bytes(&mut self, data: Bytes) -> Result<(), ProtocolError> {
        self.ensure_open()?;
        let mut data = data;
        while !data.is_empty() {
            let available = self.config.limits.max_buffered_bytes - self.input.remaining();
            if available == 0 {
                return self.fail(ProtocolError::InputBufferLimitExceeded(
                    self.config.limits.max_buffered_bytes,
                ));
            }
            let count = data.len().min(available);
            self.input.push(data.split_to(count));
            if let Err(err) = self.process_input() {
                return self.fail(err);
            }
        }
        Ok(())
    }

    fn process_input(&mut self) -> Result<(), ProtocolError> {
        loop {
            match self.state {
                PeerState::Greeting => {
                    let Some(bytes) = self.input.take_exact(GREETING_SIZE) else {
                        break;
                    };
                    self.process_greeting(&bytes)?;
                }
                PeerState::Handshake => {
                    let Some(frame) =
                        try_decode_frame(&mut self.input, self.config.limits.max_frame_bytes)?
                    else {
                        break;
                    };
                    if !frame.flags.contains(FrameFlags::COMMAND) {
                        return self.fail(ProtocolError::UnexpectedMessageDuringHandshake);
                    }

                    let command = decode_command(frame.body)?;
                    self.process_handshake_command(command)?;
                }
                PeerState::Traffic => {
                    let Some(frame) =
                        try_decode_frame(&mut self.input, self.config.limits.max_frame_bytes)?
                    else {
                        break;
                    };
                    self.process_traffic_frame(frame.flags, frame.body)?;
                }
                PeerState::Closed => return self.ensure_open(),
            }
        }

        Ok(())
    }

    /// Encodes an outbound item for transport.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ConnectionClosed`] if the peer has already
    /// failed or closed, [`ProtocolError::PeerNotReady`] if the handshake is not
    /// complete, or an encoding/mechanism error from the active security layer.
    pub fn submit(&mut self, item: &OutboundItem) -> Result<(), ProtocolError> {
        self.ensure_open()?;
        if self.state != PeerState::Traffic {
            return Err(ProtocolError::PeerNotReady);
        }

        for action in self.mechanism.encode_outbound(item)? {
            self.output.push_back(action);
        }

        Ok(())
    }

    /// Retrieves the next pending protocol action, if any.
    pub fn poll_output(&mut self) -> Option<ProtocolAction> {
        self.output.pop_front()
    }

    fn process_greeting(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let greeting = decode_greeting(bytes)?;
        let expected = self.config.security.mechanism;
        if greeting.mechanism != expected {
            return self.fail(ProtocolError::MechanismMismatch {
                expected,
                actual: greeting.mechanism,
            });
        }

        let expected_as_server = greeting_as_server(
            expected,
            match self.config.security_role {
                SecurityRole::Client => SecurityRole::Server,
                SecurityRole::Server => SecurityRole::Client,
            },
        );

        // This bit lets CURVE agree on which side acts as the server half.
        if greeting.as_server != expected_as_server {
            if expected == SecurityMechanism::Null && greeting.as_server != 0 {
                return self.fail(ProtocolError::InvalidAsServer(greeting.as_server));
            }
            if expected == SecurityMechanism::Curve {
                return self.fail(ProtocolError::InvalidAsServer(greeting.as_server));
            }
        }

        // Once the greeting checks out, the mechanism driver owns the rest.
        self.state = PeerState::Handshake;
        if let Some(complete) =
            self.mechanism
                .on_greeting(&self.config, &self.local_metadata, &mut self.output)?
        {
            self.finish_handshake(complete);
        }

        Ok(())
    }

    fn process_handshake_command(&mut self, command: Command) -> Result<(), ProtocolError> {
        if let Some(complete) = self.mechanism.on_command(
            &self.config,
            &self.local_metadata,
            command,
            &mut self.output,
        )? {
            self.finish_handshake(complete);
        }

        Ok(())
    }

    fn process_traffic_frame(
        &mut self,
        flags: FrameFlags,
        body: Bytes,
    ) -> Result<(), ProtocolError> {
        if flags.contains(FrameFlags::COMMAND) {
            // Control frames cannot interrupt a multipart message already in progress.
            if !self.current_message.is_empty() {
                return self.fail(ProtocolError::InvalidCommandFrame);
            }

            match decode_command(body)? {
                Command::Ready(_) => self.fail(ProtocolError::UnexpectedTrafficCommand("READY")),
                Command::Error(reason) => self.fail(ProtocolError::RemoteError(
                    String::from_utf8_lossy(&reason).into_owned(),
                )),
                Command::Subscribe(topic) => {
                    self.output
                        .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                            subscribe: true,
                            topic,
                        }));
                    Ok(())
                }
                Command::Cancel(topic) => {
                    self.output
                        .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                            subscribe: false,
                            topic,
                        }));
                    Ok(())
                }
                Command::Hello(_) => self.fail(ProtocolError::UnexpectedTrafficCommand("HELLO")),
                Command::Welcome(_) => {
                    self.fail(ProtocolError::UnexpectedTrafficCommand("WELCOME"))
                }
                Command::Initiate(_) => {
                    self.fail(ProtocolError::UnexpectedTrafficCommand("INITIATE"))
                }
                Command::Message(payload) => self.process_secure_message(payload),
            }
        } else {
            self.process_plain_traffic_frame(flags, body)
        }
    }

    fn process_secure_message(&mut self, payload: Bytes) -> Result<(), ProtocolError> {
        // CURVE wraps an inner stream of already-encoded ZMTP frames.
        let decrypted = self.mechanism.decode_message(payload)?;
        let mut input = InputBuffer::default();
        input.push(decrypted);

        loop {
            let Some(frame) = try_decode_frame(&mut input, self.config.limits.max_frame_bytes)?
            else {
                if input.remaining() == 0 {
                    return Ok(());
                }
                return self.fail(ProtocolError::InvalidEncryptedMessage);
            };

            if frame.flags.contains(FrameFlags::COMMAND) {
                match decode_command(frame.body)? {
                    Command::Ready(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("READY"));
                    }
                    Command::Error(reason) => {
                        return self.fail(ProtocolError::RemoteError(
                            String::from_utf8_lossy(&reason).into_owned(),
                        ));
                    }
                    Command::Subscribe(topic) => {
                        self.output
                            .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                                subscribe: true,
                                topic,
                            }));
                    }
                    Command::Cancel(topic) => {
                        self.output
                            .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                                subscribe: false,
                                topic,
                            }));
                    }
                    Command::Hello(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("HELLO"));
                    }
                    Command::Welcome(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("WELCOME"));
                    }
                    Command::Initiate(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("INITIATE"));
                    }
                    Command::Message(_) => {
                        return self.fail(ProtocolError::InvalidEncryptedMessage);
                    }
                }
            } else {
                self.process_plain_traffic_frame(frame.flags, frame.body)?;
            }
        }
    }

    fn process_plain_traffic_frame(
        &mut self,
        flags: FrameFlags,
        body: Bytes,
    ) -> Result<(), ProtocolError> {
        let limits = self.config.limits;
        if self.current_message.len() >= limits.max_message_frames {
            return self.fail(ProtocolError::MessageFrameLimitExceeded(
                limits.max_message_frames,
            ));
        }
        if body.len() > limits.max_message_bytes - self.current_message_bytes {
            return self.fail(ProtocolError::MessageLimitExceeded(
                limits.max_message_bytes,
            ));
        }
        self.current_message_bytes += body.len();
        self.current_message.push(body);
        if !flags.contains(FrameFlags::MORE) {
            // Delivery happens only once we see the final frame of the multipart.
            let message = std::mem::take(&mut self.current_message);
            self.current_message_bytes = 0;
            self.output
                .push_back(ProtocolAction::Event(PeerEvent::Message(message)));
        }
        Ok(())
    }

    fn finish_handshake(&mut self, complete: HandshakeComplete) {
        self.state = PeerState::Traffic;
        // Transports use this event as the point where queued sends may start flowing.
        self.output
            .push_back(ProtocolAction::Event(PeerEvent::HandshakeComplete {
                peer_socket_type: complete.peer_socket_type,
                metadata: complete.metadata,
            }));
    }

    fn fail<T>(&mut self, err: ProtocolError) -> Result<T, ProtocolError> {
        self.state = PeerState::Closed;
        self.input = InputBuffer::default();
        self.current_message.clear();
        self.current_message_bytes = 0;
        self.terminal_error = Some(err.clone());
        Err(err)
    }

    fn ensure_open(&self) -> Result<(), ProtocolError> {
        if let Some(err) = &self.terminal_error {
            return Err(err.clone());
        }
        if self.state == PeerState::Closed {
            return Err(ProtocolError::ConnectionClosed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::CelerityPeer;
    #[cfg(feature = "curve")]
    use crate::CurveConfig;
    use crate::wire::{Command, encode_command, encode_greeting, encode_message_frames};
    use crate::{
        LinkScope, OutboundItem, PeerConfig, PeerEvent, ProtocolAction, ProtocolError,
        SecurityConfig, SecurityRole, SocketType,
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

    fn some<T>(value: Option<T>) -> T {
        match value {
            Some(value) => value,
            None => panic!("expected Some(..), got None"),
        }
    }

    fn flatten_write(action: ProtocolAction) -> Bytes {
        match action {
            ProtocolAction::Write(bytes) => bytes,
            ProtocolAction::WriteVectored { header, body } => {
                let mut out = bytes::BytesMut::with_capacity(header.len() + body.len());
                out.extend_from_slice(&header);
                out.extend_from_slice(&body);
                out.freeze()
            }
            ProtocolAction::Event(_) => panic!("expected write action, got event"),
        }
    }

    fn local_config(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::Local)
    }

    #[cfg(feature = "curve")]
    fn non_local_curve(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::NonLocal)
            .with_security(SecurityConfig::curve())
    }

    fn non_local_insecure_null(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::NonLocal)
            .with_security(SecurityConfig::null().with_insecure_null(true))
    }

    fn pump(
        left: &mut CelerityPeer,
        right: &mut CelerityPeer,
    ) -> Result<Vec<PeerEvent>, ProtocolError> {
        let mut events = Vec::new();
        let mut progress = true;

        while progress {
            progress = false;

            while let Some(action) = left.poll_output() {
                progress = true;
                match action {
                    ProtocolAction::Write(_) | ProtocolAction::WriteVectored { .. } => {
                        right.handle_input_bytes(flatten_write(action))?;
                    }
                    ProtocolAction::Event(event) => events.push(event),
                }
            }

            while let Some(action) = right.poll_output() {
                progress = true;
                match action {
                    ProtocolAction::Write(_) | ProtocolAction::WriteVectored { .. } => {
                        left.handle_input_bytes(flatten_write(action))?;
                    }
                    ProtocolAction::Event(event) => events.push(event),
                }
            }
        }

        Ok(events)
    }

    fn limited_receiver(limits: crate::ProtocolLimits) -> CelerityPeer {
        let mut sender = CelerityPeer::new(local_config(SocketType::Push, SecurityRole::Client));
        let mut receiver = CelerityPeer::new(
            local_config(SocketType::Pull, SecurityRole::Server).with_limits(limits),
        );
        ok(pump(&mut sender, &mut receiver));
        receiver
    }

    #[test]
    fn oversized_frame_headers_close_the_peer_before_payload_arrives() {
        for header in [vec![0, 129], vec![2, 0, 0, 0, 0, 0, 0, 0, 129]] {
            let mut receiver = limited_receiver(crate::ProtocolLimits {
                max_frame_bytes: 128,
                ..crate::ProtocolLimits::default()
            });
            for byte in &header[..header.len() - 1] {
                ok(receiver.handle_input(&[*byte]));
            }
            let error = err(receiver.handle_input(&header[header.len() - 1..]));
            assert_eq!(error, ProtocolError::FrameLimitExceeded(128));
            assert_eq!(err(receiver.handle_input(&[])), error);
            assert_eq!(receiver.input.remaining(), 0);
        }
    }

    #[test]
    fn multipart_byte_limit_counts_frames_and_resets_after_delivery() {
        let mut receiver = limited_receiver(crate::ProtocolLimits {
            max_message_bytes: 4,
            ..crate::ProtocolLimits::default()
        });
        for _ in 0..2 {
            ok(receiver.handle_input(&[1, 2, b'a', b'b', 0, 2, b'c', b'd']));
            assert!(
                matches!(receiver.poll_output(), Some(ProtocolAction::Event(PeerEvent::Message(message)))
                if message == vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")])
            );
        }
        ok(receiver.handle_input(&[1, 4, b'a', b'b', b'c', b'd']));
        assert_eq!(
            err(receiver.handle_input(&[0, 1, b'e'])),
            ProtocolError::MessageLimitExceeded(4)
        );
        assert_eq!(receiver.current_message, Vec::<Bytes>::new());
        assert_eq!(receiver.current_message_bytes, 0);
        assert!(receiver.poll_output().is_none());
    }

    #[test]
    fn multipart_frame_limit_counts_empty_frames() {
        let mut receiver = limited_receiver(crate::ProtocolLimits {
            max_message_frames: 2,
            max_message_bytes: 0,
            ..crate::ProtocolLimits::default()
        });
        ok(receiver.handle_input(&[1, 0, 0, 0]));
        assert!(
            matches!(receiver.poll_output(), Some(ProtocolAction::Event(PeerEvent::Message(message))) if message.len() == 2)
        );
        ok(receiver.handle_input(&[1, 0, 1, 0]));
        assert_eq!(
            err(receiver.handle_input(&[1, 0])),
            ProtocolError::MessageFrameLimitExceeded(2)
        );
        assert_eq!(receiver.current_message, Vec::<Bytes>::new());
    }

    #[test]
    fn input_buffer_limit_applies_before_and_after_handshake() {
        let mut peer = CelerityPeer::new(
            local_config(SocketType::Pull, SecurityRole::Server).with_limits(
                crate::ProtocolLimits {
                    max_buffered_bytes: 8,
                    ..crate::ProtocolLimits::default()
                },
            ),
        );
        ok(peer.handle_input(&[0; 8]));
        assert_eq!(
            err(peer.handle_input(&[0])),
            ProtocolError::InputBufferLimitExceeded(8)
        );
        assert_eq!(peer.input.remaining(), 0);

        let mut receiver = limited_receiver(crate::ProtocolLimits {
            max_buffered_bytes: 128,
            ..crate::ProtocolLimits::default()
        });
        ok(receiver.handle_input(&[0, 127]));
        ok(receiver.handle_input(&[0; 126]));
        assert_eq!(
            err(receiver.handle_input_bytes(Bytes::from_static(&[0]))),
            ProtocolError::InputBufferLimitExceeded(128)
        );
        assert_eq!(receiver.input.remaining(), 0);
    }

    #[test]
    fn coalesced_messages_can_exceed_the_input_buffer_limit() {
        for owned in [false, true] {
            let mut receiver = limited_receiver(crate::ProtocolLimits {
                max_buffered_bytes: 128,
                max_frame_bytes: 126,
                ..crate::ProtocolLimits::default()
            });
            let mut input = vec![0, 126];
            input.extend_from_slice(&[42; 126]);
            input.extend_from_slice(&[0, 0].repeat(128));
            if owned {
                ok(receiver.handle_input_bytes(Bytes::from(input)));
            } else {
                ok(receiver.handle_input(&input));
            }
            let mut delivered = 0;
            while let Some(action) = receiver.poll_output() {
                assert!(matches!(
                    action,
                    ProtocolAction::Event(PeerEvent::Message(_))
                ));
                delivered += 1;
            }
            assert_eq!(delivered, 129);
            assert_eq!(receiver.input.remaining(), 0);
        }
    }

    #[test]
    fn zero_limits_reject_input_and_message_frames() {
        let mut peer = CelerityPeer::new(
            local_config(SocketType::Pull, SecurityRole::Server).with_limits(
                crate::ProtocolLimits {
                    max_buffered_bytes: 0,
                    ..crate::ProtocolLimits::default()
                },
            ),
        );
        assert_eq!(
            err(peer.handle_input_bytes(Bytes::from_static(&[0]))),
            ProtocolError::InputBufferLimitExceeded(0)
        );
        let mut receiver = limited_receiver(crate::ProtocolLimits {
            max_message_frames: 0,
            ..crate::ProtocolLimits::default()
        });
        assert_eq!(
            err(receiver.handle_input(&[0, 0])),
            ProtocolError::MessageFrameLimitExceeded(0)
        );
    }

    #[cfg(feature = "curve")]
    #[test]
    fn curve_multipart_limits_apply_to_decrypted_frames() {
        for (limits, expected) in [
            (
                crate::ProtocolLimits {
                    max_message_bytes: 3,
                    ..crate::ProtocolLimits::default()
                },
                ProtocolError::MessageLimitExceeded(3),
            ),
            (
                crate::ProtocolLimits {
                    max_message_frames: 1,
                    ..crate::ProtocolLimits::default()
                },
                ProtocolError::MessageFrameLimitExceeded(1),
            ),
        ] {
            let mut sender =
                CelerityPeer::new(non_local_curve(SocketType::Push, SecurityRole::Client));
            let mut receiver = CelerityPeer::new(
                non_local_curve(SocketType::Pull, SecurityRole::Server).with_limits(limits),
            );
            ok(pump(&mut sender, &mut receiver));
            ok(sender.submit(&OutboundItem::Message(vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cd"),
            ])));
            assert_eq!(err(pump(&mut sender, &mut receiver)), expected);
            assert_eq!(receiver.current_message, Vec::<Bytes>::new());
            assert_eq!(err(receiver.handle_input(&[])), expected);
        }
    }

    #[test]
    fn byte_by_byte_greeting_parsing() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = server.poll_output();

        let greeting = flatten_write(some(client.poll_output()));

        for byte in greeting.iter().copied().take(greeting.len() - 1) {
            ok(server.handle_input(&[byte]));
            assert!(server.poll_output().is_none());
        }

        ok(server.handle_input(&[greeting[greeting.len() - 1]]));
        assert!(server.poll_output().is_none());
    }

    #[test]
    fn null_handshake_completes() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));

        let events = ok(pump(&mut client, &mut server));
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, PeerEvent::HandshakeComplete { .. }))
        );
    }

    #[test]
    fn incompatible_socket_types_are_rejected() {
        let mut left = CelerityPeer::new(local_config(SocketType::Pub, SecurityRole::Client));
        let mut right = CelerityPeer::new(local_config(SocketType::Pub, SecurityRole::Server));

        let err = err(pump(&mut left, &mut right));
        assert_eq!(
            err,
            ProtocolError::IncompatibleSocketTypes {
                local: SocketType::Pub,
                remote: SocketType::Pub,
            }
        );
    }

    #[test]
    #[cfg(feature = "curve")]
    fn curve_handshake_completes() {
        let mut client = CelerityPeer::new(non_local_curve(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(non_local_curve(SocketType::Rep, SecurityRole::Server));

        let events = ok(pump(&mut client, &mut server));
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, PeerEvent::HandshakeComplete { .. }))
        );
    }

    #[test]
    fn remote_null_is_fail_closed_without_opt_in() {
        let mut peer = CelerityPeer::new(
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::null()),
        );
        assert_eq!(
            err(peer.handle_input(&[])),
            ProtocolError::InsecureNullForNonLocal
        );
        assert!(peer.poll_output().is_none());
    }

    #[test]
    fn explicit_insecure_null_opt_in_allows_remote_handshake() {
        let mut client = CelerityPeer::new(non_local_insecure_null(
            SocketType::Req,
            SecurityRole::Client,
        ));
        let mut server = CelerityPeer::new(non_local_insecure_null(
            SocketType::Rep,
            SecurityRole::Server,
        ));

        let events = ok(pump(&mut client, &mut server));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn traffic_messages_emit_events() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = ok(pump(&mut client, &mut server));

        ok(client.submit(&OutboundItem::Message(vec![
            Bytes::from_static(b""),
            Bytes::from_static(b"ping"),
        ])));

        let events = ok(pump(&mut client, &mut server));
        assert!(events.iter().any(|event| matches!(
            event,
            PeerEvent::Message(message)
                if message == &vec![Bytes::from_static(b""), Bytes::from_static(b"ping")]
        )));
    }

    #[test]
    fn submit_before_handshake_is_rejected() {
        let mut peer = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));

        assert_eq!(
            err(peer.submit(&OutboundItem::Message(vec![Bytes::from_static(b"ping",)]))),
            ProtocolError::PeerNotReady
        );
    }

    #[test]
    fn mechanism_mismatch_is_rejected() {
        let mut left = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut right = CelerityPeer::new(
            local_config(SocketType::Rep, SecurityRole::Server)
                .with_security(SecurityConfig::curve()),
        );

        let err = err(pump(&mut left, &mut right));
        assert_eq!(
            err,
            ProtocolError::MechanismMismatch {
                expected: crate::SecurityMechanism::Curve,
                actual: crate::SecurityMechanism::Null,
            }
        );
    }

    #[test]
    fn invalid_as_server_flag_closes_the_peer() {
        let mut peer = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut greeting =
            encode_greeting(&local_config(SocketType::Rep, SecurityRole::Server)).to_vec();
        greeting[32] = 1;

        let invalid = err(peer.handle_input_bytes(Bytes::from(greeting)));
        assert_eq!(invalid, ProtocolError::InvalidAsServer(1));
        assert_eq!(
            err(peer.handle_input(&[])),
            ProtocolError::InvalidAsServer(1)
        );
    }

    #[test]
    fn plain_message_frames_are_rejected_during_handshake() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = server.poll_output();

        let greeting = flatten_write(some(client.poll_output()));
        ok(server.handle_input_bytes(greeting));

        let mut frames = ok(encode_message_frames(&[Bytes::from_static(b"oops")]));
        let frame = frames.remove(0);
        assert_eq!(
            err(server.handle_input_bytes(frame)),
            ProtocolError::UnexpectedMessageDuringHandshake
        );
    }

    #[test]
    fn traffic_error_command_closes_the_peer() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = ok(pump(&mut client, &mut server));

        let result = client.handle_input_bytes(ok(encode_command(Command::Error(
            Bytes::from_static(b"boom"),
        ))));
        let remote_error = err(result);
        assert_eq!(remote_error, ProtocolError::RemoteError("boom".to_owned()));
        assert_eq!(
            err(client.submit(&OutboundItem::Message(vec![Bytes::from_static(b"again",)]))),
            ProtocolError::RemoteError("boom".to_owned())
        );
    }

    #[test]
    fn command_frames_cannot_interrupt_a_multipart_message() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = ok(pump(&mut client, &mut server));

        let mut frames = ok(encode_message_frames(&[
            Bytes::from_static(b"one"),
            Bytes::from_static(b"two"),
        ]));
        ok(server.handle_input_bytes(frames.remove(0)));

        assert_eq!(
            err(server.handle_input_bytes(ok(encode_command(Command::Subscribe(Bytes::new(),))))),
            ProtocolError::InvalidCommandFrame
        );
    }

    #[test]
    #[cfg(feature = "curve")]
    fn curve_pinned_server_key_mismatch_is_rejected() {
        let mut curve = CurveConfig::default().with_generated_keypair();
        curve.server_public_key = Some([9; 32]);
        let mut client = CelerityPeer::new(
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(curve)),
        );
        let mut server = CelerityPeer::new(non_local_curve(SocketType::Rep, SecurityRole::Server));

        let err = err(pump(&mut client, &mut server));
        assert_eq!(err, ProtocolError::CurveAuthenticationFailed);
    }

    #[test]
    #[cfg(feature = "curve")]
    fn curve_server_rejects_unlisted_client_keys() {
        let mut curve = CurveConfig::default().with_generated_keypair();
        curve.allowed_client_keys = vec![[1; 32]];
        let mut client = CelerityPeer::new(non_local_curve(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(
            PeerConfig::new(SocketType::Rep, SecurityRole::Server, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(curve)),
        );

        let err = err(pump(&mut client, &mut server));
        assert_eq!(err, ProtocolError::CurveAuthenticationFailed);
    }
}
