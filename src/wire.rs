use std::collections::VecDeque;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    MetadataMap, OutboundItem, PeerConfig, ProtocolAction, ProtocolError, SecurityMechanism,
    SecurityRole,
};

pub(crate) const GREETING_SIZE: usize = 64;
const SIGNATURE_PREFIX: u8 = 0xFF;
const SIGNATURE_SUFFIX: u8 = 0x7F;
const ZMTP_MAJOR: u8 = 3;
const ZMTP_MINOR: u8 = 1;
const MECHANISM_FIELD_LEN: usize = 20;
const GREETING_FILLER_LEN: usize = 31;
const MAX_METADATA_VALUE_LEN: usize = i32::MAX as usize;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct FrameFlags: u8 {
        const MORE = 0x01;
        const LONG = 0x02;
        const COMMAND = 0x04;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Greeting {
    pub(crate) mechanism: SecurityMechanism,
    pub(crate) as_server: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) flags: FrameFlags,
    pub(crate) body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Ready(Bytes),
    Error(Bytes),
    Subscribe(Bytes),
    Cancel(Bytes),
    Hello(Bytes),
    Welcome(Bytes),
    Initiate(Bytes),
    Message(Bytes),
}

#[derive(Debug, Default)]
pub(crate) struct InputBuffer {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl InputBuffer {
    pub(crate) fn push(&mut self, bytes: Bytes) {
        if !bytes.is_empty() {
            self.len += bytes.len();
            self.chunks.push_back(bytes);
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.len
    }

    pub(crate) fn take_exact(&mut self, len: usize) -> Option<Bytes> {
        if self.len < len {
            return None;
        }

        self.len -= len;

        if let Some(front) = self.chunks.front_mut()
            && front.len() >= len
        {
            let bytes = front.split_to(len);
            if front.is_empty() {
                self.chunks.pop_front();
            }
            return Some(bytes);
        }

        let mut remaining = len;
        // Slow path coalesces bytes that span multiple read chunks.
        let mut out = BytesMut::with_capacity(len);

        while remaining > 0 {
            let Some(mut front) = self.chunks.pop_front() else {
                unreachable!("buffer length was prevalidated");
            };
            if front.len() <= remaining {
                remaining -= front.len();
                out.extend_from_slice(&front);
            } else {
                out.extend_from_slice(&front[..remaining]);
                let tail = front.split_off(remaining);
                self.chunks.push_front(tail);
                remaining = 0;
            }
        }

        Some(out.freeze())
    }

    fn peek_byte(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }

        let mut offset = index;
        for chunk in &self.chunks {
            if offset < chunk.len() {
                return Some(chunk[offset]);
            }
            offset -= chunk.len();
        }

        None
    }

    fn peek_array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if self.len < offset + N {
            return None;
        }

        let mut out = [0_u8; N];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = self.peek_byte(offset + index)?;
        }
        Some(out)
    }
}

pub(crate) fn encode_greeting(config: &PeerConfig) -> Bytes {
    let mut bytes = [0_u8; GREETING_SIZE];
    bytes[0] = SIGNATURE_PREFIX;
    bytes[9] = SIGNATURE_SUFFIX;
    bytes[10] = ZMTP_MAJOR;
    bytes[11] = ZMTP_MINOR;

    let mechanism = config.security.mechanism.name().as_bytes();
    // The mechanism name sits in a fixed-width, NUL-padded field.
    bytes[12..12 + mechanism.len()].copy_from_slice(mechanism);
    bytes[32] = greeting_as_server(config.security.mechanism, config.security_role);

    Bytes::copy_from_slice(&bytes)
}

pub(crate) fn decode_greeting(bytes: &[u8]) -> Result<Greeting, ProtocolError> {
    if bytes.len() != GREETING_SIZE {
        return Err(ProtocolError::InvalidGreetingSignature);
    }

    if bytes[0] != SIGNATURE_PREFIX || bytes[9] != SIGNATURE_SUFFIX {
        return Err(ProtocolError::InvalidGreetingSignature);
    }

    if bytes[33..]
        .iter()
        .take(GREETING_FILLER_LEN)
        .any(|byte| *byte != 0)
    {
        // Non-zero filler means the peer is not speaking the expected greeting format.
        return Err(ProtocolError::InvalidGreetingFiller);
    }

    if (bytes[10], bytes[11]) < (ZMTP_MAJOR, ZMTP_MINOR) {
        return Err(ProtocolError::UnsupportedVersion {
            major: bytes[10],
            minor: bytes[11],
        });
    }

    let mechanism = parse_mechanism(&bytes[12..12 + MECHANISM_FIELD_LEN])?;

    Ok(Greeting {
        mechanism,
        as_server: bytes[32],
    })
}

pub(crate) fn try_decode_frame(
    input: &mut InputBuffer,
    max_frame_bytes: usize,
) -> Result<Option<Frame>, ProtocolError> {
    if input.remaining() < 2 {
        return Ok(None);
    }

    let Some(flags_raw) = input.peek_byte(0) else {
        unreachable!("remaining was checked");
    };
    if flags_raw & !FrameFlags::all().bits() != 0 {
        return Err(ProtocolError::InvalidFrameFlags(flags_raw));
    }

    let flags =
        FrameFlags::from_bits(flags_raw).ok_or(ProtocolError::InvalidFrameFlags(flags_raw))?;
    // ZMTP command frames are always single-frame.
    if flags.contains(FrameFlags::COMMAND) && flags.contains(FrameFlags::MORE) {
        return Err(ProtocolError::CommandWithMore);
    }

    let size_len = if flags.contains(FrameFlags::LONG) {
        8
    } else {
        1
    };
    // Peek lengths first so partial frames stay buffered until complete.
    if input.remaining() < 1 + size_len {
        return Ok(None);
    }

    let size = if flags.contains(FrameFlags::LONG) {
        let Some(raw) = input.peek_array::<8>(1) else {
            unreachable!("length was prevalidated");
        };
        let size = u64::from_be_bytes(raw);
        if size & (1_u64 << 63) != 0 {
            return Err(ProtocolError::NegativeFrameLength);
        }
        usize::try_from(size).map_err(|_| ProtocolError::FrameTooLarge(size))?
    } else {
        let Some(size) = input.peek_byte(1) else {
            unreachable!("length was prevalidated");
        };
        size as usize
    };

    if size > max_frame_bytes {
        return Err(ProtocolError::FrameLimitExceeded(max_frame_bytes));
    }
    let frame_len = size
        .checked_add(1 + size_len)
        .ok_or(ProtocolError::FrameTooLarge(size as u64))?;
    if input.remaining() < frame_len {
        return Ok(None);
    }

    let Some(_) = input.take_exact(1 + size_len) else {
        unreachable!("frame header is available");
    };
    let Some(body) = input.take_exact(size) else {
        unreachable!("frame body is available");
    };

    Ok(Some(Frame { flags, body }))
}

#[cfg_attr(not(feature = "curve"), allow(dead_code))]
pub(crate) fn encode_outbound_item(item: &OutboundItem) -> Result<Vec<Bytes>, ProtocolError> {
    match item {
        OutboundItem::Message(message) => encode_message_frames(message),
        OutboundItem::Subscribe(topic) => {
            Ok(vec![encode_command(Command::Subscribe(topic.clone()))?])
        }
        OutboundItem::Cancel(topic) => Ok(vec![encode_command(Command::Cancel(topic.clone()))?]),
    }
}

pub(crate) fn encode_command(command: Command) -> Result<Bytes, ProtocolError> {
    let (name, payload) = match command {
        Command::Ready(bytes) => (b"READY".as_slice(), bytes),
        Command::Error(reason) => (b"ERROR".as_slice(), encode_short_string(&reason)?),
        Command::Subscribe(topic) => (b"SUBSCRIBE".as_slice(), topic),
        Command::Cancel(topic) => (b"CANCEL".as_slice(), topic),
        Command::Hello(bytes) => (b"HELLO".as_slice(), bytes),
        Command::Welcome(bytes) => (b"WELCOME".as_slice(), bytes),
        Command::Initiate(bytes) => (b"INITIATE".as_slice(), bytes),
        Command::Message(bytes) => (b"MESSAGE".as_slice(), bytes),
    };

    let name_len =
        u8::try_from(name.len()).map_err(|_| ProtocolError::FrameTooLarge(name.len() as u64))?;
    let mut body = BytesMut::with_capacity(1 + name.len() + payload.len());
    body.put_u8(name_len);
    body.extend_from_slice(name);
    body.extend_from_slice(&payload);
    let body = body.freeze();

    Ok(encode_frame(FrameFlags::COMMAND, &body))
}

pub(crate) fn decode_command(body: Bytes) -> Result<Command, ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::InvalidCommandFrame);
    }

    let mut body = body;
    let name_len = body[0] as usize;
    if name_len == 0 || body.len() < 1 + name_len {
        return Err(ProtocolError::InvalidCommandFrame);
    }

    body.advance(1);
    let name = body.split_to(name_len);

    match name.as_ref() {
        b"READY" => Ok(Command::Ready(body)),
        b"ERROR" => decode_short_string(body).map(Command::Error),
        b"SUBSCRIBE" => Ok(Command::Subscribe(body)),
        b"CANCEL" => Ok(Command::Cancel(body)),
        b"HELLO" => Ok(Command::Hello(body)),
        b"WELCOME" => Ok(Command::Welcome(body)),
        b"INITIATE" => Ok(Command::Initiate(body)),
        b"MESSAGE" => Ok(Command::Message(body)),
        _ => Err(ProtocolError::InvalidCommandFrame),
    }
}

#[cfg_attr(not(feature = "curve"), allow(dead_code))]
pub(crate) fn encode_message_frames(message: &[Bytes]) -> Result<Vec<Bytes>, ProtocolError> {
    if message.is_empty() {
        return Err(ProtocolError::EmptyMessage);
    }

    let mut out = Vec::with_capacity(message.len());
    for (index, body) in message.iter().enumerate() {
        let mut flags = FrameFlags::empty();
        // Only the last frame clears MORE and closes the multipart sequence.
        if index + 1 != message.len() {
            flags |= FrameFlags::MORE;
        }
        out.push(encode_frame(flags, body));
    }
    Ok(out)
}

pub(crate) fn encode_message_frame_actions(
    message: &[Bytes],
) -> Result<Vec<ProtocolAction>, ProtocolError> {
    if message.is_empty() {
        return Err(ProtocolError::EmptyMessage);
    }

    let mut out = Vec::with_capacity(message.len());
    for (index, body) in message.iter().enumerate() {
        let mut flags = FrameFlags::empty();
        if index + 1 != message.len() {
            flags |= FrameFlags::MORE;
        }
        out.push(ProtocolAction::WriteVectored {
            header: encode_frame_header(flags, body.len()),
            body: body.clone(),
        });
    }
    Ok(out)
}

pub(crate) fn greeting_as_server(mechanism: SecurityMechanism, role: SecurityRole) -> u8 {
    match mechanism {
        SecurityMechanism::Null => 0,
        SecurityMechanism::Curve => u8::from(matches!(role, SecurityRole::Server)),
    }
}

pub(crate) fn encode_ready(metadata: &MetadataMap) -> Result<Bytes, ProtocolError> {
    encode_command(Command::Ready(encode_metadata(metadata)?))
}

#[cfg_attr(not(feature = "curve"), allow(dead_code))]
pub(crate) fn encode_raw_frames(frames: &[Bytes]) -> Bytes {
    let total_len: usize = frames.iter().map(Bytes::len).sum();
    // Secure transports encrypt the framed byte stream, not just message bodies.
    let mut out = BytesMut::with_capacity(total_len);
    for frame in frames {
        out.extend_from_slice(frame);
    }
    out.freeze()
}

fn encode_frame(flags: FrameFlags, body: &[u8]) -> Bytes {
    let header = encode_frame_header(flags, body.len());
    let mut frame = BytesMut::with_capacity(header.len() + body.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(body);
    frame.freeze()
}

fn encode_frame_header(flags: FrameFlags, body_len: usize) -> Bytes {
    let long = body_len > u8::MAX as usize;
    let mut header = BytesMut::with_capacity(1 + if long { 8 } else { 1 });
    let mut flags = flags;

    if long {
        flags |= FrameFlags::LONG;
        header.put_u8(flags.bits());
        header.put_u64(body_len as u64);
    } else {
        let Ok(body_len) = u8::try_from(body_len) else {
            unreachable!("short frame length was prevalidated");
        };
        header.put_u8(flags.bits());
        header.put_u8(body_len);
    }

    header.freeze()
}

pub(crate) fn encode_metadata(metadata: &MetadataMap) -> Result<Bytes, ProtocolError> {
    let mut out = BytesMut::new();
    for (name, value) in metadata.iter() {
        if value.len() > MAX_METADATA_VALUE_LEN {
            return Err(ProtocolError::FrameTooLarge(value.len() as u64));
        }
        let Ok(name_len) = u8::try_from(name.len()) else {
            unreachable!("metadata names are validated on insert");
        };
        let value_len = u32::try_from(value.len())
            .map_err(|_| ProtocolError::FrameTooLarge(value.len() as u64))?;
        out.put_u8(name_len);
        out.extend_from_slice(name);
        out.put_u32(value_len);
        out.extend_from_slice(value);
    }
    Ok(out.freeze())
}

pub(crate) fn decode_metadata(bytes: Bytes) -> Result<MetadataMap, ProtocolError> {
    let mut bytes = bytes;
    let mut metadata = MetadataMap::new();

    while !bytes.is_empty() {
        let name_len = bytes[0] as usize;
        if name_len == 0 || bytes.len() < 1 + name_len + 4 {
            return Err(ProtocolError::InvalidCommandFrame);
        }

        bytes.advance(1);
        let name = bytes.split_to(name_len);

        let raw_len: [u8; 4] = bytes[..4]
            .try_into()
            .map_err(|_| ProtocolError::InvalidCommandFrame)?;
        let value_len = u32::from_be_bytes(raw_len);
        bytes.advance(4);

        let value_len = usize::try_from(value_len)
            .map_err(|_| ProtocolError::FrameTooLarge(u64::from(value_len)))?;
        if value_len > MAX_METADATA_VALUE_LEN || bytes.len() < value_len {
            return Err(ProtocolError::InvalidCommandFrame);
        }

        let value = bytes.split_to(value_len);
        metadata.insert_bytes(name, value)?;
    }

    Ok(metadata)
}

fn encode_short_string(bytes: &[u8]) -> Result<Bytes, ProtocolError> {
    if bytes.len() > u8::MAX as usize {
        return Err(ProtocolError::FrameTooLarge(bytes.len() as u64));
    }

    let len =
        u8::try_from(bytes.len()).map_err(|_| ProtocolError::FrameTooLarge(bytes.len() as u64))?;
    let mut out = BytesMut::with_capacity(1 + bytes.len());
    out.put_u8(len);
    out.extend_from_slice(bytes);
    Ok(out.freeze())
}

fn decode_short_string(mut bytes: Bytes) -> Result<Bytes, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidCommandFrame);
    }

    let len = bytes[0] as usize;
    bytes.advance(1);
    if bytes.len() != len {
        return Err(ProtocolError::InvalidCommandFrame);
    }

    Ok(bytes)
}

fn parse_mechanism(field: &[u8]) -> Result<SecurityMechanism, ProtocolError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::InvalidGreetingFiller);
    }

    match &field[..end] {
        b"NULL" => Ok(SecurityMechanism::Null),
        b"CURVE-RS" => Ok(SecurityMechanism::Curve),
        other => Err(ProtocolError::UnsupportedMechanismName(
            String::from_utf8_lossy(other).into_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        Command, FrameFlags, GREETING_SIZE, Greeting, InputBuffer, decode_command, decode_greeting,
        decode_metadata, encode_command, encode_greeting, encode_message_frames, encode_metadata,
        greeting_as_server, try_decode_frame,
    };
    use crate::{
        LinkScope, MetadataMap, PeerConfig, ProtocolError, SecurityConfig, SecurityMechanism,
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

    fn some<T>(value: Option<T>) -> T {
        match value {
            Some(value) => value,
            None => panic!("expected Some(..), got None"),
        }
    }

    #[test]
    fn greeting_roundtrip() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local);
        let greeting_bytes = encode_greeting(&config);
        let greeting = ok(decode_greeting(&greeting_bytes));
        assert_eq!(
            greeting,
            Greeting {
                mechanism: SecurityMechanism::Null,
                as_server: 0,
            }
        );
    }

    #[test]
    fn ready_metadata_roundtrip() {
        let mut metadata = MetadataMap::new();
        ok(metadata.insert("Socket-Type", "REQ"));
        ok(metadata.insert("Identity", Bytes::from_static(b"alpha")));
        ok(metadata.insert("X-Test", Bytes::from_static(b"value")));

        let encoded = ok(encode_command(Command::Ready(ok(encode_metadata(
            &metadata,
        )))));
        let mut input = InputBuffer::default();
        input.push(encoded);

        let frame = some(ok(try_decode_frame(&mut input, usize::MAX)));
        assert_eq!(frame.flags, FrameFlags::COMMAND);
        let decoded = ok(decode_command(frame.body));
        let Command::Ready(bytes) = decoded else {
            panic!("expected ready command");
        };
        assert_eq!(ok(decode_metadata(bytes)), metadata);
    }

    #[test]
    fn short_and_long_frames_roundtrip() {
        let frames = ok(encode_message_frames(&[
            Bytes::from_static(b"short"),
            Bytes::from(vec![0xAB; 512]),
        ]));

        let mut input = InputBuffer::default();
        for frame in &frames {
            input.push(frame.clone());
        }

        let first = some(ok(try_decode_frame(&mut input, usize::MAX)));
        assert_eq!(first.flags, FrameFlags::MORE);
        assert_eq!(first.body, Bytes::from_static(b"short"));

        let second = some(ok(try_decode_frame(&mut input, usize::MAX)));
        assert!(second.flags.contains(FrameFlags::LONG));
        assert_eq!(second.body, Bytes::from(vec![0xAB; 512]));
    }

    #[test]
    fn frames_decode_at_every_split_point() {
        for size in [0, 1, 255, 256, 1024] {
            let body = Bytes::from(vec![0xAB; size]);
            let encoded = ok(encode_message_frames(std::slice::from_ref(&body))).remove(0);
            for split in 0..encoded.len() {
                let mut input = InputBuffer::default();
                input.push(encoded.slice(..split));
                assert!(ok(try_decode_frame(&mut input, size)).is_none());
                assert_eq!(input.remaining(), split);
                input.push(encoded.slice(split..));
                assert_eq!(some(ok(try_decode_frame(&mut input, size))).body, body);
                assert_eq!(input.remaining(), 0);
            }
        }
    }

    #[test]
    fn every_flag_byte_is_validated() {
        for flags in 0..=u8::MAX {
            let mut input = InputBuffer::default();
            input.push(Bytes::from(vec![flags, 0, 0, 0, 0, 0, 0, 0, 0]));
            let result = try_decode_frame(&mut input, 0);
            if flags & !FrameFlags::all().bits() != 0 {
                assert_eq!(err(result), ProtocolError::InvalidFrameFlags(flags));
            } else if flags & (FrameFlags::COMMAND | FrameFlags::MORE).bits()
                == (FrameFlags::COMMAND | FrameFlags::MORE).bits()
            {
                assert_eq!(err(result), ProtocolError::CommandWithMore);
            } else {
                assert_eq!(some(ok(result)).flags.bits(), flags);
            }
        }
    }

    #[test]
    fn metadata_rejects_every_truncated_property() {
        let mut metadata = MetadataMap::new();
        ok(metadata.insert("Socket-Type", "PULL"));
        let encoded = ok(encode_metadata(&metadata));
        for end in 1..encoded.len() {
            assert_eq!(
                err(decode_metadata(encoded.slice(..end))),
                ProtocolError::InvalidCommandFrame
            );
        }
        let mut oversized = vec![1, b'A'];
        oversized.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            err(decode_metadata(Bytes::from(oversized))),
            ProtocolError::InvalidCommandFrame
        );
    }

    #[test]
    fn malformed_flags_are_rejected() {
        let mut input = InputBuffer::default();
        input.push(Bytes::from_static(&[0x80, 0x00]));
        assert_eq!(
            err(try_decode_frame(&mut input, usize::MAX)),
            ProtocolError::InvalidFrameFlags(0x80)
        );
    }

    #[test]
    fn malformed_long_size_is_rejected() {
        let mut input = InputBuffer::default();
        let mut frame = vec![0x02];
        frame.extend_from_slice(&(1_u64 << 63).to_be_bytes());
        input.push(Bytes::from(frame));
        assert_eq!(
            err(try_decode_frame(&mut input, usize::MAX)),
            ProtocolError::NegativeFrameLength
        );
    }

    #[test]
    fn greeting_accepts_signature_padding_and_newer_versions() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local);
        for version in [(3, 1), (3, 255), (4, 0)] {
            let mut greeting = encode_greeting(&config).to_vec();
            greeting[1..9].fill(0xAB);
            greeting[10] = version.0;
            greeting[11] = version.1;
            assert_eq!(
                ok(decode_greeting(&greeting)).mechanism,
                SecurityMechanism::Null
            );
        }
    }

    #[test]
    fn greeting_has_expected_wire_size() {
        let config = PeerConfig::new(SocketType::Pub, SecurityRole::Server, LinkScope::NonLocal)
            .with_security(SecurityConfig::curve());
        let greeting = encode_greeting(&config);
        assert_eq!(greeting.len(), GREETING_SIZE);
        assert_eq!(
            ok(decode_greeting(&greeting)).as_server,
            greeting_as_server(SecurityMechanism::Curve, SecurityRole::Server)
        );
    }

    #[test]
    fn greeting_rejects_invalid_signature_and_version() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local);

        let mut bad_signature = encode_greeting(&config).to_vec();
        bad_signature[0] ^= 0x01;
        assert_eq!(
            err(decode_greeting(&Bytes::from(bad_signature))),
            ProtocolError::InvalidGreetingSignature
        );

        let mut bad_version = encode_greeting(&config).to_vec();
        bad_version[10] = 2;
        assert_eq!(
            err(decode_greeting(&Bytes::from(bad_version))),
            ProtocolError::UnsupportedVersion { major: 2, minor: 1 }
        );
    }

    #[test]
    fn greeting_rejects_standard_curve_mechanism_marker() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
            .with_security(SecurityConfig::curve());
        let mut greeting = encode_greeting(&config).to_vec();
        let field = &mut greeting[12..12 + super::MECHANISM_FIELD_LEN];
        field.fill(0);
        field[..5].copy_from_slice(b"CURVE");

        assert_eq!(
            err(decode_greeting(&greeting)),
            ProtocolError::UnsupportedMechanismName("CURVE".into())
        );
    }

    #[test]
    fn frame_limits_apply_to_commands_and_zero_length_frames() {
        let mut input = InputBuffer::default();
        input.push(Bytes::from(vec![FrameFlags::COMMAND.bits(), 1]));
        assert_eq!(
            err(try_decode_frame(&mut input, 0)),
            ProtocolError::FrameLimitExceeded(0)
        );
        let mut input = InputBuffer::default();
        input.push(Bytes::from_static(&[0, 0]));
        assert!(some(ok(try_decode_frame(&mut input, 0))).body.is_empty());
    }

    #[test]
    fn command_frames_must_not_set_more() {
        let mut input = InputBuffer::default();
        input.push(Bytes::from(vec![
            (FrameFlags::COMMAND | FrameFlags::MORE).bits(),
            0,
        ]));

        assert_eq!(
            err(try_decode_frame(&mut input, usize::MAX)),
            ProtocolError::CommandWithMore
        );
    }

    #[test]
    fn command_and_metadata_decoders_reject_malformed_payloads() {
        assert_eq!(
            err(decode_command(Bytes::from_static(&[3, b'O', b'K']))),
            ProtocolError::InvalidCommandFrame
        );
        assert_eq!(
            err(decode_metadata(Bytes::from_static(&[0, 0, 0, 0, 0]))),
            ProtocolError::InvalidCommandFrame
        );
        assert_eq!(
            err(decode_metadata(Bytes::from_static(&[
                1, b'A', 0, 0, 0, 4, b'x'
            ]))),
            ProtocolError::InvalidCommandFrame
        );
    }

    #[test]
    fn empty_multipart_messages_are_rejected() {
        assert_eq!(err(encode_message_frames(&[])), ProtocolError::EmptyMessage);
    }
}
