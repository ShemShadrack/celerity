//! Pin the server identity and restrict clients using CURVE-RS.

use bytes::Bytes;
use celerity::io::{TokioCelerity, TokioCelerityError, TransportKind, TransportMeta};
use celerity::{
    CurveConfig, CurveKeyPair, LinkScope, Multipart, OutboundItem, PeerConfig, PeerEvent,
    SecurityConfig, SecurityRole, SocketType,
};
use tokio::net::TcpListener;

async fn recv_message(peer: &mut TokioCelerity) -> Result<Multipart, TokioCelerityError> {
    while let Some(event) = peer.recv().await {
        if let PeerEvent::Message(message) = event {
            return Ok(message);
        }
    }
    Err(TokioCelerityError::BackgroundTaskEnded)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_key = CurveKeyPair::generate();
    let client_key = CurveKeyPair::generate();
    let client_config = PeerConfig::new(SocketType::Push, SecurityRole::Client, LinkScope::Local)
        .with_security(SecurityConfig::curve().with_curve_config(CurveConfig {
            server_public_key: Some(server_key.public),
            local_static_keypair: client_key.clone(),
            ..CurveConfig::default()
        }));
    let server_config = PeerConfig::new(SocketType::Pull, SecurityRole::Server, LinkScope::Local)
        .with_security(SecurityConfig::curve().with_curve_config(CurveConfig {
            local_static_keypair: server_key,
            allowed_client_keys: vec![client_key.public],
            ..CurveConfig::default()
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let sender = TokioCelerity::connect(&listener.local_addr()?.to_string(), client_config).await?;
    let (stream, _) = listener.accept().await?;
    let mut receiver = TokioCelerity::from_stream(
        stream,
        TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: LinkScope::Local,
            null_authorized: true,
        },
        server_config,
    )?;
    sender
        .send(OutboundItem::Message(vec![Bytes::from_static(
            b"encrypted task",
        )]))
        .await?;
    let message = recv_message(&mut receiver).await?;
    println!("{}", String::from_utf8_lossy(&message[0]));
    Ok(())
}
