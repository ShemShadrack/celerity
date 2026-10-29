//! Tokio transport integration tests.

#![cfg(feature = "tokio")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use celerity::io::{
    PubSocket, PullSocket, PushSocket, RepSocket, ReqSocket, SubSocket, TokioCelerity,
    TokioCelerityError, TransportKind, TransportMeta,
};
use celerity::{
    CelerityPeer, HwmConfig, HwmPolicy, LinkScope, OutboundItem, PeerConfig, PeerEvent,
    ProtocolAction, ProtocolError, ProtocolLimits, SecurityRole, SocketType,
};
#[cfg(feature = "curve")]
use celerity::{CurveConfig, SecurityConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected Ok(..), got Err({err:?})"),
    }
}

fn some<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("expected Some(..), got None"),
    }
}

async fn raw_push_connection(limits: ProtocolLimits) -> (TcpStream, TokioCelerity) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let mut raw = ok(TcpStream::connect(ok(listener.local_addr())).await);
    let (stream, _) = ok(listener.accept().await);
    let mut receiver = ok(TokioCelerity::from_stream(
        stream,
        TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: LinkScope::Local,
            null_authorized: true,
        },
        PeerConfig::new(SocketType::Pull, SecurityRole::Server, LinkScope::Local)
            .with_limits(limits),
    ));
    let mut peer = CelerityPeer::new(PeerConfig::new(
        SocketType::Push,
        SecurityRole::Client,
        LinkScope::Local,
    ));
    let mut ready = false;
    while !ready {
        while let Some(action) = peer.poll_output() {
            match action {
                ProtocolAction::Write(bytes) => ok(raw.write_all(&bytes).await),
                ProtocolAction::WriteVectored { header, body } => {
                    ok(raw.write_all(&header).await);
                    ok(raw.write_all(&body).await);
                }
                ProtocolAction::Event(PeerEvent::HandshakeComplete { .. }) => ready = true,
                ProtocolAction::Event(event) => panic!("unexpected event: {event:?}"),
            }
        }
        if !ready {
            let mut buffer = [0; 1024];
            let count = ok(raw.read(&mut buffer).await);
            assert_ne!(count, 0);
            ok(peer.handle_input(&buffer[..count]));
        }
    }
    assert!(matches!(
        receiver.recv().await,
        Some(PeerEvent::HandshakeComplete { .. })
    ));
    (raw, receiver)
}

#[tokio::test]
async fn disconnect_mid_multipart_does_not_deliver_partial_messages() {
    let (mut raw, mut receiver) = ok(timeout(
        Duration::from_secs(2),
        raw_push_connection(ProtocolLimits::default()),
    )
    .await);
    ok(raw.write_all(&[1, 2, b'a', b'b', 0, 4, b'x']).await);
    ok(raw.shutdown().await);
    assert!(ok(timeout(Duration::from_secs(2), receiver.recv()).await).is_none());
    ok(ok(timeout(Duration::from_secs(2), receiver.join()).await));
}

#[tokio::test]
async fn oversized_tcp_frame_is_rejected_without_waiting_for_payload() {
    let limits = ProtocolLimits {
        max_frame_bytes: 128,
        ..ProtocolLimits::default()
    };
    let (mut raw, mut receiver) =
        ok(timeout(Duration::from_secs(2), raw_push_connection(limits)).await);
    ok(raw.write_all(&[2, 0, 0, 0, 0, 0, 0, 1, 0]).await);
    assert!(ok(timeout(Duration::from_secs(2), receiver.recv()).await).is_none());
    assert!(matches!(
        ok(timeout(Duration::from_secs(2), receiver.join()).await),
        Err(TokioCelerityError::Protocol(
            ProtocolError::FrameLimitExceeded(128)
        ))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokio_celerity_delivers_subscription_events_over_tcp() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let endpoint = ok(listener.local_addr()).to_string();

    let server = tokio::spawn(async move {
        let (stream, addr) = ok(listener.accept().await);
        let transport = TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: if addr.ip().is_loopback() {
                LinkScope::Local
            } else {
                LinkScope::NonLocal
            },
            null_authorized: addr.ip().is_loopback(),
        };
        let server = TokioCelerity::from_stream(
            stream,
            transport,
            PeerConfig::new(SocketType::Pub, SecurityRole::Server, transport.link_scope),
        );
        let mut server = ok(server);

        loop {
            match ok(timeout(Duration::from_secs(1), server.recv()).await) {
                Some(PeerEvent::Subscription { subscribe, topic }) => {
                    return (subscribe, topic);
                }
                Some(_) => {}
                None => panic!("server closed before subscription arrived"),
            }
        }
    });

    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Sub, SecurityRole::Client, LinkScope::Local),
    );
    let client = ok(client.await);
    ok(client
        .send(OutboundItem::Subscribe(Bytes::from_static(b"topic")))
        .await);

    let (subscribe, topic) = ok(server.await);
    assert!(subscribe);
    assert_eq!(topic, Bytes::from_static(b"topic"));
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_roundtrip_over_tcp_loopback() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let endpoint = ok(listener.local_addr()).to_string();

    let server = tokio::spawn(async move {
        let (stream, addr) = ok(listener.accept().await);
        let transport = TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: if addr.ip().is_loopback() {
                LinkScope::Local
            } else {
                LinkScope::NonLocal
            },
            null_authorized: addr.ip().is_loopback(),
        };
        let config = PeerConfig::new(SocketType::Rep, SecurityRole::Server, transport.link_scope)
            .with_security(SecurityConfig::curve());
        let mut server = ok(TokioCelerity::from_stream(stream, transport, config));

        loop {
            match ok(timeout(Duration::from_secs(2), server.recv()).await) {
                Some(PeerEvent::Message(message)) => {
                    assert_eq!(message, vec![Bytes::new(), Bytes::from_static(b"ping")]);
                    ok(server
                        .send(OutboundItem::Message(vec![
                            Bytes::new(),
                            Bytes::from_static(b"pong"),
                        ]))
                        .await);
                    return;
                }
                Some(_) => {}
                None => panic!("server closed before request arrived"),
            }
        }
    });

    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve()),
    );
    let mut client = ok(client.await);
    ok(client
        .send(OutboundItem::Message(vec![
            Bytes::new(),
            Bytes::from_static(b"ping"),
        ]))
        .await);

    loop {
        match ok(timeout(Duration::from_secs(2), client.recv()).await) {
            Some(PeerEvent::Message(message)) => {
                assert_eq!(message, vec![Bytes::new(), Bytes::from_static(b"pong")]);
                break;
            }
            Some(_) => {}
            None => panic!("client closed before reply arrived"),
        }
    }

    ok(server.await);
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_handshake_timeout_is_enforced() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let endpoint = ok(listener.local_addr()).to_string();

    let server = tokio::spawn(async move {
        let (_stream, _) = ok(listener.accept().await);
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut curve = CurveConfig::default().with_generated_keypair();
    curve.handshake_timeout_ms = 50;
    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve().with_curve_config(curve)),
    );
    let client = ok(client.await);

    let Err(err) = client.join().await else {
        panic!("expected Err(..), got Ok(..)");
    };
    assert!(matches!(err, TokioCelerityError::HandshakeTimeout));
    ok(server.await);
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_keypair_mismatch_is_rejected_early() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let addr = ok(listener.local_addr());
    let accepted = tokio::spawn(async move {
        let (_stream, _) = ok(listener.accept().await);
    });

    let stream = ok(tokio::net::TcpStream::connect(addr).await);
    let mut curve = CurveConfig::default().with_generated_keypair();
    curve.local_static_keypair.public[0] ^= 0x01;
    let Err(err) = TokioCelerity::from_stream(
        stream,
        TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: LinkScope::Local,
            null_authorized: true,
        },
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve().with_curve_config(curve)),
    ) else {
        panic!("mismatched CURVE keypair should be rejected");
    };

    assert!(matches!(
        err,
        TokioCelerityError::Protocol(ProtocolError::InvalidCurveKeyPair)
    ));
    ok(accepted.await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_newest_drops_pre_auth_messages_instead_of_blocking() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await);
    let endpoint = ok(listener.local_addr()).to_string();

    let server = tokio::spawn(async move {
        let (_stream, _) = ok(listener.accept().await);
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    let hwm = HwmConfig {
        outbound_messages: 1,
        policy: HwmPolicy::DropNewest,
        ..HwmConfig::default()
    };

    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Pub, SecurityRole::Client, LinkScope::Local).with_hwm(hwm),
    );
    let client = ok(client.await);

    ok(ok(timeout(
        Duration::from_millis(100),
        client.send(OutboundItem::Message(vec![Bytes::from_static(b"first")])),
    )
    .await));
    ok(ok(timeout(
        Duration::from_millis(100),
        client.send(OutboundItem::Message(vec![Bytes::from_static(b"second")])),
    )
    .await));

    let _ = ok(timeout(Duration::from_secs(1), client.join()).await);
    ok(server.await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pub_sub_roundtrip_over_tcp() {
    let mut publisher = ok(PubSocket::bind("127.0.0.1:0").await);
    let endpoint = publisher.local_addr().to_string();
    let mut subscriber = ok(SubSocket::connect(&endpoint).await);

    ok(subscriber.subscribe(Bytes::new()).await);
    let has_subscriber = ok(publisher.wait_for_subscriber(Duration::from_secs(1)).await);
    assert!(has_subscriber);

    ok(publisher.send(vec![Bytes::from_static(b"hello")]).await);

    let message = ok(ok(timeout(Duration::from_secs(1), subscriber.recv()).await));
    assert_eq!(message, vec![Bytes::from_static(b"hello")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_send_without_subscribers_is_a_noop() {
    let publisher = ok(PubSocket::bind("127.0.0.1:0").await);
    ok(publisher.send(vec![Bytes::from_static(b"orphaned")]).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_for_subscriber_times_out_when_no_subscribers_arrive() {
    let mut publisher = ok(PubSocket::bind("127.0.0.1:0").await);

    let has_subscriber = ok(publisher
        .wait_for_subscriber(Duration::from_millis(100))
        .await);
    assert!(!has_subscriber);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_pull_roundtrip_over_tcp() {
    let mut puller = ok(PullSocket::bind("127.0.0.1:0").await);
    let endpoint = puller.local_addr().to_string();
    let pusher = ok(PushSocket::connect(&endpoint).await);

    ok(pusher.send(vec![Bytes::from_static(b"work-item")]).await);

    let message = ok(ok(timeout(Duration::from_secs(1), puller.recv()).await));
    assert_eq!(message, vec![Bytes::from_static(b"work-item")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_socket_rejects_empty_messages_over_tcp() {
    let puller = ok(PullSocket::bind("127.0.0.1:0").await);
    let endpoint = puller.local_addr().to_string();
    let pusher = ok(PushSocket::connect(&endpoint).await);

    let err = match pusher.send(Vec::new()).await {
        Ok(()) => panic!("expected Err(..), got Ok(..)"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        TokioCelerityError::Protocol(ProtocolError::EmptyMessage)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pull_socket_accepts_messages_from_multiple_pushers() {
    let mut puller = ok(PullSocket::bind("127.0.0.1:0").await);
    let endpoint = puller.local_addr().to_string();
    let first = ok(PushSocket::connect(&endpoint).await);
    let second = ok(PushSocket::connect(&endpoint).await);

    ok(first.send(vec![Bytes::from_static(b"one")]).await);
    ok(second.send(vec![Bytes::from_static(b"two")]).await);

    let first_message = ok(ok(timeout(Duration::from_secs(1), puller.recv()).await));
    let second_message = ok(ok(timeout(Duration::from_secs(1), puller.recv()).await));

    let mut received = vec![first_message, second_message];
    received.sort();
    assert_eq!(
        received,
        vec![
            vec![Bytes::from_static(b"one")],
            vec![Bytes::from_static(b"two")],
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_rep_roundtrip_over_tcp() {
    let mut responder = ok(RepSocket::bind("127.0.0.1:0").await);
    let endpoint = responder.local_addr().to_string();
    let requester = ok(ReqSocket::connect(&endpoint).await);

    let server = tokio::spawn(async move {
        let message = ok(responder.recv().await);
        assert_eq!(message, vec![Bytes::from_static(b"ping")]);
        ok(responder.reply(vec![Bytes::from_static(b"pong")]).await);
    });

    let reply = ok(requester.request(vec![Bytes::from_static(b"ping")]).await);
    assert_eq!(reply, vec![Bytes::from_static(b"pong")]);

    ok(server.await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rep_socket_keeps_progress_with_two_clients() {
    let mut responder = ok(RepSocket::bind("127.0.0.1:0").await);
    let endpoint = responder.local_addr().to_string();
    let requester_one = ok(ReqSocket::connect(&endpoint).await);
    let requester_two = ok(ReqSocket::connect(&endpoint).await);

    let first = tokio::spawn(async move {
        ok(requester_one
            .request(vec![Bytes::from_static(b"one")])
            .await)
    });

    let first_message = ok(ok(timeout(Duration::from_secs(1), responder.recv()).await));
    assert_eq!(first_message, vec![Bytes::from_static(b"one")]);

    let second = tokio::spawn(async move {
        ok(requester_two
            .request(vec![Bytes::from_static(b"two")])
            .await)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    ok(responder.reply(vec![Bytes::from_static(b"ack-one")]).await);

    let second_message = ok(ok(timeout(Duration::from_secs(1), responder.recv()).await));
    assert_eq!(second_message, vec![Bytes::from_static(b"two")]);

    ok(responder.reply(vec![Bytes::from_static(b"ack-two")]).await);

    assert_eq!(ok(first.await), vec![Bytes::from_static(b"ack-one")]);
    assert_eq!(ok(second.await), vec![Bytes::from_static(b"ack-two")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sub_cancel_stops_future_deliveries() {
    let mut publisher = ok(PubSocket::bind("127.0.0.1:0").await);
    let endpoint = publisher.local_addr().to_string();
    let mut subscriber = ok(SubSocket::connect(&endpoint).await);

    ok(subscriber.subscribe(Bytes::from_static(b"topic")).await);
    let has_subscriber = ok(publisher.wait_for_subscriber(Duration::from_secs(1)).await);
    assert!(has_subscriber);

    ok(publisher.send(vec![Bytes::from_static(b"topic-one")]).await);
    let first = ok(ok(timeout(Duration::from_secs(1), subscriber.recv()).await));
    assert_eq!(first, vec![Bytes::from_static(b"topic-one")]);

    ok(subscriber.cancel(Bytes::from_static(b"topic")).await);
    tokio::time::sleep(Duration::from_millis(100)).await;

    ok(publisher.send(vec![Bytes::from_static(b"topic-two")]).await);
    assert!(
        timeout(Duration::from_millis(200), subscriber.recv())
            .await
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_pub_sub_roundtrip_and_cleanup() {
    let path = unique_ipc_path("pub-sub");
    let endpoint = format!("ipc://{}", path.display());
    ok(std::fs::create_dir_all(some(path.parent())));

    {
        let mut publisher = ok(PubSocket::bind(&endpoint).await);
        let mut subscriber = ok(SubSocket::connect(&endpoint).await);
        ok(subscriber.subscribe(Bytes::new()).await);
        let has_subscriber = ok(publisher.wait_for_subscriber(Duration::from_secs(1)).await);
        assert!(has_subscriber);
        ok(publisher.send(vec![Bytes::from_static(b"hello-ipc")]).await);
        let message = ok(ok(timeout(Duration::from_secs(1), subscriber.recv()).await));
        assert_eq!(message, vec![Bytes::from_static(b"hello-ipc")]);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!path.exists(), "IPC socket file should be removed on drop");
    let _ = std::fs::remove_dir_all(some(path.parent()));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_push_pull_roundtrip_and_cleanup() {
    let path = unique_ipc_path("push-pull");
    let endpoint = format!("ipc://{}", path.display());
    ok(std::fs::create_dir_all(some(path.parent())));

    {
        let mut puller = ok(PullSocket::bind(&endpoint).await);
        let pusher = ok(PushSocket::connect(&endpoint).await);
        ok(pusher.send(vec![Bytes::from_static(b"hello-ipc")]).await);
        let message = ok(ok(timeout(Duration::from_secs(1), puller.recv()).await));
        assert_eq!(message, vec![Bytes::from_static(b"hello-ipc")]);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!path.exists(), "IPC socket file should be removed on drop");
    let _ = std::fs::remove_dir_all(some(path.parent()));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_stale_socket_is_replaced() {
    let path = unique_ipc_path("stale");
    let endpoint = format!("ipc://{}", path.display());
    ok(std::fs::create_dir_all(some(path.parent())));
    let stale = ok(std::os::unix::net::UnixListener::bind(&path));
    drop(stale);

    {
        let socket = ok(PubSocket::bind(&endpoint).await);
        assert!(path.exists());
        drop(socket);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !path.exists(),
        "stale socket replacement should still clean up"
    );
    let _ = std::fs::remove_dir_all(some(path.parent()));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_strict_auth_rejects_world_writable_parent() {
    let parent = unique_ipc_parent("bad-parent");
    ok(std::fs::create_dir_all(&parent));
    ok(std::fs::set_permissions(
        &parent,
        std::fs::Permissions::from_mode(0o777),
    ));
    let path = parent.join("celerity.sock");
    let endpoint = format!("ipc://{}", path.display());

    let Err(err) = PubSocket::bind(&endpoint).await else {
        panic!("bind should fail for a world-writable parent directory");
    };
    assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&parent);
}

#[cfg(unix)]
fn unique_ipc_path(name: &str) -> std::path::PathBuf {
    unique_ipc_parent(name).join("celerity.sock")
}

#[cfg(unix)]
fn unique_ipc_parent(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("/tmp");
    let unique = ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_nanos();
    path.push(format!("cel-{name}-{}-{unique}", std::process::id()));
    path
}
