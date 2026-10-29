//! Interoperability with libzmq through pyzmq.

#![cfg(feature = "tokio")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bytes::Bytes;
use celerity::Multipart;
use celerity::io::{PubSocket, PullSocket, PushSocket, RepSocket, ReqSocket, SubSocket};
use tokio::time::timeout;

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    }
}

fn message() -> Multipart {
    vec![
        Bytes::from_static(b"topic"),
        Bytes::new(),
        Bytes::from((0..=255).cycle().take(512).collect::<Vec<u8>>()),
    ]
}

struct LibZmq {
    child: Child,
    endpoint: String,
}

impl LibZmq {
    fn start(kind: &str, endpoint: Option<&str>) -> Self {
        let python = std::env::var("CELERITY_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
        let mut command = Command::new(python);
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/libzmq_peer.py"
            ))
            .arg(kind);
        if let Some(endpoint) = endpoint {
            command.arg(endpoint);
        }
        let mut child = ok(command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn());
        let Some(stdout) = child.stdout.take() else {
            panic!("missing child stdout");
        };
        let mut endpoint = String::new();
        assert_ne!(
            ok(BufReader::new(stdout).read_line(&mut endpoint)),
            0,
            "libzmq failed to start"
        );
        Self {
            child,
            endpoint: endpoint.trim().to_owned(),
        }
    }

    async fn finish(&mut self) {
        ok(timeout(Duration::from_secs(8), async {
            loop {
                if let Some(status) = ok(self.child.try_wait()) {
                    assert!(status.success(), "libzmq exited with {status}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await);
    }
}

impl Drop for LibZmq {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn push_to_libzmq_pull() {
    let mut peer = LibZmq::start("PULL", None);
    let socket = ok(PushSocket::connect(&peer.endpoint).await);
    ok(socket.send(message()).await);
    ok(timeout(Duration::from_secs(5), socket.flush())
        .await
        .map(ok));
    peer.finish().await;
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn pull_from_libzmq_push() {
    let mut socket = ok(PullSocket::bind("127.0.0.1:0").await);
    let mut peer = LibZmq::start("PUSH", Some(&format!("tcp://{}", socket.local_addr())));
    assert_eq!(
        ok(ok(timeout(Duration::from_secs(5), socket.recv()).await)),
        message()
    );
    peer.finish().await;
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn request_to_libzmq_rep() {
    let mut peer = LibZmq::start("REP", None);
    let socket = ok(ReqSocket::connect(&peer.endpoint).await);
    assert_eq!(
        ok(ok(timeout(
            Duration::from_secs(5),
            socket.request(message())
        )
        .await)),
        message()
    );
    peer.finish().await;
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn reply_to_libzmq_req() {
    let mut socket = ok(RepSocket::bind("127.0.0.1:0").await);
    let mut peer = LibZmq::start("REQ", Some(&format!("tcp://{}", socket.local_addr())));
    assert_eq!(
        ok(ok(timeout(Duration::from_secs(5), socket.recv()).await)),
        message()
    );
    ok(socket.reply(message()).await);
    peer.finish().await;
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn publish_to_libzmq_sub() {
    let mut socket = ok(PubSocket::bind("127.0.0.1:0").await);
    let mut peer = LibZmq::start("SUB", Some(&format!("tcp://{}", socket.local_addr())));
    assert!(ok(socket.wait_for_subscriber(Duration::from_secs(5)).await));
    ok(socket.send(vec![Bytes::from_static(b"other")]).await);
    ok(socket.send(message()).await);
    peer.finish().await;
}

#[tokio::test]
#[ignore = "requires Python with pyzmq"]
async fn subscribe_to_libzmq_pub() {
    let mut peer = LibZmq::start("PUB", None);
    let mut socket = ok(SubSocket::connect(&peer.endpoint).await);
    ok(socket.subscribe(Bytes::from_static(b"topic")).await);
    assert_eq!(
        ok(ok(timeout(Duration::from_secs(5), socket.recv()).await)),
        message()
    );
    peer.finish().await;
}
