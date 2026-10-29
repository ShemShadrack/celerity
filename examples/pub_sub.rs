//! Publish and receive a topic-filtered multipart message.

use std::time::Duration;

use bytes::Bytes;
use celerity::io::{PubSocket, SubSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut publisher = PubSocket::bind("127.0.0.1:0").await?;
    let mut subscriber = SubSocket::connect(&publisher.local_addr().to_string()).await?;
    subscriber.subscribe(Bytes::from_static(b"weather")).await?;
    if !publisher
        .wait_for_subscriber(Duration::from_secs(5))
        .await?
    {
        return Err("subscriber did not become ready".into());
    }
    publisher
        .send(vec![
            Bytes::from_static(b"weather"),
            Bytes::from_static(b"Vienna: 18 C"),
        ])
        .await?;
    let message = tokio::time::timeout(Duration::from_secs(5), subscriber.recv()).await??;
    println!("{}", String::from_utf8_lossy(&message[1]));
    Ok(())
}
