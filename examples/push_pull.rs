//! Send a task over TCP, or pass an ipc:// endpoint to use a Unix socket.

use bytes::Bytes;
use celerity::io::{PullSocket, PushSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://127.0.0.1:0".into());
    let mut worker = PullSocket::bind(&endpoint).await?;
    let sender = PushSocket::connect(&worker.endpoint().to_string()).await?;
    sender.send(vec![Bytes::from_static(b"task-1")]).await?;
    let task = worker.recv().await?;
    println!("{}", String::from_utf8_lossy(&task[0]));
    Ok(())
}
