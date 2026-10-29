//! Exchange a multipart request and reply.

use bytes::Bytes;
use celerity::io::{RepSocket, ReqSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut responder = RepSocket::bind("127.0.0.1:0").await?;
    let requester = ReqSocket::connect(&responder.local_addr().to_string()).await?;
    let respond = async {
        let request = responder.recv().await?;
        responder.reply(request).await
    };
    let ((), reply) = tokio::try_join!(
        respond,
        requester.request(vec![Bytes::from_static(b"hello")])
    )?;
    println!("{}", String::from_utf8_lossy(&reply[0]));
    Ok(())
}
