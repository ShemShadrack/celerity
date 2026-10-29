#![no_main]

use celerity::{
    CelerityPeer, LinkScope, OutboundItem, PeerConfig, PeerEvent, ProtocolAction, ProtocolLimits,
    SecurityRole, SocketType,
};
use libfuzzer_sys::fuzz_target;

fn transfer(from: &mut CelerityPeer, to: &mut CelerityPeer) -> bool {
    let mut progress = false;
    while let Some(action) = from.poll_output() {
        match action {
            ProtocolAction::Write(bytes) => {
                assert!(to.handle_input_bytes(bytes).is_ok());
                progress = true;
            }
            ProtocolAction::WriteVectored { header, body } => {
                assert!(to.handle_input_bytes(header).is_ok());
                assert!(to.handle_input_bytes(body).is_ok());
                progress = true;
            }
            ProtocolAction::Event(_) => {}
        }
    }
    progress
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, data)) = data.split_first() else {
        return;
    };
    let limits = ProtocolLimits {
        max_frame_bytes: 512,
        max_message_bytes: 1024,
        max_message_frames: 8,
        max_buffered_bytes: 1024,
    };
    let mut peer = CelerityPeer::new(
        PeerConfig::new(SocketType::Pull, SecurityRole::Server, LinkScope::Local)
            .with_limits(limits),
    );
    let mut remote = CelerityPeer::new(PeerConfig::new(
        SocketType::Push,
        SecurityRole::Client,
        LinkScope::Local,
    ));
    match control % 3 {
        1 => {
            transfer(&mut remote, &mut peer);
        }
        2 => loop {
            let sent = transfer(&mut remote, &mut peer);
            let received = transfer(&mut peer, &mut remote);
            if !sent && !received {
                break;
            }
        },
        _ => {}
    }
    while peer.poll_output().is_some() {}
    for chunk in data.chunks(usize::from(control / 3) + 1) {
        let result = peer.handle_input(chunk);
        while let Some(action) = peer.poll_output() {
            if let ProtocolAction::Event(PeerEvent::Message(message)) = action {
                assert!(message.len() <= limits.max_message_frames);
                assert!(
                    message.iter().map(|frame| frame.len()).sum::<usize>()
                        <= limits.max_message_bytes
                );
            }
        }
        if let Err(error) = result {
            assert_eq!(peer.handle_input(&[]), Err(error.clone()));
            assert_eq!(peer.submit(&OutboundItem::Message(Vec::new())), Err(error));
            break;
        }
    }
});
