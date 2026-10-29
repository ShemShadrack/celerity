//! Messaging-pattern state machines built on top of peer events.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::marker::PhantomData;

use bytes::Bytes;

use crate::{Multipart, OutboundItem, PeerEvent, ProtocolError};

/// An action produced by a pattern core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternAction<PeerId> {
    /// Send an outbound item to a specific peer.
    Send {
        /// The target peer identifier.
        peer: PeerId,
        /// The outbound item to send.
        item: OutboundItem,
    },
    /// Deliver an inbound multipart message to the caller.
    Deliver {
        /// The peer that produced the message.
        peer: PeerId,
        /// The message body to surface to the caller.
        message: Multipart,
    },
}

/// Core state for PUB socket behavior.
#[derive(Debug, Clone)]
pub struct PubCore<PeerId> {
    subscriptions: HashMap<PeerId, HashMap<Bytes, usize>>,
}

impl<PeerId> Default for PubCore<PeerId> {
    fn default() -> Self {
        Self {
            subscriptions: HashMap::new(),
        }
    }
}

impl<PeerId> PubCore<PeerId>
where
    PeerId: Copy + Eq + Hash,
{
    #[must_use]
    /// Creates an empty PUB core.
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all subscription state associated with a peer.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.subscriptions.remove(&peer);
    }

    /// Updates subscription state from a peer event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownSubscription`] when a peer cancels a
    /// topic that is not currently tracked.
    pub fn on_peer_event(&mut self, peer: PeerId, event: PeerEvent) -> Result<(), ProtocolError> {
        match event {
            PeerEvent::Subscription { subscribe, topic } => {
                let peer_topics = self.subscriptions.entry(peer).or_default();
                if subscribe {
                    // SUB peers may repeat the same topic, so track a refcount.
                    *peer_topics.entry(topic).or_insert(0) += 1;
                } else {
                    decrement_topic(peer_topics, &topic)?;
                    if peer_topics.is_empty() {
                        self.subscriptions.remove(&peer);
                    }
                }
                Ok(())
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Message(_) => Ok(()),
        }
    }

    /// Produces outbound publish actions for matching subscribers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when `message` has no frames.
    pub fn publish(
        &self,
        message: &Multipart,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }

        let first_frame = &message[0];
        let mut out = Vec::new();
        for (peer, topics) in &self.subscriptions {
            // PUB/SUB matching is prefix-based on the first frame only.
            if topics
                .keys()
                .any(|topic| topic.is_empty() || first_frame.starts_with(topic))
            {
                out.push(PatternAction::Send {
                    peer: *peer,
                    item: OutboundItem::Message(message.clone()),
                });
            }
        }

        Ok(out)
    }
}

/// Core state for SUB socket behavior.
#[derive(Debug, Clone)]
pub struct SubCore<PeerId> {
    peers: Vec<PeerId>,
    subscriptions: HashMap<Bytes, usize>,
    filter_inbound: bool,
}

impl<PeerId> Default for SubCore<PeerId> {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            subscriptions: HashMap::new(),
            filter_inbound: true,
        }
    }
}

impl<PeerId> SubCore<PeerId>
where
    PeerId: Copy + Eq,
{
    #[must_use]
    /// Creates an empty SUB core.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Controls whether inbound messages are filtered against local subscriptions.
    pub fn with_filter_inbound(mut self, filter_inbound: bool) -> Self {
        self.filter_inbound = filter_inbound;
        self
    }

    /// Adds a peer and replays local subscriptions to it.
    pub fn add_peer(&mut self, peer: PeerId) -> Vec<PatternAction<PeerId>> {
        if self.peers.contains(&peer) {
            return Vec::new();
        }

        self.peers.push(peer);
        // New connections need the full local subscription set replayed to them.
        self.subscriptions
            .keys()
            .cloned()
            .map(|topic| PatternAction::Send {
                peer,
                item: OutboundItem::Subscribe(topic),
            })
            .collect()
    }

    /// Removes a peer from the active SUB peer set.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|candidate| *candidate != peer);
    }

    /// Registers a local subscription and fans it out to connected peers.
    ///
    /// # Errors
    ///
    /// This method currently does not return an error.
    pub fn subscribe(
        &mut self,
        topic: &Bytes,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        // Refcounts keep repeated subscribe calls balanced with cancel.
        *self.subscriptions.entry(topic.clone()).or_insert(0) += 1;
        Ok(self
            .peers
            .iter()
            .copied()
            .map(|peer| PatternAction::Send {
                peer,
                item: OutboundItem::Subscribe(topic.clone()),
            })
            .collect())
    }

    /// Removes a local subscription and fans the cancel out to connected peers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownSubscription`] when `topic` is not
    /// currently subscribed.
    pub fn cancel(&mut self, topic: &Bytes) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        decrement_topic(&mut self.subscriptions, topic)?;
        Ok(self
            .peers
            .iter()
            .copied()
            .map(|peer| PatternAction::Send {
                peer,
                item: OutboundItem::Cancel(topic.clone()),
            })
            .collect())
    }

    /// Handles inbound peer events for a SUB socket.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when an inbound message has no
    /// frames.
    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(message) => {
                if message.is_empty() {
                    return Err(ProtocolError::EmptyMessage);
                }

                // Local filtering mirrors SUB semantics when the remote side forwards everything.
                if self.filter_inbound
                    && !self
                        .subscriptions
                        .keys()
                        .any(|topic| topic.is_empty() || message[0].starts_with(topic))
                {
                    return Ok(Vec::new());
                }

                Ok(vec![PatternAction::Deliver { peer, message }])
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }
}

/// Core state for PUSH socket behavior.
#[derive(Debug, Clone)]
pub struct PushCore<PeerId> {
    // Empty means there is nowhere to send. Otherwise, the front peer gets the next message.
    peers: VecDeque<PeerId>,
}

impl<PeerId> Default for PushCore<PeerId> {
    fn default() -> Self {
        Self {
            peers: VecDeque::new(),
        }
    }
}

impl<PeerId> PushCore<PeerId>
where
    PeerId: Copy + Eq,
{
    #[must_use]
    /// Creates an empty PUSH core.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a peer to the round-robin send queue.
    pub fn add_peer(&mut self, peer: PeerId) {
        if !self.peers.contains(&peer) {
            self.peers.push_back(peer);
        }
    }

    /// Removes a peer from the send queue.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|candidate| *candidate != peer);
    }

    /// Sends a message to the next available pull peer.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when `message` has no frames or
    /// [`ProtocolError::NoAvailablePeers`] when no peers are connected.
    pub fn send(&mut self, message: Multipart) -> Result<PatternAction<PeerId>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }

        let peer = self
            .peers
            .pop_front()
            .ok_or(ProtocolError::NoAvailablePeers)?;
        self.peers.push_back(peer);

        Ok(PatternAction::Send {
            peer,
            item: OutboundItem::Message(message),
        })
    }
}

/// Core state for PULL socket behavior.
#[derive(Debug, Clone)]
pub struct PullCore<PeerId> {
    // PULL does not need pattern state; it only turns inbound peer events into deliveries.
    marker: PhantomData<PeerId>,
}

impl<PeerId> Default for PullCore<PeerId> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<PeerId> PullCore<PeerId>
where
    PeerId: Copy,
{
    #[must_use]
    /// Creates an empty PULL core.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles inbound peer events for a PULL socket.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when an inbound message has no
    /// frames.
    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(message) => {
                if message.is_empty() {
                    return Err(ProtocolError::EmptyMessage);
                }

                Ok(vec![PatternAction::Deliver { peer, message }])
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }
}

/// Core state for REQ socket behavior.
#[derive(Debug, Clone)]
pub struct ReqCore<PeerId> {
    peers: VecDeque<PeerId>,
    waiting_on: Option<PeerId>,
}

impl<PeerId> Default for ReqCore<PeerId> {
    fn default() -> Self {
        Self {
            peers: VecDeque::new(),
            waiting_on: None,
        }
    }
}

impl<PeerId> ReqCore<PeerId>
where
    PeerId: Copy + Eq,
{
    #[must_use]
    /// Creates an empty REQ core.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a peer to the round-robin request queue.
    pub fn add_peer(&mut self, peer: PeerId) {
        if !self.peers.contains(&peer) {
            self.peers.push_back(peer);
        }
    }

    /// Removes a peer from the request queue and clears any pending wait on it.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|candidate| *candidate != peer);
        if self.waiting_on == Some(peer) {
            self.waiting_on = None;
        }
    }

    /// Sends a request to the next available peer.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when `message` has no frames,
    /// [`ProtocolError::ReqStateViolation`] when a reply is still pending, or
    /// [`ProtocolError::NoAvailablePeers`] when no peers are connected.
    pub fn send(&mut self, message: Multipart) -> Result<PatternAction<PeerId>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }
        if self.waiting_on.is_some() {
            return Err(ProtocolError::ReqStateViolation(
                "cannot send a new request before receiving the reply",
            ));
        }

        let peer = self
            .peers
            .pop_front()
            .ok_or(ProtocolError::NoAvailablePeers)?;
        self.peers.push_back(peer);
        self.waiting_on = Some(peer);

        let mut wire_message = Vec::with_capacity(message.len() + 1);
        // REQ prefixes the body with the empty delimiter frame REP expects.
        wire_message.push(Bytes::new());
        wire_message.extend(message);

        Ok(PatternAction::Send {
            peer,
            item: OutboundItem::Message(wire_message),
        })
    }

    /// Handles replies arriving from peers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::MissingEnvelopeDelimiter`] when the reply does
    /// not begin with the required empty delimiter frame, or
    /// [`ProtocolError::MissingBodyFrames`] when the reply has no body frames.
    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(mut message) => {
                // Ignore stray replies from peers we are not currently waiting on.
                if self.waiting_on != Some(peer) {
                    return Ok(Vec::new());
                }
                if message.is_empty() || !message[0].is_empty() {
                    return Err(ProtocolError::MissingEnvelopeDelimiter);
                }

                message.remove(0);
                if message.is_empty() {
                    return Err(ProtocolError::MissingBodyFrames);
                }

                self.waiting_on = None;
                Ok(vec![PatternAction::Deliver { peer, message }])
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedRequest {
    envelope: Multipart,
    body: Multipart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveReply<PeerId> {
    peer: PeerId,
    envelope: Multipart,
}

/// Core state for REP socket behavior.
#[derive(Debug, Clone)]
pub struct RepCore<PeerId> {
    queues: HashMap<PeerId, VecDeque<QueuedRequest>>,
    ready_peers: VecDeque<PeerId>,
    active: Option<ActiveReply<PeerId>>,
}

impl<PeerId> Default for RepCore<PeerId> {
    fn default() -> Self {
        Self {
            queues: HashMap::new(),
            ready_peers: VecDeque::new(),
            active: None,
        }
    }
}

impl<PeerId> RepCore<PeerId>
where
    PeerId: Copy + Eq + Hash,
{
    #[must_use]
    /// Creates an empty REP core.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a peer with an empty inbound request queue.
    pub fn add_peer(&mut self, peer: PeerId) {
        self.queues.entry(peer).or_default();
    }

    /// Removes a peer and returns any action unblocked by that removal.
    ///
    /// # Errors
    ///
    /// This method currently does not return an error.
    pub fn remove_peer(
        &mut self,
        peer: PeerId,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        self.queues.remove(&peer);
        self.ready_peers.retain(|candidate| *candidate != peer);
        if self.active.as_ref().map(|active| active.peer) == Some(peer) {
            self.active = None;
            return Ok(self.dispatch_next());
        }
        Ok(Vec::new())
    }

    /// Queues an inbound request from a peer.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::MissingEnvelopeDelimiter`] when the request is
    /// missing the empty delimiter frame, or [`ProtocolError::MissingBodyFrames`]
    /// when the request has no body frames.
    pub fn on_peer_event(
        &mut self,
        peer: PeerId,
        event: PeerEvent,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        match event {
            PeerEvent::Message(message) => {
                let (envelope, body) = split_envelope(&message)?;
                // Keep each peer's requests ordered even when peers interleave.
                let queue = self.queues.entry(peer).or_default();
                let was_empty = queue.is_empty();
                queue.push_back(QueuedRequest { envelope, body });
                // A peer only enters the ready queue when it transitions from empty to non-empty.
                if was_empty && self.active.as_ref().map(|active| active.peer) != Some(peer) {
                    self.ready_peers.push_back(peer);
                }
                if self.active.is_none() {
                    return Ok(self.dispatch_next());
                }
                Ok(Vec::new())
            }
            PeerEvent::HandshakeComplete { .. } | PeerEvent::Subscription { .. } => Ok(Vec::new()),
        }
    }

    /// Sends a reply for the active request and dispatches the next ready one.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] when `message` has no frames, or
    /// [`ProtocolError::RepStateViolation`] when there is no active request to
    /// reply to.
    pub fn reply(
        &mut self,
        message: Multipart,
    ) -> Result<Vec<PatternAction<PeerId>>, ProtocolError> {
        if message.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }
        let Some(active) = self.active.take() else {
            return Err(ProtocolError::RepStateViolation(
                "cannot send a reply before receiving a request",
            ));
        };

        if self
            .queues
            .get(&active.peer)
            .is_some_and(|queue| !queue.is_empty())
        {
            self.ready_peers.push_back(active.peer);
        }

        let mut wire_message = active.envelope;
        wire_message.extend(message);

        let mut out = vec![PatternAction::Send {
            peer: active.peer,
            item: OutboundItem::Message(wire_message),
        }];
        out.extend(self.dispatch_next());
        Ok(out)
    }

    fn dispatch_next(&mut self) -> Vec<PatternAction<PeerId>> {
        while let Some(peer) = self.ready_peers.pop_front() {
            let Some(queue) = self.queues.get_mut(&peer) else {
                continue;
            };
            let Some(request) = queue.pop_front() else {
                continue;
            };

            self.active = Some(ActiveReply {
                peer,
                envelope: request.envelope,
            });

            // REP exposes one active request at a time until reply() consumes it.
            return vec![PatternAction::Deliver {
                peer,
                message: request.body,
            }];
        }

        Vec::new()
    }
}

fn decrement_topic(topics: &mut HashMap<Bytes, usize>, topic: &Bytes) -> Result<(), ProtocolError> {
    match topics.get_mut(topic) {
        Some(count) if *count > 1 => {
            *count -= 1;
            Ok(())
        }
        Some(_) => {
            topics.remove(topic);
            Ok(())
        }
        None => Err(ProtocolError::UnknownSubscription),
    }
}

fn split_envelope(message: &Multipart) -> Result<(Multipart, Multipart), ProtocolError> {
    let Some(delimiter_index) = message.iter().position(Bytes::is_empty) else {
        return Err(ProtocolError::MissingEnvelopeDelimiter);
    };

    let (envelope, body) = message.split_at(delimiter_index + 1);
    if body.is_empty() {
        return Err(ProtocolError::MissingBodyFrames);
    }

    Ok((envelope.to_vec(), body.to_vec()))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{PatternAction, PubCore, PullCore, PushCore, RepCore, ReqCore, SubCore};
    use crate::{OutboundItem, PeerEvent, ProtocolError};

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
    fn pubcore_tracks_additive_subscriptions() {
        let mut core = PubCore::<u8>::new();
        ok(core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::from_static(b"ab"),
            },
        ));
        ok(core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::from_static(b"ab"),
            },
        ));
        ok(core.on_peer_event(
            1,
            PeerEvent::Subscription {
                subscribe: false,
                topic: Bytes::from_static(b"ab"),
            },
        ));

        let actions = ok(core.publish(&vec![
            Bytes::from_static(b"abc"),
            Bytes::from_static(b"body"),
        ]));
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn pubcore_empty_subscription_matches_all() {
        let mut core = PubCore::<u8>::new();
        ok(core.on_peer_event(
            7,
            PeerEvent::Subscription {
                subscribe: true,
                topic: Bytes::new(),
            },
        ));

        let actions = ok(core.publish(&vec![Bytes::from_static(b"topic")]));
        assert_eq!(
            actions,
            vec![PatternAction::Send {
                peer: 7,
                item: OutboundItem::Message(vec![Bytes::from_static(b"topic")]),
            }]
        );
    }

    #[test]
    fn subcore_replays_subscriptions_to_new_peers() {
        let mut core = SubCore::<u8>::new();
        let _ = ok(core.subscribe(&Bytes::from_static(b"alpha")));
        let actions = core.add_peer(3);
        assert_eq!(
            actions,
            vec![PatternAction::Send {
                peer: 3,
                item: OutboundItem::Subscribe(Bytes::from_static(b"alpha")),
            }]
        );
    }

    #[test]
    fn subcore_filters_inbound_messages() {
        let mut core = SubCore::<u8>::new();
        core.add_peer(1);
        let _ = ok(core.subscribe(&Bytes::from_static(b"ab")));

        let allowed = core.on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"abc")]));
        let allowed = ok(allowed);
        assert_eq!(
            allowed,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"abc")],
            }]
        );

        let blocked = core.on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"zzz")]));
        let blocked = ok(blocked);
        assert_eq!(blocked, []);
    }

    #[test]
    fn subcore_can_disable_inbound_filtering() {
        let mut core = SubCore::<u8>::new().with_filter_inbound(false);

        let delivered = core.on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"zzz")]));
        let delivered = ok(delivered);
        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"zzz")],
            }]
        );
    }

    #[test]
    fn subcore_rejects_unknown_cancels() {
        let mut core = SubCore::<u8>::new();

        assert_eq!(
            err(core.cancel(&Bytes::from_static(b"alpha"))),
            ProtocolError::UnknownSubscription
        );
    }

    #[test]
    fn pushcore_rejects_messages_without_any_peers() {
        let mut core = PushCore::<u8>::new();

        assert_eq!(
            err(core.send(vec![Bytes::from_static(b"one")])),
            ProtocolError::NoAvailablePeers
        );
    }

    #[test]
    fn pushcore_rejects_empty_messages() {
        let mut core = PushCore::<u8>::new();
        core.add_peer(1);

        assert_eq!(err(core.send(Vec::new())), ProtocolError::EmptyMessage);
    }

    #[test]
    fn pushcore_round_robins_across_peers() {
        let mut core = PushCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = ok(core.send(vec![Bytes::from_static(b"one")]));
        let second = ok(core.send(vec![Bytes::from_static(b"two")]));

        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::from_static(b"one")]),
            }
        );
        assert_eq!(
            second,
            PatternAction::Send {
                peer: 2,
                item: OutboundItem::Message(vec![Bytes::from_static(b"two")]),
            }
        );
    }

    #[test]
    fn pushcore_ignores_duplicate_peers() {
        let mut core = PushCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(1);
        core.add_peer(2);

        let first = ok(core.send(vec![Bytes::from_static(b"one")]));
        let second = ok(core.send(vec![Bytes::from_static(b"two")]));

        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::from_static(b"one")]),
            }
        );
        assert_eq!(
            second,
            PatternAction::Send {
                peer: 2,
                item: OutboundItem::Message(vec![Bytes::from_static(b"two")]),
            }
        );
    }

    #[test]
    fn pushcore_removing_a_peer_keeps_the_queue_consistent() {
        let mut core = PushCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);
        core.remove_peer(1);

        let sent = ok(core.send(vec![Bytes::from_static(b"only")]));

        assert_eq!(
            sent,
            PatternAction::Send {
                peer: 2,
                item: OutboundItem::Message(vec![Bytes::from_static(b"only")]),
            }
        );
    }

    #[test]
    fn pullcore_delivers_inbound_messages() {
        let mut core = PullCore::<u8>::new();

        let delivered =
            ok(core.on_peer_event(4, PeerEvent::Message(vec![Bytes::from_static(b"payload")])));

        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 4,
                message: vec![Bytes::from_static(b"payload")],
            }]
        );
    }

    #[test]
    fn pullcore_rejects_empty_messages() {
        let mut core = PullCore::<u8>::new();

        assert_eq!(
            err(core.on_peer_event(4, PeerEvent::Message(Vec::new()))),
            ProtocolError::EmptyMessage
        );
    }

    #[test]
    fn pullcore_ignores_non_message_events() {
        let mut core = PullCore::<u8>::new();

        let actions = ok(core.on_peer_event(
            4,
            PeerEvent::HandshakeComplete {
                peer_socket_type: crate::SocketType::Push,
                metadata: crate::MetadataMap::new(),
            },
        ));
        assert_eq!(actions, []);
    }

    #[test]
    fn reqcore_inserts_delimiter_and_enforces_last_peer() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = ok(core.send(vec![Bytes::from_static(b"one")]));
        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
            }
        );

        let ignored = core.on_peer_event(
            2,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"wrong")]),
        );
        let ignored = ok(ignored);
        assert_eq!(ignored, []);

        let delivered = core.on_peer_event(
            1,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"reply")]),
        );
        let delivered = ok(delivered);
        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"reply")],
            }]
        );
    }

    #[test]
    fn reqcore_round_robins_requests() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = ok(core.send(vec![Bytes::from_static(b"one")]));
        let reply = core.on_peer_event(
            1,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"ok")]),
        );
        let _ = ok(reply);
        let second = ok(core.send(vec![Bytes::from_static(b"two")]));

        assert_eq!(
            first,
            PatternAction::Send {
                peer: 1,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
            }
        );
        assert_eq!(
            second,
            PatternAction::Send {
                peer: 2,
                item: OutboundItem::Message(vec![Bytes::new(), Bytes::from_static(b"two")]),
            }
        );
    }

    #[test]
    fn reqcore_rejects_strict_alternation_violations() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        let _ = ok(core.send(vec![Bytes::from_static(b"one")]));

        assert_eq!(
            err(core.send(vec![Bytes::from_static(b"two")])),
            ProtocolError::ReqStateViolation(
                "cannot send a new request before receiving the reply",
            )
        );
    }

    #[test]
    fn reqcore_rejects_requests_without_any_peers() {
        let mut core = ReqCore::<u8>::new();

        assert_eq!(
            err(core.send(vec![Bytes::from_static(b"one")])),
            ProtocolError::NoAvailablePeers
        );
    }

    #[test]
    fn reqcore_rejects_replies_without_a_delimiter_or_body() {
        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        let _ = ok(core.send(vec![Bytes::from_static(b"one")]));

        assert_eq!(
            err(core.on_peer_event(1, PeerEvent::Message(vec![Bytes::from_static(b"bad")]),)),
            ProtocolError::MissingEnvelopeDelimiter
        );

        let mut core = ReqCore::<u8>::new();
        core.add_peer(1);
        let _ = ok(core.send(vec![Bytes::from_static(b"one")]));
        assert_eq!(
            err(core.on_peer_event(1, PeerEvent::Message(vec![Bytes::new()]))),
            ProtocolError::MissingBodyFrames
        );
    }

    #[test]
    fn repcore_restores_envelope_on_reply() {
        let mut core = RepCore::<u8>::new();
        core.add_peer(9);

        let delivered = core.on_peer_event(
            9,
            PeerEvent::Message(vec![
                Bytes::from_static(b"route"),
                Bytes::new(),
                Bytes::from_static(b"body"),
            ]),
        );
        let delivered = ok(delivered);
        assert_eq!(
            delivered,
            vec![PatternAction::Deliver {
                peer: 9,
                message: vec![Bytes::from_static(b"body")],
            }]
        );

        let replied = ok(core.reply(vec![Bytes::from_static(b"ok")]));
        assert_eq!(
            replied,
            vec![PatternAction::Send {
                peer: 9,
                item: OutboundItem::Message(vec![
                    Bytes::from_static(b"route"),
                    Bytes::new(),
                    Bytes::from_static(b"ok"),
                ]),
            }]
        );
    }

    #[test]
    fn repcore_fair_queues_across_peers() {
        let mut core = RepCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = core.on_peer_event(
            1,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
        );
        let first = ok(first);
        assert_eq!(
            first,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"one")],
            }]
        );

        let none = core.on_peer_event(
            1,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"two")]),
        );
        let none = ok(none);
        assert_eq!(none, []);

        let none = core.on_peer_event(
            2,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"three")]),
        );
        let none = ok(none);
        assert_eq!(none, []);

        let after_reply = ok(core.reply(vec![Bytes::from_static(b"ok")]));
        assert_eq!(
            after_reply[1],
            PatternAction::Deliver {
                peer: 2,
                message: vec![Bytes::from_static(b"three")],
            }
        );
    }

    #[test]
    fn repcore_rejects_replies_without_an_active_request() {
        let mut core = RepCore::<u8>::new();

        assert_eq!(
            err(core.reply(vec![Bytes::from_static(b"ok")])),
            ProtocolError::RepStateViolation("cannot send a reply before receiving a request",)
        );
    }

    #[test]
    fn repcore_removing_the_active_peer_dispatches_the_next_waiter() {
        let mut core = RepCore::<u8>::new();
        core.add_peer(1);
        core.add_peer(2);

        let first = core.on_peer_event(
            1,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"one")]),
        );
        let first = ok(first);
        assert_eq!(
            first,
            vec![PatternAction::Deliver {
                peer: 1,
                message: vec![Bytes::from_static(b"one")],
            }]
        );

        let second = core.on_peer_event(
            2,
            PeerEvent::Message(vec![Bytes::new(), Bytes::from_static(b"two")]),
        );
        let second = ok(second);
        assert_eq!(second, []);

        let actions = ok(core.remove_peer(1));
        assert_eq!(
            actions,
            vec![PatternAction::Deliver {
                peer: 2,
                message: vec![Bytes::from_static(b"two")],
            }]
        );
    }
}
