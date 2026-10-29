//! Tokio task orchestration for a single peer connection.

use std::collections::VecDeque;
use std::future::{pending, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::{
    CelerityPeer, HwmConfig, HwmPolicy, LinkScope, OutboundItem, PeerConfig, PeerEvent,
    ProtocolAction, SecurityMechanism,
};

use super::transport::{AnyStream, connect_any_stream};
use super::{
    Endpoint, MAX_DRAIN_ACTIONS_PER_TURN, MAX_DRAIN_BYTES_PER_TURN, READ_BUFFER_CAPACITY,
    TokioCelerityError, TransportKind, TransportMeta, capacity_from_hwm,
};

const MAX_COMMANDS_PER_TURN: usize = 64;

#[derive(Debug, Clone)]
pub(crate) enum DriverStatus {
    CleanShutdown,
    Failed(String),
}

#[derive(Debug)]
pub(crate) enum RuntimeCommand {
    Submit(OutboundItem),
    SubmitSync(
        OutboundItem,
        oneshot::Sender<Result<(), TokioCelerityError>>,
    ),
    Flush(oneshot::Sender<Result<(), TokioCelerityError>>),
}

#[derive(Debug)]
struct QueuedOutbound {
    item: OutboundItem,
    bytes: usize,
}

#[derive(Debug)]
pub(crate) struct ConnectionHandle {
    pub(crate) command_tx: mpsc::Sender<RuntimeCommand>,
    pub(crate) terminal_rx: watch::Receiver<Option<DriverStatus>>,
}

#[derive(Debug, Clone, Copy)]
struct DrainState {
    handshake_completed: bool,
    has_more: bool,
}

/// A Tokio-driven connection wrapper around [`crate::CelerityPeer`].
#[derive(Debug)]
pub struct TokioCelerity {
    command_tx: mpsc::Sender<RuntimeCommand>,
    event_rx: mpsc::Receiver<PeerEvent>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
    terminal_rx: watch::Receiver<Option<DriverStatus>>,
}

impl TokioCelerity {
    /// Connects to an endpoint and spawns a Tokio task to drive the peer.
    ///
    /// # Errors
    ///
    /// Returns any endpoint parsing, transport, local-authorization, or
    /// protocol-validation error encountered before the task starts.
    pub async fn connect(endpoint: &str, config: PeerConfig) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let (stream, transport) = connect_any_stream(&endpoint, config.security.local_auth).await?;
        Self::from_stream(stream, transport, config)
    }

    /// Wraps an existing stream and starts the Tokio runtime driver for it.
    ///
    /// # Errors
    ///
    /// Returns transport-policy or protocol-validation errors detected before
    /// the background task is spawned.
    pub fn from_stream<S>(
        stream: S,
        transport: TransportMeta,
        config: PeerConfig,
    ) -> Result<Self, TokioCelerityError>
    where
        S: Into<AnyStream> + Send + 'static,
    {
        let config = apply_transport_policy(config, transport)?;
        config.validate_policy()?;
        let command_capacity = capacity_from_hwm(config.hwm.outbound_messages);
        let event_capacity = capacity_from_hwm(config.hwm.inbound_messages);
        let (command_tx, command_rx) = mpsc::channel(command_capacity);
        let (event_tx, event_rx) = mpsc::channel(event_capacity);
        let (terminal_tx, terminal_rx) = watch::channel(None);
        let stream = stream.into();

        let task = tokio::spawn(async move {
            let result = run_tokio_peer(stream, config, command_rx, event_tx).await;
            let status = match &result {
                Ok(()) => DriverStatus::CleanShutdown,
                Err(err) => DriverStatus::Failed(err.to_string()),
            };
            let _ = terminal_tx.send(Some(status));
            result
        });

        Ok(Self {
            command_tx,
            event_rx,
            task,
            terminal_rx,
        })
    }

    /// Submits an outbound item to the background runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the background task has already ended or if the
    /// runtime rejects the item while processing it.
    pub async fn send(&self, item: OutboundItem) -> Result<(), TokioCelerityError> {
        send_runtime_command_sync(&self.command_tx, &self.terminal_rx, item).await
    }

    /// Attempts to submit an outbound item without waiting for queue capacity.
    ///
    /// # Errors
    ///
    /// Returns [`TokioCelerityError::QueueFull`] when the command queue is
    /// full, or another runtime error if the background task has ended.
    pub async fn try_send(&self, item: OutboundItem) -> Result<(), TokioCelerityError> {
        try_send_runtime_command_sync(&self.command_tx, &self.terminal_rx, item).await
    }

    /// Waits for the next peer event from the background task.
    pub async fn recv(&mut self) -> Option<PeerEvent> {
        self.event_rx.recv().await
    }

    /// Waits for the background task to finish.
    ///
    /// # Errors
    ///
    /// Returns the terminal runtime error if the task failed.
    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ConnectionHandle,
        mpsc::Receiver<PeerEvent>,
        JoinHandle<Result<(), TokioCelerityError>>,
    ) {
        (
            ConnectionHandle {
                command_tx: self.command_tx,
                terminal_rx: self.terminal_rx,
            },
            self.event_rx,
            self.task,
        )
    }
}

async fn run_tokio_peer(
    mut stream: AnyStream,
    config: PeerConfig,
    mut command_rx: mpsc::Receiver<RuntimeCommand>,
    event_tx: mpsc::Sender<PeerEvent>,
) -> Result<(), TokioCelerityError> {
    let hwm = config.hwm;
    let handshake_deadline = curve_handshake_deadline(&config);
    let mut peer = CelerityPeer::new(config);
    let mut read_buf = BytesMut::with_capacity(READ_BUFFER_CAPACITY);
    let mut pending: VecDeque<QueuedOutbound> = VecDeque::new();
    let mut pending_bytes = 0_usize;
    let mut pending_flushes: Vec<oneshot::Sender<Result<(), TokioCelerityError>>> = Vec::new();
    // Application sends queue here until the handshake opens the traffic phase.
    let mut ready_for_traffic = false;
    let mut needs_drain = true;

    loop {
        tokio::select! {
            biased;

            () = wait_for_handshake_deadline(handshake_deadline), if !ready_for_traffic => {
                return Err(TokioCelerityError::HandshakeTimeout);
            }

            () = ready(()), if needs_drain => {
                // Drain protocol output before taking more input or new commands.
                needs_drain = false;
                let drain = pump_peer_actions(&mut peer, &mut stream, &event_tx, hwm).await?;
                if drain.handshake_completed {
                    ready_for_traffic = true;
                }

                if ready_for_traffic && !pending.is_empty() {
                    // Release everything queued once the peer reports handshake completion.
                    while let Some(queued) = pending.pop_front() {
                        pending_bytes = pending_bytes.saturating_sub(queued.bytes);
                        peer.submit(&queued.item)?;
                    }
                    needs_drain = true;
                } else if drain.has_more {
                    needs_drain = true;
                    tokio::task::yield_now().await;
                }

                if ready_for_traffic && pending.is_empty() && !needs_drain {
                    for ack in pending_flushes.drain(..) {
                        let _ = ack.send(Ok(()));
                    }
                }
            }

            read = stream.read_buf(&mut read_buf), if should_read(hwm, &read_buf) => {
                let count = read?;
                if count == 0 {
                    return Ok(());
                }

                let chunk = read_buf.split().freeze();
                peer.handle_input_bytes(chunk)?;
                needs_drain = true;
            }

            command = command_rx.recv(), if ready_for_traffic || can_take_command(hwm, pending.len(), pending_bytes) => {
                match command {
                    Some(command) => {
                        handle_runtime_command(
                            &mut peer,
                            hwm,
                            &mut pending,
                            &mut pending_bytes,
                            &mut pending_flushes,
                            ready_for_traffic,
                            &mut needs_drain,
                            command,
                        )?;

                        for _ in 1..MAX_COMMANDS_PER_TURN {
                            let Ok(command) = command_rx.try_recv() else {
                                break;
                            };

                            handle_runtime_command(
                                &mut peer,
                                hwm,
                                &mut pending,
                                &mut pending_bytes,
                                &mut pending_flushes,
                                ready_for_traffic,
                                &mut needs_drain,
                                command,
                            )?;
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

fn should_read(hwm: HwmConfig, read_buf: &BytesMut) -> bool {
    read_buf.len() < hwm.inbound_bytes.max(READ_BUFFER_CAPACITY)
}

fn queue_has_headroom(hwm: HwmConfig, pending_messages: usize, pending_bytes: usize) -> bool {
    pending_messages < capacity_from_hwm(hwm.outbound_messages)
        && pending_bytes < hwm.outbound_bytes.max(READ_BUFFER_CAPACITY)
}

fn can_take_command(hwm: HwmConfig, pending_messages: usize, pending_bytes: usize) -> bool {
    hwm.policy == HwmPolicy::DropNewest || queue_has_headroom(hwm, pending_messages, pending_bytes)
}

fn submit_runtime_item(
    peer: &mut CelerityPeer,
    hwm: HwmConfig,
    pending: &mut VecDeque<QueuedOutbound>,
    pending_bytes: &mut usize,
    ready_for_traffic: bool,
    needs_drain: &mut bool,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    if ready_for_traffic {
        peer.submit(&item)?;
        *needs_drain = true;
    } else if queue_has_headroom(hwm, pending.len(), *pending_bytes) {
        // Before READY, we queue locally instead of touching the peer state.
        let bytes = outbound_item_bytes(&item);
        *pending_bytes = pending_bytes.saturating_add(bytes);
        pending.push_back(QueuedOutbound { item, bytes });
    } else if hwm.policy != HwmPolicy::DropNewest {
        return Err(TokioCelerityError::QueueFull);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_runtime_command(
    peer: &mut CelerityPeer,
    hwm: HwmConfig,
    pending: &mut VecDeque<QueuedOutbound>,
    pending_bytes: &mut usize,
    pending_flushes: &mut Vec<oneshot::Sender<Result<(), TokioCelerityError>>>,
    ready_for_traffic: bool,
    needs_drain: &mut bool,
    command: RuntimeCommand,
) -> Result<(), TokioCelerityError> {
    match command {
        RuntimeCommand::Submit(item) => submit_runtime_item(
            peer,
            hwm,
            pending,
            pending_bytes,
            ready_for_traffic,
            needs_drain,
            item,
        ),
        RuntimeCommand::SubmitSync(item, ack) => {
            let result = submit_runtime_item(
                peer,
                hwm,
                pending,
                pending_bytes,
                ready_for_traffic,
                needs_drain,
                item,
            );
            let _ = ack.send(result);
            Ok(())
        }
        RuntimeCommand::Flush(ack) => {
            pending_flushes.push(ack);
            *needs_drain = true;
            Ok(())
        }
    }
}

async fn pump_peer_actions(
    peer: &mut CelerityPeer,
    stream: &mut AnyStream,
    event_tx: &mpsc::Sender<PeerEvent>,
    hwm: HwmConfig,
) -> Result<DrainState, TokioCelerityError> {
    let mut handshake_completed = false;
    // Batch consecutive writes so we do not await for every tiny frame.
    let mut writes = Vec::new();
    let mut actions = 0_usize;
    let mut written_bytes = 0_usize;
    let mut has_more = false;

    while actions < MAX_DRAIN_ACTIONS_PER_TURN && written_bytes < MAX_DRAIN_BYTES_PER_TURN {
        let Some(action) = peer.poll_output() else {
            break;
        };
        actions += 1;

        match action {
            ProtocolAction::Write(bytes) => {
                written_bytes = written_bytes.saturating_add(bytes.len());
                writes.push(bytes);
            }
            ProtocolAction::WriteVectored { header, body } => {
                written_bytes = written_bytes.saturating_add(header.len() + body.len());
                writes.push(header);
                writes.push(body);
            }
            ProtocolAction::Event(event) => {
                // Flush pending bytes before surfacing events across an await boundary.
                if !writes.is_empty() {
                    stream.write_all_vectored(&writes).await?;
                    writes.clear();
                }

                if matches!(event, PeerEvent::HandshakeComplete { .. }) {
                    handshake_completed = true;
                }
                forward_peer_event(event_tx, event, hwm).await?;
            }
        }
    }

    if !writes.is_empty() {
        stream.write_all_vectored(&writes).await?;
    }

    if actions == MAX_DRAIN_ACTIONS_PER_TURN || written_bytes >= MAX_DRAIN_BYTES_PER_TURN {
        has_more = true;
    }

    Ok(DrainState {
        handshake_completed,
        has_more,
    })
}

async fn forward_peer_event(
    event_tx: &mpsc::Sender<PeerEvent>,
    event: PeerEvent,
    hwm: HwmConfig,
) -> Result<(), TokioCelerityError> {
    // Only message events are droppable; control flow events must always get through.
    if hwm.policy == HwmPolicy::DropNewest && matches!(event, PeerEvent::Message(_)) {
        return match event_tx.try_send(event) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(TokioCelerityError::ChannelClosed("peer event channel"))
            }
        };
    }

    event_tx
        .send(event)
        .await
        .map_err(|_| TokioCelerityError::ChannelClosed("peer event channel"))
}

fn curve_handshake_deadline(config: &PeerConfig) -> Option<Instant> {
    if config.security.mechanism != SecurityMechanism::Curve {
        return None;
    }

    let timeout_ms = config.security.curve.as_ref()?.handshake_timeout_ms;
    if timeout_ms == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms))
    }
}

async fn wait_for_handshake_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

pub(crate) async fn send_runtime_command(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    validate_runtime_item(&item)?;
    command_tx
        .send(RuntimeCommand::Submit(item))
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;
    Ok(())
}

pub(crate) async fn send_runtime_command_sync(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    validate_runtime_item(&item)?;
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .send(RuntimeCommand::SubmitSync(item, reply_tx))
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;

    reply_rx
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?
}

pub(crate) async fn try_send_runtime_command_sync(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    validate_runtime_item(&item)?;
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .try_send(RuntimeCommand::SubmitSync(item, reply_tx))
        .map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => TokioCelerityError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => terminal_error(terminal_rx.borrow().as_ref()),
        })?;

    reply_rx
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?
}

pub(crate) async fn flush_runtime_command(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
) -> Result<(), TokioCelerityError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .send(RuntimeCommand::Flush(reply_tx))
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;

    reply_rx
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?
}

fn validate_runtime_item(item: &OutboundItem) -> Result<(), TokioCelerityError> {
    if matches!(item, OutboundItem::Message(message) if message.is_empty()) {
        return Err(crate::ProtocolError::EmptyMessage.into());
    }

    Ok(())
}

fn terminal_error(status: Option<&DriverStatus>) -> TokioCelerityError {
    match status {
        Some(DriverStatus::CleanShutdown) => TokioCelerityError::BackgroundTaskEnded,
        Some(DriverStatus::Failed(message)) => {
            TokioCelerityError::BackgroundTaskFailed(message.clone())
        }
        None => TokioCelerityError::ChannelClosed("connection task"),
    }
}

fn apply_transport_policy(
    mut config: PeerConfig,
    transport: TransportMeta,
) -> Result<PeerConfig, TokioCelerityError> {
    config.link_scope = transport.link_scope;

    if config.security.mechanism == SecurityMechanism::Null {
        match transport.kind {
            TransportKind::Tcp => {
                if transport.link_scope == LinkScope::Local
                    && !config.security.policy.allow_null_loopback
                    && !config.security.allow_insecure_null
                {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "tcp".to_owned(),
                        reason: "NULL is disabled on loopback TCP by policy".to_owned(),
                    });
                }
            }
            TransportKind::Ipc => {
                // IPC NULL can be gated both by policy and filesystem checks.
                if !config.security.policy.allow_null_ipc && !config.security.allow_insecure_null {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "ipc".to_owned(),
                        reason: "NULL is disabled on IPC by policy".to_owned(),
                    });
                }
                if config.security.local_auth == crate::LocalAuthPolicy::FilesystemStrict
                    && !transport.null_authorized
                {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "ipc".to_owned(),
                        reason:
                            "filesystem ownership or permissions are too loose for strict NULL IPC"
                                .to_owned(),
                    });
                }
            }
        }
    }

    Ok(config)
}

fn outbound_item_bytes(item: &OutboundItem) -> usize {
    match item {
        OutboundItem::Message(message) => message.iter().map(Bytes::len).sum(),
        OutboundItem::Subscribe(topic) | OutboundItem::Cancel(topic) => topic.len(),
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, task::Poll, time::Duration};

    use bytes::Bytes;
    use tokio::sync::{mpsc, watch};

    use crate::{
        HwmConfig, HwmPolicy, LinkScope, LocalAuthPolicy, OutboundItem, PeerConfig, PeerEvent,
        SecurityConfig, SecurityMechanism, SecurityPolicy, SecurityRole, SocketType,
    };

    use super::{
        DriverStatus, READ_BUFFER_CAPACITY, RuntimeCommand, TransportKind, TransportMeta,
        apply_transport_policy, can_take_command, curve_handshake_deadline, forward_peer_event,
        queue_has_headroom, send_runtime_command_sync, terminal_error,
    };
    use crate::io::TokioCelerityError;

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

    #[tokio::test]
    async fn cancelled_send_does_not_leave_a_command_in_the_queue() {
        let (tx, mut rx) = mpsc::channel(1);
        let (_status_tx, status_rx) = watch::channel(None);
        let item = OutboundItem::Message(vec![Bytes::from_static(b"queued")]);
        ok(tx.send(RuntimeCommand::Submit(item.clone())).await);
        {
            let send = send_runtime_command_sync(&tx, &status_rx, item.clone());
            tokio::pin!(send);
            let state = std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await;
            assert!(state.is_pending());
        }
        assert!(matches!(rx.recv().await, Some(RuntimeCommand::Submit(_))));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let send = send_runtime_command_sync(&tx, &status_rx, item);
        tokio::pin!(send);
        let state = std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await;
        assert!(state.is_pending());
        let Some(RuntimeCommand::SubmitSync(_, ack)) = rx.recv().await else {
            panic!("missing send command");
        };
        ok(ack.send(Ok(())));
        ok(send.await);
    }

    #[tokio::test]
    async fn disconnect_releases_a_send_waiting_for_acknowledgement() {
        let (tx, rx) = mpsc::channel(1);
        let (status_tx, status_rx) = watch::channel(None);
        let send =
            send_runtime_command_sync(&tx, &status_rx, OutboundItem::Message(vec![Bytes::new()]));
        tokio::pin!(send);
        let state = std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await;
        assert!(state.is_pending());
        ok(status_tx.send(Some(DriverStatus::CleanShutdown)));
        drop(rx);
        assert!(matches!(
            ok(tokio::time::timeout(Duration::from_secs(1), send).await),
            Err(TokioCelerityError::BackgroundTaskEnded)
        ));
    }

    #[tokio::test]
    async fn slow_receivers_apply_backpressure_and_closed_receivers_release_it() {
        let (tx, rx) = mpsc::channel(1);
        let event = PeerEvent::Message(vec![Bytes::new()]);
        ok(tx.send(event.clone()).await);
        let forward = forward_peer_event(&tx, event, HwmConfig::default());
        tokio::pin!(forward);
        let state = std::future::poll_fn(|cx| Poll::Ready(forward.as_mut().poll(cx))).await;
        assert!(state.is_pending());
        drop(rx);
        assert!(matches!(
            ok(tokio::time::timeout(Duration::from_secs(1), forward).await),
            Err(TokioCelerityError::ChannelClosed("peer event channel"))
        ));
    }

    #[test]
    fn curve_handshake_deadline_depends_on_mechanism_and_timeout() {
        let null_config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local);
        assert!(curve_handshake_deadline(&null_config).is_none());

        let curve = crate::CurveConfig {
            handshake_timeout_ms: 0,
            ..crate::CurveConfig::default()
        };
        let curve_config =
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(curve));
        assert!(curve_handshake_deadline(&curve_config).is_none());

        let curve_config =
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve());
        assert!(curve_handshake_deadline(&curve_config).is_some());
    }

    #[test]
    fn queue_helpers_respect_policy_and_capacity() {
        let mut hwm = HwmConfig {
            outbound_messages: 1,
            outbound_bytes: 1,
            ..HwmConfig::default()
        };

        assert!(queue_has_headroom(hwm, 0, 0));
        assert!(!queue_has_headroom(hwm, 1, 0));
        assert!(!queue_has_headroom(hwm, 0, READ_BUFFER_CAPACITY));
        assert!(!can_take_command(hwm, 1, READ_BUFFER_CAPACITY));

        hwm.policy = HwmPolicy::DropNewest;
        assert!(can_take_command(hwm, 1, READ_BUFFER_CAPACITY));
    }

    #[test]
    fn terminal_error_maps_driver_status() {
        assert!(matches!(
            terminal_error(None),
            TokioCelerityError::ChannelClosed("connection task")
        ));
        assert!(matches!(
            terminal_error(Some(&DriverStatus::CleanShutdown)),
            TokioCelerityError::BackgroundTaskEnded
        ));
        assert_eq!(
            terminal_error(Some(&DriverStatus::Failed("boom".to_owned()))).to_string(),
            "background task failed: boom"
        );
    }

    #[test]
    fn apply_transport_policy_rejects_disallowed_loopback_null() {
        let policy = SecurityPolicy {
            allow_null_loopback: false,
            allow_null_ipc: true,
            require_curve_non_local: true,
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::new(SecurityMechanism::Null).with_policy(policy));

        let result = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Tcp,
                link_scope: LinkScope::Local,
                null_authorized: true,
            },
        );
        let err = err(result);
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_rejects_ipc_null_when_policy_disabled() {
        let policy = SecurityPolicy {
            allow_null_loopback: true,
            allow_null_ipc: false,
            require_curve_non_local: true,
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::new(SecurityMechanism::Null).with_policy(policy));

        let result = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: true,
            },
        );
        let err = err(result);
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_rejects_strict_ipc_without_authorization() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::null());
        let result = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: false,
            },
        );
        let err = err(result);
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_allows_relaxed_ipc_null() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(
                SecurityConfig::null().with_local_auth_policy(LocalAuthPolicy::FilesystemRelaxed),
            );

        let applied = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: false,
            },
        );
        let applied = ok(applied);
        assert_eq!(applied.link_scope, LinkScope::Local);
    }
}
