//! `gram-egress`: Concurrent `SessionHub` for real-time MTProto `Updates` push,
//! live `ForceDisconnectAuthKey` control, `updateConfig` cluster broadcasts,
//! and zero-overhead `AtomicBool`-guarded live RPC sniffer telemetry.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc};

use crate::dispatch::{Outbound, OutboundKind};

#[derive(Debug, Clone)]
pub enum EgressCommand {
    Send(Outbound),
    ForceDisconnect,
}

#[derive(Debug, Clone)]
pub struct LiveSessionInfo {
    pub conn_id: u64,
    pub dc_id: i32,
    pub peer_addr: String,
    pub auth_key_id: i64,
    pub perm_auth_key_id: i64,
    pub session_id: i64,
    pub user_id: Option<i64>,
    pub negotiated_layer: u16,
    pub device_model: String,
    pub app_version: String,
    pub is_push_socket: bool,
    pub connected_at_unix: i64,
    pub last_active_unix: i64,
}

struct SessionEntry {
    info: LiveSessionInfo,
    tx: mpsc::UnboundedSender<EgressCommand>,
}

/// Decoded RPC trace sample emitted only when `sniffer_active == true`.
#[derive(Debug, Clone)]
pub struct RpcTraceEvent {
    pub trace_id: u64,
    pub timestamp_micros: i64,
    pub dc_id: i32,
    pub user_id: i64,
    pub auth_key_id: i64,
    pub client_layer: u16,
    pub constructor_id: u32,
    pub method_name: String,
    pub duration_micros: u32,
    pub rpc_error_code: i32,
    pub rpc_error_message: String,
}

#[derive(Debug, Clone, Default)]
pub struct SnifferFilter {
    pub sample_rate_per_myriad: u32, // 0..=10000 (10000 = 100%)
    pub filter_user_id: i64,         // 0 = any
    pub filter_dc_id: i32,           // 0 = any
    pub filter_constructor_id: u32,  // 0 = any
    pub errors_only: bool,
}

/// Concurrent real-time egress router & telemetry hub shared between `gram-edge`,
/// `gram-core`, and `gram-admin`.
pub struct SessionHub {
    next_conn_id: AtomicU64,
    next_trace_id: AtomicU64,
    total_rpcs: AtomicU64,
    sessions: RwLock<HashMap<u64, SessionEntry>>,
    sniffer_active: AtomicBool,
    sniffer_filter: RwLock<SnifferFilter>,
    sniffer_tx: broadcast::Sender<RpcTraceEvent>,
}

impl Default for SessionHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionHub {
    pub fn new() -> Self {
        let (sniffer_tx, _) = broadcast::channel(1024);
        Self {
            next_conn_id: AtomicU64::new(1),
            next_trace_id: AtomicU64::new(1),
            total_rpcs: AtomicU64::new(0),
            sessions: RwLock::new(HashMap::new()),
            sniffer_active: AtomicBool::new(false),
            sniffer_filter: RwLock::new(SnifferFilter {
                sample_rate_per_myriad: 10_000,
                ..Default::default()
            }),
            sniffer_tx,
        }
    }

    /// Register a newly accepted TCP or WebSocket connection and return its
    /// `(conn_id, receiver)`.
    pub fn register_connection(
        &self,
        peer_addr: String,
        dc_id: i32,
    ) -> (u64, mpsc::UnboundedReceiver<EgressCommand>) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let now = now_unix_i64();
        let (tx, rx) = mpsc::unbounded_channel();
        let entry = SessionEntry {
            info: LiveSessionInfo {
                conn_id,
                dc_id,
                peer_addr,
                auth_key_id: 0,
                perm_auth_key_id: 0,
                session_id: 0,
                user_id: None,
                negotiated_layer: 232,
                device_model: String::new(),
                app_version: String::new(),
                is_push_socket: false,
                connected_at_unix: now,
                last_active_unix: now,
            },
            tx,
        };
        self.sessions.write().unwrap().insert(conn_id, entry);
        (conn_id, rx)
    }

    /// Remove a connection on socket close.
    pub fn unregister_connection(&self, conn_id: u64) {
        self.sessions.write().unwrap().remove(&conn_id);
    }

    /// Update live session metadata after decrypting a message or completing login.
    #[allow(clippy::too_many_arguments)]
    pub fn update_session(
        &self,
        conn_id: u64,
        auth_key_id: i64,
        perm_auth_key_id: i64,
        session_id: i64,
        user_id: Option<i64>,
        negotiated_layer: u16,
        is_push_socket: bool,
        device_model: Option<&str>,
        app_version: Option<&str>,
    ) {
        if conn_id == 0 {
            return;
        }
        let now = now_unix_i64();
        if let Some(entry) = self.sessions.write().unwrap().get_mut(&conn_id) {
            entry.info.auth_key_id = auth_key_id;
            entry.info.perm_auth_key_id = perm_auth_key_id;
            entry.info.session_id = session_id;
            if user_id.is_some() {
                entry.info.user_id = user_id;
            }
            if negotiated_layer > 0 {
                entry.info.negotiated_layer = negotiated_layer;
            }
            if is_push_socket {
                entry.info.is_push_socket = true;
            }
            if let Some(dm) = device_model {
                if !dm.is_empty() && entry.info.device_model != dm {
                    entry.info.device_model = dm.to_string();
                }
            }
            if let Some(av) = app_version {
                if !av.is_empty() && entry.info.app_version != av {
                    entry.info.app_version = av.to_string();
                }
            }
            entry.info.last_active_unix = now;
        }
    }

    /// Push a serialized `Updates` frame to all active sessions of `user_id`
    /// (optionally skipping `exclude_conn_id`, e.g. the sender's own RPC socket
    /// that already received `updateShortSentMessage`).
    pub fn push_to_user(&self, user_id: i64, exclude_conn_id: Option<u64>, body: Vec<u8>) -> usize {
        let map = self.sessions.read().unwrap();
        let mut delivered = 0usize;
        let mut seen_sessions: HashSet<(i64, i64)> = HashSet::new();

        // First pass: prefer push sockets or main generic sockets with non-zero session_id
        for (&cid, entry) in map.iter() {
            if Some(cid) == exclude_conn_id || entry.info.user_id != Some(user_id) {
                continue;
            }
            let dedup_key = (entry.info.perm_auth_key_id, entry.info.session_id);
            if dedup_key.0 != 0 && dedup_key.1 != 0 && !seen_sessions.insert(dedup_key) {
                continue;
            }
            if entry
                .tx
                .send(EgressCommand::Send(Outbound {
                    kind: OutboundKind::Content,
                    body: body.clone(),
                }))
                .is_ok()
            {
                delivered += 1;
            }
        }
        delivered
    }

    /// Broadcast an outbound update (e.g., `updateConfig`) to all encrypted sessions.
    pub fn broadcast_all(&self, body: Vec<u8>) -> usize {
        let map = self.sessions.read().unwrap();
        let mut delivered = 0usize;
        for entry in map.values() {
            if entry.info.auth_key_id != 0
                && entry
                    .tx
                    .send(EgressCommand::Send(Outbound {
                        kind: OutboundKind::Content,
                        body: body.clone(),
                    }))
                    .is_ok()
            {
                delivered += 1;
            }
        }
        delivered
    }

    /// Force-disconnect all live sockets using `auth_key_id` (either temp or perm).
    pub fn force_disconnect_auth_key(&self, auth_key_id: i64) -> usize {
        let map = self.sessions.read().unwrap();
        let mut count = 0usize;
        for entry in map.values() {
            if entry.info.auth_key_id == auth_key_id || entry.info.perm_auth_key_id == auth_key_id {
                let _ = entry.tx.send(EgressCommand::ForceDisconnect);
                count += 1;
            }
        }
        count
    }

    pub fn active_connection_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    pub fn snapshot_sessions(&self, filter_user_id: Option<i64>) -> Vec<LiveSessionInfo> {
        let map = self.sessions.read().unwrap();
        map.values()
            .filter(|e| filter_user_id.is_none_or(|uid| e.info.user_id == Some(uid)))
            .map(|e| e.info.clone())
            .collect()
    }

    pub fn is_user_online(&self, user_id: i64) -> bool {
        let now = now_unix_i64();
        let map = self.sessions.read().unwrap();
        map.values()
            .any(|e| e.info.user_id == Some(user_id) && now - e.info.last_active_unix <= 120)
    }

    #[inline(always)]
    pub fn sniffer_enabled(&self) -> bool {
        self.sniffer_active.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn bump_rpc_counter(&self) -> u64 {
        self.total_rpcs.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn total_rpcs(&self) -> u64 {
        self.total_rpcs.load(Ordering::Relaxed)
    }

    pub fn configure_sniffer(&self, active: bool, filter: SnifferFilter) {
        *self.sniffer_filter.write().unwrap() = filter;
        self.sniffer_active.store(active, Ordering::Release);
    }

    pub fn subscribe_sniffer(&self) -> broadcast::Receiver<RpcTraceEvent> {
        self.sniffer_tx.subscribe()
    }

    /// Emit a non-blocking RPC trace sample if `sniffer_active` is enabled and
    /// `filter` matches. Never blocks or allocates when disabled!
    #[allow(clippy::too_many_arguments)]
    pub fn record_rpc_trace(
        &self,
        dc_id: i32,
        user_id: i64,
        auth_key_id: i64,
        client_layer: u16,
        constructor_id: u32,
        method_name: &str,
        duration_micros: u32,
        rpc_error_code: i32,
        rpc_error_message: &str,
    ) {
        if !self.sniffer_enabled() {
            return;
        }
        let filter = self.sniffer_filter.read().unwrap().clone();
        if filter.errors_only && rpc_error_code == 0 {
            return;
        }
        if filter.filter_user_id != 0 && filter.filter_user_id != user_id {
            return;
        }
        if filter.filter_dc_id != 0 && filter.filter_dc_id != dc_id {
            return;
        }
        if filter.filter_constructor_id != 0 && filter.filter_constructor_id != constructor_id {
            return;
        }
        let trace_id = self.next_trace_id.fetch_add(1, Ordering::Relaxed);
        if filter.sample_rate_per_myriad < 10_000
            && (trace_id % 10_000) >= (filter.sample_rate_per_myriad as u64)
        {
            return;
        }
        let ts_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        let _ = self.sniffer_tx.send(RpcTraceEvent {
            trace_id,
            timestamp_micros: ts_micros,
            dc_id,
            user_id,
            auth_key_id,
            client_layer,
            constructor_id,
            method_name: method_name.to_string(),
            duration_micros,
            rpc_error_code,
            rpc_error_message: rpc_error_message.to_string(),
        });
    }
}

fn now_unix_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
