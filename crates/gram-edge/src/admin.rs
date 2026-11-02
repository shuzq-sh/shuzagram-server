//! `gram-admin`: HTTP Control Plane & Real-Time RPC Sniffer on port 8080.
//!
//! Exposes a rich Web Dashboard, REST telemetry APIs, and Server-Sent Events (SSE)
//! for real-time MTProto RPC sniffing and cluster operations.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use gram_core::egress::SnifferFilter;
use gram_core::messaging::{encode_tl_message, encode_tl_updates, encode_tl_user, encode_update_new_message};
use gram_core::{SessionHub, Store};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub(crate) fn check_basic_auth(auth_header: Option<&str>) -> bool {
    let expected_user = std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let expected_pass = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string());

    let Some(header) = auth_header else {
        return false;
    };
    if !header.starts_with("Basic ") {
        return false;
    }
    let b64 = header["Basic ".len()..].trim();
    let Some(decoded_bytes) = base64_decode(b64) else {
        return false;
    };
    let Ok(credentials) = std::str::from_utf8(&decoded_bytes) else {
        return false;
    };
    let mut parts = credentials.splitn(2, ':');
    let user = parts.next().unwrap_or("");
    let pass = parts.next().unwrap_or("");
    user == expected_user && pass == expected_pass
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

pub async fn serve_admin_listener(
    listener: TcpListener,
    store: Arc<Store>,
    hub: Arc<SessionHub>,
) -> Result<(), std::io::Error> {
    START_TIME.get_or_init(Instant::now);
    loop {
        let (stream, _) = listener.accept().await?;
        let s = Arc::clone(&store);
        let h = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = handle_admin_client(stream, s, h).await;
        });
    }
}

async fn handle_admin_client(
    mut stream: TcpStream,
    store: Arc<Store>,
    hub: Arc<SessionHub>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = BytesMut::with_capacity(8192);
    let mut temp = [0u8; 4096];

    let (body_offset, content_length) = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&temp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(hdr_len)) = req.parse(&buf) {
            let mut cl = 0;
            for h in req.headers.iter() {
                if h.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        cl = s.trim().parse::<usize>().unwrap_or(0);
                    }
                }
            }
            break (hdr_len, cl);
        }
    };

    while buf.len() < body_offset + content_length {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(&buf);

    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");

    let mut auth_header = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("authorization") {
            if let Ok(s) = std::str::from_utf8(h.value) {
                auth_header = Some(s.trim().to_string());
            }
        }
    }

    if method != "OPTIONS" && !check_basic_auth(auth_header.as_deref()) {
        let resp = "HTTP/1.1 401 Unauthorized\r\n\
                    WWW-Authenticate: Basic realm=\"ShuzaGram Control Plane\"\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 31\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Headers: *\r\n\
                    Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                    \r\n\
                    {\"error\":\"Unauthorized access\"}";
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    let body_bytes = if buf.len() >= body_offset {
        &buf[body_offset..body_offset + content_length.min(buf.len() - body_offset)]
    } else {
        &[]
    };

    if path == "/api/sniffer/events" {
        return handle_sniffer_sse(stream, hub).await;
    }

    let (status, content_type, body_data) =
        handle_admin_route(method, path, body_bytes, &store, &hub).await;

    let http_response = format!(
        "HTTP/1.1 {status} OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         \r\n",
        body_data.len()
    );

    stream.write_all(http_response.as_bytes()).await?;
    stream.write_all(&body_data).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_sniffer_sse(
    mut stream: TcpStream,
    hub: Arc<SessionHub>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Automatically enable sniffer sampling for connected operators
    hub.configure_sniffer(
        true,
        SnifferFilter {
            sample_rate_per_myriad: 10_000, // 100%
            ..Default::default()
        },
    );

    let mut rx = hub.subscribe_sniffer();

    let sse_headers = "HTTP/1.1 200 OK\r\n\
                       Content-Type: text/event-stream\r\n\
                       Cache-Control: no-cache\r\n\
                       Connection: keep-alive\r\n\
                       Access-Control-Allow-Origin: *\r\n\
                       \r\n";
    stream.write_all(sse_headers.as_bytes()).await?;

    // Send initial keepalive
    stream.write_all(b": ping\n\n").await?;

    while let Ok(event) = rx.recv().await {
        let payload = json!({
            "trace_id": event.trace_id,
            "timestamp": event.timestamp_micros,
            "dc_id": event.dc_id,
            "user_id": event.user_id,
            "auth_key_id": format!("{:#018x}", event.auth_key_id),
            "layer": event.client_layer,
            "constructor_id": format!("{:#010x}", event.constructor_id),
            "method": event.method_name,
            "duration_us": event.duration_micros,
            "error_code": event.rpc_error_code,
            "error_message": event.rpc_error_message
        });
        let msg = format!("data: {}\n\n", serde_json::to_string(&payload)?);
        if stream.write_all(msg.as_bytes()).await.is_err() {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn handle_admin_route(
    method: &str,
    path: &str,
    body: &[u8],
    store: &Store,
    hub: &SessionHub,
) -> (u16, &'static str, Vec<u8>) {
    if method == "OPTIONS" {
        return (200, "application/json", b"{\"ok\":true}".to_vec());
    }

    match path {
        "/" | "/index.html" => {
            (200, "text/html; charset=utf-8", DASHBOARD_HTML.as_bytes().to_vec())
        }
        "/api/health" => {
            let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
            let active_conns = hub.active_connection_count();
            let total_rpcs = hub.total_rpcs();
            let res = json!({
                "status": "ok",
                "uptime_seconds": uptime,
                "active_connections": active_conns,
                "total_rpcs": total_rpcs,
                "dc_id": 2,
                "sniffer_active": hub.sniffer_enabled()
            });
            (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
        }
        "/api/sessions" => {
            let sessions = hub.snapshot_sessions(None);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let list: Vec<Value> = sessions.into_iter().map(|s| {
                json!({
                    "conn_id": s.conn_id,
                    "peer_addr": s.peer_addr,
                    "auth_key_id": format!("{:#018x}", s.auth_key_id),
                    "perm_auth_key_id": format!("{:#018x}", s.perm_auth_key_id),
                    "user_id": s.user_id,
                    "layer": s.negotiated_layer,
                    "device_model": s.device_model,
                    "app_version": s.app_version,
                    "is_push_socket": s.is_push_socket,
                    "connected_sec_ago": (now - s.connected_at_unix).max(0),
                    "last_active_sec_ago": (now - s.last_active_unix).max(0)
                })
            }).collect();
            (200, "application/json", serde_json::to_vec(&list).unwrap_or_default())
        }
        "/api/sessions/disconnect" if method == "POST" => {
            let val: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let auth_key_id = val.get("auth_key_id")
                .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| i64::from_str_radix(s.trim_start_matches("0x"), 16).ok())))
                .unwrap_or(0);
            let count = hub.force_disconnect_auth_key(auth_key_id);
            let res = json!({ "ok": true, "disconnected_count": count });
            (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
        }
        "/api/users" => {
            let users = store.acid().search_users("", 200);
            let list: Vec<Value> = users.into_iter().map(|u| {
                let wallet = store.acid().get_stars_wallet(u.user_id);
                json!({
                    "id": u.user_id,
                    "phone": u.phone,
                    "username": u.username,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "stars_balance": wallet.balance_units,
                    "pts": u.pts,
                    "qts": u.qts,
                    "online": hub.is_user_online(u.user_id)
                })
            }).collect();
            (200, "application/json", serde_json::to_vec(&list).unwrap_or_default())
        }
        "/api/economy/catalog" => {
            let catalog = store.acid().list_gift_catalog();
            let list: Vec<Value> = catalog.into_iter().map(|g| {
                json!({
                    "gift_id": g.gift_id,
                    "title": g.title,
                    "slug_prefix": g.slug_prefix,
                    "price_stars": g.star_price_units,
                    "upgrade_stars": g.upgrade_price_units,
                    "convert_stars": g.convert_units,
                    "total_supply": g.total_supply,
                    "minted_count": g.minted_count,
                    "is_limited": g.is_limited,
                    "is_upgradeable": g.is_upgradeable
                })
            }).collect();
            (200, "application/json", serde_json::to_vec(&list).unwrap_or_default())
        }
        "/api/economy/adjust-stars" if method == "POST" => {
            let val: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let user_id = val.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);
            let delta = val.get("delta").and_then(|v| v.as_i64()).unwrap_or(0);
            let title = val.get("title").and_then(|v| v.as_str()).unwrap_or("Admin Adjustment");

            let idemp = format!("admin_adj_{user_id}_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros());
            match store.acid().adjust_stars(&idemp, user_id, None, "admin_grant", delta, title) {
                Ok(w) => {
                    let res = json!({ "ok": true, "user_id": user_id, "new_balance": w.balance_units });
                    (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
                Err(e) => {
                    let res = json!({ "ok": false, "error": e.to_string() });
                    (400, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
            }
        }
        "/api/notifications/send" if method == "POST" => {
            let val: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let text = val.get("text").and_then(|v| v.as_str()).unwrap_or("").trim();
            let broadcast = val.get("broadcast").and_then(|v| v.as_bool()).unwrap_or(false);
            let target_user_id = val.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);

            if text.is_empty() {
                let res = json!({ "ok": false, "description": "Message text cannot be empty" });
                return (400, "application/json", serde_json::to_vec(&res).unwrap_or_default());
            }

            let service_user = store.user_by_id(777000).unwrap_or_else(|| {
                store.get_or_create_user("777000", Some("Telegram"), Some(""))
            });

            let targets: Vec<i64> = if broadcast {
                store.acid().search_users("", 10000).into_iter()
                    .map(|u| u.user_id)
                    .filter(|&id| id >= 1000 && id != 777000)
                    .collect()
            } else if target_user_id > 0 {
                vec![target_user_id]
            } else {
                Vec::new()
            };

            if targets.is_empty() {
                let res = json!({ "ok": false, "description": "No valid recipient user specified" });
                return (400, "application/json", serde_json::to_vec(&res).unwrap_or_default());
            }

            let mut delivered = 0;
            for &uid in &targets {
                let random_id = rand::random::<i64>().abs().max(1);
                if let Ok(outcome) = store.acid().send_direct_message(
                    777000, uid, random_id, text, None, None, None, None
                ) {
                    if let Some((recip_msg, recip_pts)) = outcome.recipient_msg {
                        let recip_msg_tl = encode_tl_message(&recip_msg, false);
                        let upd = encode_update_new_message(&recip_msg_tl, recip_pts);
                        let srv_tl = encode_tl_user(&service_user, Some(uid), false, false, true);
                        let push = encode_tl_updates(&[upd], &[srv_tl], &[]);
                        hub.push_to_user(uid, None, push);
                    }
                    delivered += 1;
                }
            }

            let res = json!({
                "ok": true,
                "delivered_count": delivered,
                "total_targets": targets.len()
            });
            (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
        }
        "/api/alerts/config" if method == "GET" => {
            let cfg = crate::alerts::AlertConfig::load(store);
            (200, "application/json", serde_json::to_vec(&cfg).unwrap_or_default())
        }
        "/api/alerts/config" if method == "POST" => {
            if let Ok(cfg) = serde_json::from_slice::<crate::alerts::AlertConfig>(body) {
                cfg.save(store);
                (200, "application/json", b"{\"ok\":true}".to_vec())
            } else {
                (400, "application/json", b"{\"ok\":false,\"description\":\"Invalid JSON payload\"}".to_vec())
            }
        }
        "/api/alerts/test-telegram" if method == "POST" => {
            let val: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let token = val.get("token").and_then(|v| v.as_str()).unwrap_or("");
            let chat_id = val.get("chat_id").and_then(|v| v.as_str()).unwrap_or("");
            match crate::alerts::test_telegram_alert(token, chat_id).await {
                Ok(msg) => {
                    let res = json!({ "ok": true, "message": msg });
                    (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
                Err(err) => {
                    let res = json!({ "ok": false, "error": err });
                    (400, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
            }
        }
        "/api/alerts/test-email" if method == "POST" => {
            let val: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let url = val.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let to = val.get("to").and_then(|v| v.as_str()).unwrap_or("");
            match crate::alerts::test_email_alert(url, to).await {
                Ok(msg) => {
                    let res = json!({ "ok": true, "message": msg });
                    (200, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
                Err(err) => {
                    let res = json!({ "ok": false, "error": err });
                    (400, "application/json", serde_json::to_vec(&res).unwrap_or_default())
                }
            }
        }
        _ => (404, "application/json", b"{\"ok\":false,\"error\":\"Not Found\"}".to_vec()),
    }
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ShuzaGram Control Plane & Node Monitor</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; }
    .tab-active { border-bottom: 2px solid #38bdf8; color: #38bdf8; }
    .badge-ok { background: #065f46; color: #34d399; }
    .badge-err { background: #991b1b; color: #f87171; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
      <div>
        <h1 class="text-2xl font-bold flex items-center gap-3">
          <span class="inline-block w-3 h-3 bg-emerald-400 rounded-full animate-ping"></span>
          ShuzaGram MTProto Control Plane
        </h1>
        <p class="text-sm text-slate-400 mt-1">DC-2 Cluster Gateway &bull; Live Telemetry &bull; Port 8443 / 8080 / 8081</p>
      </div>
      <div class="flex gap-8 text-right">
        <div>
          <div class="text-xs text-slate-400 uppercase tracking-wider">Uptime</div>
          <div id="stat-uptime" class="text-xl font-mono font-semibold">0s</div>
        </div>
        <div>
          <div class="text-xs text-slate-400 uppercase tracking-wider">Active Sockets</div>
          <div id="stat-conns" class="text-xl font-mono font-semibold text-sky-400">0</div>
        </div>
        <div>
          <div class="text-xs text-slate-400 uppercase tracking-wider">Total RPCs</div>
          <div id="stat-rpcs" class="text-xl font-mono font-semibold text-emerald-400">0</div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="flex border-b border-slate-700 gap-6 text-sm font-medium">
      <button onclick="setTab('sniffer')" id="tab-sniffer" class="pb-3 tab-active cursor-pointer">Live RPC Sniffer</button>
      <button onclick="setTab('sessions')" id="tab-sessions" class="pb-3 text-slate-400 hover:text-slate-200 cursor-pointer">Active Sessions</button>
      <button onclick="setTab('users')" id="tab-users" class="pb-3 text-slate-400 hover:text-slate-200 cursor-pointer">Users & Stars</button>
      <button onclick="setTab('gifts')" id="tab-gifts" class="pb-3 text-slate-400 hover:text-slate-200 cursor-pointer">Star Gifts Catalog</button>
      <button onclick="setTab('notif')" id="tab-notif" class="pb-3 text-slate-400 hover:text-slate-200 cursor-pointer">📢 System Notifications</button>
      <button onclick="setTab('alerts')" id="tab-alerts" class="pb-3 text-slate-400 hover:text-slate-200 cursor-pointer">🔔 Webhooks & Alerts</button>
    </div>

    <!-- Tab 1: Live RPC Sniffer -->
    <div id="view-sniffer" class="space-y-4">
      <div class="flex justify-between items-center bg-slate-800/60 p-4 rounded-lg border border-slate-700">
        <div class="flex gap-4 items-center">
          <button id="btn-pause" onclick="togglePause()" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-sm font-semibold">Pause Stream</button>
          <label class="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" id="chk-errors" onchange="applyFilter()" class="rounded bg-slate-700"> Errors Only
          </label>
        </div>
        <div class="text-xs text-slate-400">Streaming real-time decrypted MTProto calls via SSE</div>
      </div>
      <div class="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow">
        <div class="max-h-[550px] overflow-y-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-800/80 sticky top-0 text-slate-300">
              <tr>
                <th class="p-3">Time</th>
                <th class="p-3">User ID</th>
                <th class="p-3">Layer</th>
                <th class="p-3">Method Name</th>
                <th class="p-3">Duration</th>
                <th class="p-3">Status</th>
              </tr>
            </thead>
            <tbody id="sniffer-rows" class="divide-y divide-slate-800/60">
              <tr><td colspan="6" class="p-4 text-center text-slate-500">Waiting for incoming MTProto calls...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab 2: Active Sessions -->
    <div id="view-sessions" class="hidden bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <table class="w-full text-left text-xs font-mono">
        <thead class="bg-slate-800 text-slate-300">
          <tr>
            <th class="p-3">Conn ID</th>
            <th class="p-3">Remote Address</th>
            <th class="p-3">User ID</th>
            <th class="p-3">Layer</th>
            <th class="p-3">Device / Client</th>
            <th class="p-3">Last Active</th>
            <th class="p-3">Action</th>
          </tr>
        </thead>
        <tbody id="session-rows" class="divide-y divide-slate-800"></tbody>
      </table>
    </div>

    <!-- Tab 3: Users -->
    <div id="view-users" class="hidden bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <table class="w-full text-left text-xs font-mono">
        <thead class="bg-slate-800 text-slate-300">
          <tr>
            <th class="p-3">ID</th>
            <th class="p-3">Phone</th>
            <th class="p-3">Name</th>
            <th class="p-3">Username</th>
            <th class="p-3">Stars Balance</th>
            <th class="p-3">Online Status</th>
          </tr>
        </thead>
        <tbody id="user-rows" class="divide-y divide-slate-800"></tbody>
      </table>
    </div>

    <!-- Tab 4: Star Gifts Catalog -->
    <div id="view-gifts" class="hidden space-y-6">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6" id="gift-cards"></div>
      <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 class="text-lg font-bold mb-4">Grant / Adjust Telegram Stars</h3>
        <div class="flex gap-4">
          <input id="adj-user" type="number" placeholder="User ID" class="bg-slate-900 border border-slate-700 px-3 py-2 rounded text-sm">
          <input id="adj-delta" type="number" placeholder="Amount (e.g. 500)" class="bg-slate-900 border border-slate-700 px-3 py-2 rounded text-sm">
          <input id="adj-title" type="text" placeholder="Reason (e.g. Grant)" class="bg-slate-900 border border-slate-700 px-3 py-2 rounded text-sm flex-1">
          <button onclick="submitStars()" class="bg-emerald-600 hover:bg-emerald-500 px-6 py-2 rounded text-sm font-semibold cursor-pointer">Submit</button>
        </div>
      </div>
    </div>

    <!-- Tab 5: System Notifications (777000) -->
    <div id="view-notif" class="hidden space-y-6">
      <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl max-w-2xl">
        <h2 class="text-lg font-bold mb-2 flex items-center gap-2">
          <span class="text-sky-400">📢</span>
          <span>Официальные системные уведомления (Telegram 777000)</span>
        </h2>
        <p class="text-xs text-slate-400 mb-6">
          Отправляет верифицированное системное push-уведомление от служебного аккаунта 777000. В клиентах отображается в официальном диалоге с синей галочкой.
        </p>

        <div class="space-y-4">
          <div>
            <label class="block text-xs uppercase text-slate-400 font-semibold mb-2">Адресат</label>
            <div class="flex gap-6 text-sm">
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="radio" name="notif_mode" value="broadcast" checked onchange="toggleNotifUser(false)" class="text-sky-500">
                <span>Всем зарегистрированным пользователям (Broadcast)</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="radio" name="notif_mode" value="single" onchange="toggleNotifUser(true)" class="text-sky-500">
                <span>Одному пользователю</span>
              </label>
            </div>
          </div>

          <div id="notif-user-container" class="hidden">
            <label class="block text-xs uppercase text-slate-400 font-semibold mb-1">User ID</label>
            <input id="notif-uid" type="number" placeholder="например 1002" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-slate-200 font-mono">
          </div>

          <div>
            <label class="block text-xs uppercase text-slate-400 font-semibold mb-1">Текст уведомления</label>
            <textarea id="notif-text" rows="4" placeholder="Введите текст системного уведомления..." class="w-full bg-slate-900 border border-slate-700 rounded p-3 text-sm text-slate-200"></textarea>
          </div>

          <div class="flex items-center justify-between pt-2">
            <button onclick="sendSystemNotification()" class="px-5 py-2.5 bg-sky-600 hover:bg-sky-500 text-white rounded font-semibold text-sm transition cursor-pointer">
              🚀 Отправить уведомление
            </button>
            <span id="notif-status" class="text-xs text-slate-400 font-mono"></span>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 6: Webhooks & Alerts -->
    <div id="view-alerts" class="hidden space-y-6">
      <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl max-w-3xl space-y-6">
        <div>
          <h2 class="text-lg font-bold flex items-center gap-2">
            <span class="text-amber-400">🔔</span>
            <span>Настройка вебхуков и внешних уведомлений</span>
          </h2>
          <p class="text-xs text-slate-400 mt-1">
            Перенаправление системных алертов, регистраций и событий авторизации в бота Telegram, на Email и через Custom Webhooks.
          </p>
        </div>

        <!-- Telegram Directed Bot -->
        <div class="bg-slate-900/80 p-5 rounded-lg border border-slate-700/80 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-sky-400 flex items-center gap-2">
              <span>✈️ Направленный вебхук в Telegram Бота</span>
            </h3>
            <button onclick="testTelegramAlert()" class="px-3 py-1 bg-sky-600 hover:bg-sky-500 text-xs font-semibold rounded cursor-pointer">Проверить отправку</button>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Telegram Bot Token</label>
              <input id="alert-tg-token" type="password" placeholder="123456789:ABCDef..." class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-200 font-mono">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Target Chat ID (группа/канал/личка)</label>
              <input id="alert-tg-chat" type="text" placeholder="-100123456789" class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-200 font-mono">
            </div>
          </div>
          <div id="tg-test-res" class="text-xs font-mono"></div>
        </div>

        <!-- Email Webhook / Relay -->
        <div class="bg-slate-900/80 p-5 rounded-lg border border-slate-700/80 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-emerald-400 flex items-center gap-2">
              <span>✉️ Уведомления по почте (Email Webhook / Relay)</span>
            </h3>
            <button onclick="testEmailAlert()" class="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold rounded cursor-pointer">Проверить отправку</button>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Email получателя</label>
              <input id="alert-email-to" type="email" placeholder="admin@example.com" class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-200">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Email Webhook URL (SendGrid / Mailgun / Postmark / Bridge)</label>
              <input id="alert-email-url" type="url" placeholder="https://api.your-email-bridge.com/send" class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-200 font-mono">
            </div>
          </div>
          <div id="email-test-res" class="text-xs font-mono"></div>
        </div>

        <!-- Custom Generic Webhook -->
        <div class="bg-slate-900/80 p-5 rounded-lg border border-slate-700/80 space-y-3">
          <h3 class="text-sm font-bold text-purple-400">🌐 Универсальный Custom Webhook URL</h3>
          <input id="alert-custom-url" type="url" placeholder="https://hooks.yourdomain.com/shuzagram-events" class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono">
        </div>

        <!-- Event Selection -->
        <div class="space-y-2 text-xs">
          <span class="block text-slate-400 font-semibold uppercase">События для триггера:</span>
          <div class="grid grid-cols-2 gap-2 text-slate-300">
            <label class="flex items-center gap-2"><input id="ev-login" type="checkbox" checked class="rounded"> Вход и регистрация пользователей</label>
            <label class="flex items-center gap-2"><input id="ev-code" type="checkbox" checked class="rounded"> Отправка SMS-кодов авторизации</label>
            <label class="flex items-center gap-2"><input id="ev-stars" type="checkbox" checked class="rounded"> Покупка Stars и NFT-подарков</label>
            <label class="flex items-center gap-2"><input id="ev-support" type="checkbox" checked class="rounded"> Системные алерты и поддержка</label>
          </div>
        </div>

        <div class="pt-2 flex items-center justify-between border-t border-slate-700">
          <button onclick="saveAlertConfig()" class="px-5 py-2.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-semibold text-sm transition cursor-pointer">
            💾 Сохранить настройки вебхуков
          </button>
          <span id="alert-save-status" class="text-xs text-slate-400 font-mono"></span>
        </div>
      </div>
    </div>
  </div>

  <script>
    let isPaused = false;
    let snifferRows = [];

    function setTab(name) {
      ['sniffer', 'sessions', 'users', 'gifts', 'notif', 'alerts'].forEach(t => {
        document.getElementById('view-' + t).classList.toggle('hidden', t !== name);
        document.getElementById('tab-' + t).classList.toggle('tab-active', t === name);
        document.getElementById('tab-' + t).classList.toggle('text-slate-400', t !== name);
      });
      if (name === 'sessions') loadSessions();
      if (name === 'users') loadUsers();
      if (name === 'gifts') loadGifts();
      if (name === 'alerts') loadAlertConfig();
    }

    function togglePause() {
      isPaused = !isPaused;
      document.getElementById('btn-pause').textContent = isPaused ? 'Resume Stream' : 'Pause Stream';
    }

    // Connect Server-Sent Events (SSE)
    const evtSource = new EventSource('/api/sniffer/events');
    evtSource.onmessage = function(e) {
      if (isPaused) return;
      const data = JSON.parse(e.data);
      snifferRows.unshift(data);
      if (snifferRows.length > 200) snifferRows.pop();
      renderSniffer();
    };

    function renderSniffer() {
      const errOnly = document.getElementById('chk-errors').checked;
      const tbody = document.getElementById('sniffer-rows');
      const filtered = snifferRows.filter(r => !errOnly || r.error_code !== 0);
      if (filtered.length === 0) return;

      tbody.innerHTML = filtered.slice(0, 50).map(r => {
        const time = new Date(r.timestamp / 1000).toLocaleTimeString();
        const isOk = r.error_code === 0;
        return `<tr>
          <td class="p-3 text-slate-400">${time}</td>
          <td class="p-3 text-sky-400">${r.user_id ? r.user_id : '<span class="text-slate-600">anon</span>'}</td>
          <td class="p-3 text-slate-400">L${r.layer}</td>
          <td class="p-3 font-semibold text-slate-200">${r.method}</td>
          <td class="p-3 text-slate-400">${(r.duration_us / 1000).toFixed(2)}ms</td>
          <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${isOk ? 'badge-ok' : 'badge-err'}">${isOk ? 'OK' : r.error_message || r.error_code}</span></td>
        </tr>`;
      }).join('');
    }

    async function loadHealth() {
      try {
        const r = await fetch('/api/health');
        const d = await r.json();
        document.getElementById('stat-uptime').textContent = d.uptime_seconds + 's';
        document.getElementById('stat-conns').textContent = d.active_connections;
        document.getElementById('stat-rpcs').textContent = d.total_rpcs;
      } catch (e) {}
    }
    setInterval(loadHealth, 2000);
    loadHealth();

    async function loadSessions() {
      const r = await fetch('/api/sessions');
      const list = await r.json();
      document.getElementById('session-rows').innerHTML = list.map(s => `<tr>
        <td class="p-3">${s.conn_id}</td>
        <td class="p-3 text-sky-400">${s.peer_addr}</td>
        <td class="p-3">${s.user_id || '-'}</td>
        <td class="p-3">L${s.layer}</td>
        <td class="p-3">${s.device_model || 'Unknown'} / ${s.app_version || '1.0'}</td>
        <td class="p-3">${s.last_active_sec_ago}s ago</td>
        <td class="p-3"><button onclick="disconnect('${s.auth_key_id}')" class="text-rose-400 hover:text-rose-300">Drop</button></td>
      </tr>`).join('');
    }

    async function loadUsers() {
      const r = await fetch('/api/users');
      const list = await r.json();
      document.getElementById('user-rows').innerHTML = list.map(u => `<tr>
        <td class="p-3 font-bold">${u.id}</td>
        <td class="p-3 text-sky-400">${u.phone}</td>
        <td class="p-3">${u.first_name} ${u.last_name || ''}</td>
        <td class="p-3 text-slate-400">@${u.username || '-'}</td>
        <td class="p-3 text-amber-400 font-bold">${u.stars_balance} ⭐️</td>
        <td class="p-3"><span class="${u.online ? 'text-emerald-400' : 'text-slate-500'}">${u.online ? '● Online' : '○ Offline'}</span></td>
      </tr>`).join('');
    }

    async function loadGifts() {
      const r = await fetch('/api/economy/catalog');
      const list = await r.json();
      document.getElementById('gift-cards').innerHTML = list.map(g => `<div class="bg-slate-800 p-5 rounded-xl border border-slate-700 space-y-2">
        <div class="flex justify-between items-start">
          <h4 class="font-bold text-lg">${g.title}</h4>
          <span class="text-amber-400 font-bold">${g.price_stars} ⭐️</span>
        </div>
        <div class="text-xs text-slate-400">Slug: ${g.slug_prefix} &bull; Minted: ${g.minted_count} / ${g.total_supply || '∞'}</div>
        <div class="text-xs text-slate-300">Upgrade: ${g.upgrade_stars} ⭐️ &bull; Convert: ${g.convert_stars} ⭐️</div>
      </div>`).join('');
    }

    async function disconnect(authKey) {
      await fetch('/api/sessions/disconnect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ auth_key_id: authKey })
      });
      loadSessions();
    }

    async function submitStars() {
      const uid = parseInt(document.getElementById('adj-user').value);
      const delta = parseInt(document.getElementById('adj-delta').value);
      const title = document.getElementById('adj-title').value;
      if (!uid || !delta) return alert('Fill User ID and delta');
      await fetch('/api/economy/adjust-stars', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ user_id: uid, delta: delta, title: title })
      });
      alert('Stars balance adjusted!');
      loadUsers();
    }

    function toggleNotifUser(isSingle) {
      document.getElementById('notif-user-container').classList.toggle('hidden', !isSingle);
    }

    async function sendSystemNotification() {
      const isSingle = document.querySelector('input[name="notif_mode"]:checked').value === 'single';
      const text = document.getElementById('notif-text').value.trim();
      const statusEl = document.getElementById('notif-status');
      if (!text) {
        alert('Пожалуйста, введите текст сообщения');
        return;
      }
      let uid = 0;
      if (isSingle) {
        uid = parseInt(document.getElementById('notif-uid').value);
        if (!uid) {
          alert('Укажите корректный User ID');
          return;
        }
      }
      statusEl.textContent = 'Отправка...';
      try {
        const res = await fetch('/api/notifications/send', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            broadcast: !isSingle,
            user_id: uid,
            text: text
          })
        });
        const data = await res.json();
        if (data.ok) {
          statusEl.textContent = `Успешно доставлено: ${data.delivered_count} получателям`;
          document.getElementById('notif-text').value = '';
        } else {
          statusEl.textContent = `Ошибка: ${data.description || 'Не удалось отправить'}`;
        }
      } catch (e) {
        statusEl.textContent = 'Ошибка сети: ' + e;
      }
    }

    async function loadAlertConfig() {
      try {
        const r = await fetch('/api/alerts/config');
        const cfg = await r.json();
        document.getElementById('alert-tg-token').value = cfg.telegram_bot_token || '';
        document.getElementById('alert-tg-chat').value = cfg.telegram_chat_id || '';
        document.getElementById('alert-email-to').value = cfg.email_recipient || '';
        document.getElementById('alert-email-url').value = cfg.email_webhook_url || '';
        document.getElementById('alert-custom-url').value = cfg.custom_webhook_url || '';
        document.getElementById('ev-login').checked = cfg.notify_on_login !== false;
        document.getElementById('ev-code').checked = cfg.notify_on_code !== false;
        document.getElementById('ev-stars').checked = cfg.notify_on_stars !== false;
        document.getElementById('ev-support').checked = cfg.notify_on_support !== false;
      } catch (e) {}
    }

    async function saveAlertConfig() {
      const cfg = {
        telegram_bot_token: document.getElementById('alert-tg-token').value.trim(),
        telegram_chat_id: document.getElementById('alert-tg-chat').value.trim(),
        email_recipient: document.getElementById('alert-email-to').value.trim(),
        email_webhook_url: document.getElementById('alert-email-url').value.trim(),
        custom_webhook_url: document.getElementById('alert-custom-url').value.trim(),
        notify_on_login: document.getElementById('ev-login').checked,
        notify_on_code: document.getElementById('ev-code').checked,
        notify_on_stars: document.getElementById('ev-stars').checked,
        notify_on_support: document.getElementById('ev-support').checked,
      };
      const statusEl = document.getElementById('alert-save-status');
      statusEl.textContent = 'Сохранение...';
      try {
        const r = await fetch('/api/alerts/config', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(cfg)
        });
        const res = await r.json();
        if (res.ok) {
          statusEl.textContent = '✅ Настройки успешно сохранены!';
        } else {
          statusEl.textContent = '❌ Ошибка сохранения';
        }
      } catch (e) {
        statusEl.textContent = 'Ошибка: ' + e;
      }
    }

    async function testTelegramAlert() {
      const token = document.getElementById('alert-tg-token').value.trim();
      const chatId = document.getElementById('alert-tg-chat').value.trim();
      const resEl = document.getElementById('tg-test-res');
      resEl.textContent = 'Отправка в Telegram...';
      try {
        const r = await fetch('/api/alerts/test-telegram', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ token: token, chat_id: chatId })
        });
        const res = await r.json();
        if (res.ok) {
          resEl.innerHTML = '<span class="text-emerald-400">✅ ' + res.message + '</span>';
        } else {
          resEl.innerHTML = '<span class="text-rose-400">❌ ' + (res.error || 'Ошибка') + '</span>';
        }
      } catch (e) {
        resEl.innerHTML = '<span class="text-rose-400">❌ Ошибка сети: ' + e + '</span>';
      }
    }

    async function testEmailAlert() {
      const url = document.getElementById('alert-email-url').value.trim();
      const to = document.getElementById('alert-email-to').value.trim();
      const resEl = document.getElementById('email-test-res');
      resEl.textContent = 'Отправка на Email Webhook...';
      try {
        const r = await fetch('/api/alerts/test-email', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ url: url, to: to })
        });
        const res = await r.json();
        if (res.ok) {
          resEl.innerHTML = '<span class="text-emerald-400">✅ ' + res.message + '</span>';
        } else {
          resEl.innerHTML = '<span class="text-rose-400">❌ ' + (res.error || 'Ошибка') + '</span>';
        }
      } catch (e) {
        resEl.innerHTML = '<span class="text-rose-400">❌ Ошибка сети: ' + e + '</span>';
      }
    }
  </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admin_endpoints_work() {
        let store = Arc::new(Store::with_test_code(Some("12345".to_string())));
        let hub = Arc::new(SessionHub::new());

        // Test root dashboard
        let (status, ctype, body) = handle_admin_route("GET", "/", &[], &store, &hub).await;
        assert_eq!(status, 200);
        assert_eq!(ctype, "text/html; charset=utf-8");
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("ShuzaGram Control Plane"));

        // Test health check
        let (status, ctype, body) = handle_admin_route("GET", "/api/health", &[], &store, &hub).await;
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["status"], "ok");

        // Test economy catalog
        let (status, _, body) = handle_admin_route("GET", "/api/economy/catalog", &[], &store, &hub).await;
        assert_eq!(status, 200);
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert!(res.as_array().unwrap().len() >= 3);

        // Test users list and adjust-stars
        let user = store.get_or_create_user("+12025550100", Some("Bob"), None);
        let adj_body = json!({
            "user_id": user.id,
            "delta": 250,
            "title": "Admin Bonus"
        });
        let (status, _, body) = handle_admin_route(
            "POST",
            "/api/economy/adjust-stars",
            &serde_json::to_vec(&adj_body).unwrap(),
            &store,
            &hub,
        ).await;
        assert_eq!(status, 200);
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["ok"], true);
        assert_eq!(res["new_balance"], 250);

        let (status, _, body) = handle_admin_route("GET", "/api/users", &[], &store, &hub).await;
        assert_eq!(status, 200);
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert!(!res.as_array().unwrap().is_empty());

        // Test system notifications
        let notif_body = json!({
            "user_id": user.id,
            "broadcast": false,
            "text": "Тестовое системное уведомление"
        });
        let (status, _, body) = handle_admin_route(
            "POST",
            "/api/notifications/send",
            &serde_json::to_vec(&notif_body).unwrap(),
            &store,
            &hub,
        ).await;
        assert_eq!(status, 200);
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["ok"], true);
        assert_eq!(res["delivered_count"], 1);

        // Test basic auth helper
        assert!(check_basic_auth(Some("Basic YWRtaW46YWRtaW4="))); // admin:admin
        assert!(!check_basic_auth(Some("Basic d3Jvbmc6cGFzcw==")));
        assert!(!check_basic_auth(None));

        // Test alert config save & load
        let alert_body = json!({
            "telegram_bot_token": "12345:TOKEN",
            "telegram_chat_id": "-100111222333",
            "email_recipient": "ops@example.com",
            "email_webhook_url": "https://example.com/email-hook",
            "custom_webhook_url": "https://example.com/custom-hook",
            "notify_on_login": true,
            "notify_on_code": true,
            "notify_on_stars": true,
            "notify_on_support": true
        });
        let (status, _, _body) = handle_admin_route(
            "POST",
            "/api/alerts/config",
            &serde_json::to_vec(&alert_body).unwrap(),
            &store,
            &hub,
        ).await;
        assert_eq!(status, 200);

        let (status, _, body) = handle_admin_route("GET", "/api/alerts/config", &[], &store, &hub).await;
        assert_eq!(status, 200);
        let res: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["email_recipient"], "ops@example.com");
    }
}
