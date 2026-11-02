//! RPC envelope unwrapping, MTProto service replies, PFS `bindTempAuthKey`,
//! and Layer-232 auth / startup request routing.

use std::io::Read as _;
use std::sync::Arc;
use std::time::Instant;

use flate2::read::GzDecoder;
use mtproto_crypto::dh;
use mtproto_crypto::kdf::{self, Direction};
use rand::RngCore;
use tl_compiler::LayerAdapterRegistry;
use tl_core::{Reader, TlError, Writer};

use crate::egress::SessionHub;
use crate::keystore::KeyStore;
use crate::store::{Store, User};

// --- MTProto service & envelope constructors --------------------------------
const MSG_CONTAINER: u32 = 0x73f1_f8dc;
const GZIP_PACKED: u32 = 0x3072_cfa1;
const MAX_GZIP_UNPACKED_LEN: usize = 4 * 1024 * 1024;
const INVOKE_WITH_LAYER: u32 = 0xda9b_0d0d;
const INIT_CONNECTION: u32 = 0xc1cd_5ea9;
const INVOKE_AFTER_MSG: u32 = 0xcb9f_372d;
const INVOKE_AFTER_MSGS: u32 = 0x3dc4_b4f0;
const INVOKE_WITHOUT_UPDATES: u32 = 0xbf94_59b7;
const INVOKE_WITH_MESSAGES_RANGE: u32 = 0x3652_75f2;
const INVOKE_WITH_TAKEOUT: u32 = 0xaca9_fd2e;
const INVOKE_WITH_BUSINESS_CONNECTION: u32 = 0xdd28_9f8e;
const INVOKE_WITH_GOOGLE_PLAY_INTEGRITY: u32 = 0x1df9_2984;
const INVOKE_WITH_APNS_SECRET: u32 = 0x0dae_54f8;
const INVOKE_WITH_RECAPTCHA: u32 = 0xadbb_0f94;

const INPUT_CLIENT_PROXY: u32 = 0x7558_8b3f;
const JSON_NULL: u32 = 0x3f6d_7b68;
const JSON_BOOL: u32 = 0xc734_5e6a;
const JSON_NUMBER: u32 = 0x2be0_dfa4;
const JSON_STRING: u32 = 0xb71e_767a;
const JSON_ARRAY: u32 = 0xf744_4763;
const JSON_OBJECT: u32 = 0x99c1_d49d;
const JSON_OBJECT_VALUE: u32 = 0xc0de_1bd9;

const PING: u32 = 0x7abe_77ec;
const PING_DELAY_DISCONNECT: u32 = 0xf342_7b8c;
const PONG: u32 = 0x3477_73c5;
const GET_FUTURE_SALTS: u32 = 0xb921_bd04;
const FUTURE_SALTS: u32 = 0xae50_0895;
const DESTROY_SESSION: u32 = 0xe751_2126;
const DESTROY_SESSION_OK: u32 = 0xe220_45fc;
const RPC_DROP_ANSWER: u32 = 0x58e4_a740;
const RPC_ANSWER_UNKNOWN: u32 = 0x5e2a_d36e;
const MSGS_STATE_REQ: u32 = 0xda69_fb52;
const MSGS_STATE_INFO: u32 = 0x04de_b57d;
const MSGS_ACK: u32 = 0x62d6_b459;
const HTTP_WAIT: u32 = 0x9299_359f;

const RPC_RESULT: u32 = 0xf35c_6d01;
const RPC_ERROR: u32 = 0x2144_ca19;

// --- PFS key binding --------------------------------------------------------
const AUTH_BIND_TEMP_AUTH_KEY: u32 = 0xcdd4_2a05;
const BIND_AUTH_KEY_INNER: u32 = 0x75a3_f765;
const AUTH_DROP_TEMP_AUTH_KEYS: u32 = 0x8e48_a188;

// --- Auth / Help / Startup RPCs (verified against ShuzaGramMod TLRPC.java) --
const AUTH_SEND_CODE: u32 = 0xa677_244f;
const AUTH_RESEND_CODE: u32 = 0xcae4_7523;
const AUTH_CANCEL_CODE: u32 = 0x1f04_0578;
const AUTH_SIGN_IN: u32 = 0x8d52_a951;
const AUTH_SIGN_IN_OLD: u32 = 0xbcd5_1581;
const AUTH_SIGN_UP: u32 = 0x80ee_e427;
const AUTH_SIGN_UP_LAYER190: u32 = 0xaac7_b717;
const AUTH_LOG_OUT: u32 = 0x3e72_ba19;
const AUTH_LOGGED_OUT: u32 = 0xc3a2_835f;

const AUTH_SENT_CODE: u32 = 0x5e00_2502;
const AUTH_SENT_CODE_TYPE_APP: u32 = 0x3dbb_5986;
const AUTH_AUTHORIZATION: u32 = 0x2ea2_c0d4;
const USER: u32 = 0xb1b8_cc83;

const HELP_GET_CONFIG: u32 = 0xc4f9_186b;
const CONFIG: u32 = 0xcc1a_241e;
const DC_OPTION: u32 = 0x18b7_a10d;
const HELP_GET_NEAREST_DC: u32 = 0x1fb3_3026;
const NEAREST_DC: u32 = 0x8e1a_1775;
const HELP_GET_COUNTRIES_LIST: u32 = 0x7357_87a8;
const HELP_COUNTRIES_LIST: u32 = 0x87d0_759e;
const HELP_COUNTRIES_LIST_NOT_MODIFIED: u32 = 0x93cc_1f32;
const HELP_COUNTRY: u32 = 0xc387_8e23;
const HELP_COUNTRY_CODE: u32 = 0x4203_c5ef;
const COUNTRIES_HASH: i32 = 0x2026_1102;
const HELP_GET_APP_CONFIG: u32 = 0x61e3_f854;
const HELP_GET_APP_CONFIG_LEGACY: u32 = 0x9891_4110;
const HELP_APP_CONFIG: u32 = 0xdd18_782e;
const HELP_GET_TERMS_OF_SERVICE_UPDATE: u32 = 0x2ca5_1fd1;
const HELP_TERMS_OF_SERVICE_UPDATE_EMPTY: u32 = 0xe330_9f7f;
const HELP_GET_PROMO_DATA: u32 = 0xc097_7421;
const HELP_PROMO_DATA_EMPTY: u32 = 0x98f6_ac75;
const HELP_GET_APP_UPDATE: u32 = 0x522d_5a7d;
const HELP_NO_APP_UPDATE: u32 = 0xc45a_6536;
const HELP_SAVE_APP_LOG: u32 = 0x6f02_f748;
const HELP_GET_PEER_COLORS: u32 = 0xda80_f42f;
const HELP_GET_PEER_PROFILE_COLORS: u32 = 0xabcf_a9fd;
const HELP_PEER_COLORS_NOT_MODIFIED: u32 = 0x2ba1_f5ce;
const HELP_GET_CDN_CONFIG: u32 = 0x5202_9342;
const CDN_CONFIG: u32 = 0x5725_e40a;
const ACCOUNT_REGISTER_DEVICE_TGNET: u32 = 0x637e_a878;

const LANGPACK_GET_LANGUAGES: u32 = 0x42c6_978f;
const LANGPACK_GET_LANGUAGES_LEGACY: u32 = 0x800f_d57d;
const LANGPACK_GET_STRINGS: u32 = 0xefea_3803;
const LANGPACK_GET_STRINGS_LEGACY: u32 = 0x2e1e_e318;
const LANGPACK_GET_LANG_PACK: u32 = 0xf2f2_330a;
const LANGPACK_GET_DIFFERENCE: u32 = 0xcd98_4aa5;
const LANGPACK_DIFFERENCE: u32 = 0xf385_c1f6;

const UPDATES_GET_STATE: u32 = 0xedd4_882a;
#[cfg(test)]
const UPDATES_STATE: u32 = 0xa56c_2a3e;
const UPDATES_GET_DIFFERENCE: u32 = 0x19c2_f763;
const UPDATES_GET_DIFFERENCE_LEGACY: u32 = 0x2593_9651;
#[allow(dead_code)]
const UPDATES_DIFFERENCE_EMPTY: u32 = 0x5d75_a138;

const MESSAGES_GET_DIALOGS: u32 = 0xa0f4_cb4f;
#[cfg(test)]
const MESSAGES_DIALOGS: u32 = 0x15ba_6c40;
const MESSAGES_GET_PINNED_DIALOGS: u32 = 0xd6b9_4df2;
const MESSAGES_GET_PEER_DIALOGS: u32 = 0xe470_bcfd;
#[allow(dead_code)]
const MESSAGES_PEER_DIALOGS: u32 = 0x3371_c354;
const MESSAGES_GET_DIALOG_FILTERS: u32 = 0xefd4_8c89;
const MESSAGES_GET_DIALOG_FILTERS_LEGACY: u32 = 0xf19e_d96d;
const MESSAGES_DIALOG_FILTERS: u32 = 0x2ad9_3719;
const MESSAGES_GET_SUGGESTED_DIALOG_FILTERS: u32 = 0xa29c_d42c;
const MESSAGES_UPDATE_DIALOG_FILTER: u32 = 0x1ad4_a04a;
const MESSAGES_GET_ALL_STICKERS: u32 = 0xb8a0_a1a8;
const MESSAGES_GET_EMOJI_STICKERS: u32 = 0xfbfc_a18f;
const MESSAGES_GET_MASK_STICKERS: u32 = 0x640f_82b8;
const MESSAGES_ALL_STICKERS: u32 = 0xcdbb_cebb;
const MESSAGES_ALL_STICKERS_NOT_MODIFIED: u32 = 0xe866_02c3;
const MESSAGES_GET_FEATURED_STICKERS: u32 = 0x6478_0b14;
const MESSAGES_GET_FEATURED_EMOJI_STICKERS: u32 = 0x0ecf_6736;
const MESSAGES_READ_FEATURED_STICKERS: u32 = 0x5b11_8126;
const MESSAGES_FEATURED_STICKERS: u32 = 0xbe38_2906;
const MESSAGES_FEATURED_STICKERS_NOT_MODIFIED: u32 = 0xc6dc_0c66;
const MESSAGES_GET_ARCHIVED_STICKERS: u32 = 0x57f1_7692;
const MESSAGES_ARCHIVED_STICKERS: u32 = 0x4fcb_a9c8;
const MESSAGES_GET_STICKER_SET: u32 = 0xc8a0_ec74;
const MESSAGES_STICKER_SET: u32 = 0x6e15_3f16;
const STICKER_SET: u32 = 0x2dd1_4edc;
const MESSAGES_GET_RECENT_STICKERS: u32 = 0x9da9_403b;
const MESSAGES_RECENT_STICKERS_NOT_MODIFIED: u32 = 0x0b17_f890;
const MESSAGES_GET_FAVED_STICKERS: u32 = 0x04f1_aaa9;
const MESSAGES_FAVED_STICKERS_NOT_MODIFIED: u32 = 0x9e8f_a6d3;
const MESSAGES_GET_SAVED_GIFS: u32 = 0x5cf0_9635;
const MESSAGES_SAVED_GIFS: u32 = 0x84a0_2a0d;
const MESSAGES_SAVED_GIFS_NOT_MODIFIED: u32 = 0xe802_5ca2;
const MESSAGES_GET_AVAILABLE_REACTIONS: u32 = 0x18de_a0ac;
const MESSAGES_AVAILABLE_REACTIONS_NOT_MODIFIED: u32 = 0x9f07_1957;
const MESSAGES_GET_SEARCH_COUNTERS: u32 = 0x1bbc_f300;
const MESSAGES_SEARCH_COUNTER: u32 = 0xe844_ebff;
const MESSAGES_GET_SEARCH_RESULTS_POSITIONS: u32 = 0x9c7f_2f10;
const MESSAGES_SEARCH_RESULTS_POSITIONS: u32 = 0x53b2_2baf;
const MESSAGES_GET_ATTACH_MENU_BOTS: u32 = 0x16fc_c2cb;
const ATTACH_MENU_BOTS: u32 = 0x3c43_01c0;
const ATTACH_MENU_BOTS_NOT_MODIFIED: u32 = 0xf1d8_8a5c;
const MESSAGES_GET_DEFAULT_HISTORY_TTL: u32 = 0x658b_7188;
const DEFAULT_HISTORY_TTL: u32 = 0x43b4_6b20;
const HELP_DISMISS_SUGGESTION: u32 = 0xf50d_baa1;

const INPUT_STICKER_SET_EMPTY: u32 = 0xffb6_2b95;
const INPUT_STICKER_SET_ID: u32 = 0x9de7_a269;
const INPUT_STICKER_SET_SHORT_NAME: u32 = 0x861c_c8a0;
const INPUT_STICKER_SET_ANIMATED_EMOJI: u32 = 0x0287_03c8;
const INPUT_STICKER_SET_DICE: u32 = 0xe67f_520e;
const INPUT_STICKER_SET_DICE_LAYER111: u32 = 0x79e2_1a53;
const INPUT_STICKER_SET_PREMIUM_GIFTS: u32 = 0xc88b_3b02;
const INPUT_STICKER_SET_TON_GIFTS: u32 = 0x1cf6_71a0;
const INPUT_STICKER_SET_EMOJI_DEFAULT_STATUSES: u32 = 0x29d0_f5ee;
const INPUT_STICKER_SET_EMOJI_CHANNEL_DEFAULT_STATUSES: u32 = 0x4974_8553;
const INPUT_STICKER_SET_EMOJI_GENERIC_ANIMATIONS: u32 = 0x04c4_d4ce;
const INPUT_STICKER_SET_EMOJI_DEFAULT_TOPIC_ICONS: u32 = 0x44c1_f8e9;

const INPUT_MESSAGES_FILTER_PHONE_CALLS: u32 = 0x80c9_9768;

const INPUT_USER_EMPTY: u32 = 0xb988_86cf;
const INPUT_USER_SELF: u32 = 0xf7c1_b13f;
const INPUT_USER: u32 = 0xf211_58c6;
const INPUT_USER_LAYER132: u32 = 0xd829_2816;
const INPUT_USER_FROM_MESSAGE: u32 = 0x1da4_48e2;

const INPUT_PEER_EMPTY: u32 = 0x7f3b_18ea;
const INPUT_PEER_SELF: u32 = 0x7da0_7ec9;
const INPUT_PEER_CHAT: u32 = 0x35a9_5cb9;
const INPUT_PEER_CHAT_LAYER131: u32 = 0x179b_e863;
const INPUT_PEER_USER: u32 = 0xdde8_a54c;
const INPUT_PEER_USER_LAYER131: u32 = 0x7b8e_7de6;
const INPUT_PEER_CHANNEL: u32 = 0x27bc_bbfc;
const INPUT_PEER_CHANNEL_LAYER131: u32 = 0x20ad_aef8;
const INPUT_PEER_USER_FROM_MESSAGE: u32 = 0xa87b_0a1c;
const INPUT_PEER_CHANNEL_FROM_MESSAGE: u32 = 0xbd2a_0840;

const PEER_USER: u32 = 0x5951_1722;
const PEER_CHAT: u32 = 0x36c6_019a;
const PEER_CHANNEL: u32 = 0xa2a5_371e;

const USERS_GET_USERS: u32 = 0x0d91_a548;
const USERS_GET_FULL_USER: u32 = 0xb60f_5918;
const USERS_USER_FULL: u32 = 0x3b6d_152e;
const USER_FULL: u32 = 0x7fe7_38c4;
const PEER_SETTINGS: u32 = 0xf477_41f7;
const PEER_NOTIFY_SETTINGS: u32 = 0x9962_2c0c;

const ACCOUNT_UPDATE_STATUS: u32 = 0x6628_562c;
const ACCOUNT_REGISTER_DEVICE: u32 = 0xec86_017a;
const ACCOUNT_UNREGISTER_DEVICE: u32 = 0x6a0d_3206;
const ACCOUNT_UPDATE_NOTIFY_SETTINGS: u32 = 0x84be_5b93;
const ACCOUNT_GET_NOTIFY_SETTINGS: u32 = 0x12b3_ad31;
const ACCOUNT_RESET_NOTIFY_SETTINGS: u32 = 0xdb7e_1747;
const ACCOUNT_GET_PASSWORD: u32 = 0x548a_30f5;
const ACCOUNT_PASSWORD: u32 = 0x957b_50fb;
const PASSWORD_KDF_ALGO_MODPOW: u32 = 0x3a91_2d4a;
const SECURE_PASSWORD_KDF_ALGO_PBKDF2: u32 = 0xbbf2_dda0;
const ACCOUNT_GET_PRIVACY: u32 = 0xdadb_c950;
const ACCOUNT_SET_PRIVACY: u32 = 0xc9f8_1ce8;
const ACCOUNT_PRIVACY_RULES: u32 = 0x50a0_4e45;
const ACCOUNT_GET_GLOBAL_PRIVACY_SETTINGS: u32 = 0xeb2b_4cf6;
const ACCOUNT_SET_GLOBAL_PRIVACY_SETTINGS: u32 = 0x1eda_aac2;
const GLOBAL_PRIVACY_SETTINGS: u32 = 0xfe41_b34f;
const ACCOUNT_GET_CONTENT_SETTINGS: u32 = 0x8b9b_4dae;
const ACCOUNT_CONTENT_SETTINGS: u32 = 0x57e2_8221;
const ACCOUNT_GET_CONTACT_SIGN_UP_NOTIFICATION: u32 = 0x9f07_c728;
const ACCOUNT_SET_CONTACT_SIGN_UP_NOTIFICATION: u32 = 0xcff4_3f61;
const ACCOUNT_GET_AUTHORIZATIONS: u32 = 0xe320_c158;
const ACCOUNT_AUTHORIZATIONS: u32 = 0x4bff_8ea0;

const CONTACTS_GET_CONTACTS: u32 = 0x5dd6_9e12;
#[allow(dead_code)]
const CONTACTS_CONTACTS_NOT_MODIFIED: u32 = 0xb74b_a9d2;
const CONTACTS_GET_STATUSES: u32 = 0xc4a3_53ee;
const CONTACTS_GET_TOP_PEERS: u32 = 0x9734_78b6;
const CONTACTS_TOP_PEERS_NOT_MODIFIED: u32 = 0xde26_6ef5;

const PAYMENTS_GET_SAVED_STAR_GIFTS: u32 = 0xa319_e569;
const PAYMENTS_SAVED_STAR_GIFTS: u32 = 0x95f3_89b1;
const PAYMENTS_GET_STARS_STATUS: u32 = 0x4ea9_b3bf;
const PAYMENTS_STARS_STATUS: u32 = 0x6c9c_e8ed;
const STARS_AMOUNT: u32 = 0xbbb6_b4a3;

const STORIES_GET_ALL_STORIES: u32 = 0xeeb0_d625;
const STORIES_ALL_STORIES_NOT_MODIFIED: u32 = 0x1158_fe3e;
const STORIES_STEALTH_MODE: u32 = 0x712e_27fd;
const STORIES_GET_PEER_STORIES: u32 = 0x2c4a_da50;
const STORIES_PEER_STORIES: u32 = 0xcae6_8768;
const PEER_STORIES: u32 = 0x9a35_e999;

/// Per-connection state threaded through dispatch.
#[derive(Default)]
pub struct ConnContext {
    pub conn_id: u64,
    pub auth_key_id: i64,
    pub server_salt: i64,
    pub session_id: i64,
    pub negotiated_layer: u16,
    pub is_push_socket: bool,
    pub device_model: String,
    pub app_version: String,
    pub user: Option<User>,
}

/// One serialized reply body.
pub type Response = Vec<u8>;

/// Whether an outbound MTProto message is content-related (odd `seq_no`,
/// expects `msgs_ack`) or a transport/service reply (even `seq_no`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Content,
    Service,
}

/// A serialized reply annotated with its MTProto `seq_no` class.
#[derive(Debug, Clone)]
pub struct Outbound {
    pub kind: OutboundKind,
    pub body: Response,
}

impl Outbound {
    pub fn content(body: Response) -> Self {
        Outbound {
            kind: OutboundKind::Content,
            body,
        }
    }

    pub fn service(body: Response) -> Self {
        Outbound {
            kind: OutboundKind::Service,
            body,
        }
    }
}

/// Advertised data-center endpoint (for `help.getConfig`).
#[derive(Clone)]
pub struct DcEndpoint {
    pub dc_id: i32,
    pub ip: String,
    pub port: i32,
}

impl Default for DcEndpoint {
    fn default() -> Self {
        DcEndpoint {
            dc_id: 2,
            ip: "127.0.0.1".to_string(),
            port: 8443,
        }
    }
}

/// Routes decrypted requests to handlers.
pub struct Dispatcher {
    store: Arc<Store>,
    keys: Arc<KeyStore>,
    hub: Arc<SessionHub>,
    layers: Arc<LayerAdapterRegistry>,
    dc: DcEndpoint,
}

impl Dispatcher {
    pub fn new(store: Arc<Store>) -> Self {
        Dispatcher {
            store,
            keys: Arc::new(KeyStore::load(None)),
            hub: Arc::new(SessionHub::new()),
            layers: Arc::new(LayerAdapterRegistry::new()),
            dc: DcEndpoint::default(),
        }
    }

    /// Share the edge `KeyStore` so `auth.bindTempAuthKey` can verify the
    /// client's permanent `auth_key` and link PFS temporary keys to it.
    pub fn with_keys(mut self, keys: Arc<KeyStore>) -> Self {
        self.keys = keys;
        self
    }

    /// Share a [`SessionHub`] for real-time `Updates` push & sniffer telemetry.
    pub fn with_hub(mut self, hub: Arc<SessionHub>) -> Self {
        self.hub = hub;
        self
    }

    /// Set the data-center endpoint advertised by `help.getConfig`.
    pub fn with_dc(mut self, dc: DcEndpoint) -> Self {
        self.dc = dc;
        self
    }

    pub fn hub(&self) -> &Arc<SessionHub> {
        &self.hub
    }

    pub fn dc(&self) -> &DcEndpoint {
        &self.dc
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    pub fn keys(&self) -> &Arc<KeyStore> {
        &self.keys
    }

    /// Handle one decrypted inbound message body, returning reply bodies.
    pub fn handle_message(&self, ctx: &mut ConnContext, msg_id: i64, body: &[u8]) -> Vec<Response> {
        self.handle_message_ex(ctx, msg_id, body)
            .into_iter()
            .map(|o| o.body)
            .collect()
    }

    /// Handle one decrypted inbound message body, returning replies annotated
    /// with whether they require an odd (content) or even (service) `seq_no`.
    pub fn handle_message_ex(
        &self,
        ctx: &mut ConnContext,
        msg_id: i64,
        body: &[u8],
    ) -> Vec<Outbound> {
        // Hydrate logged-in user across reconnects / parallel sockets via perm key.
        if ctx.user.is_none() && ctx.auth_key_id != 0 {
            let perm_id = self.keys.resolve_perm(ctx.auth_key_id);
            ctx.user = self
                .store
                .user_for_key(perm_id)
                .or_else(|| self.store.user_for_key(ctx.auth_key_id));
        }

        let mut r = Reader::new(body);
        let Ok(id) = r.read_u32() else {
            return vec![];
        };

        if id == GZIP_PACKED {
            let Ok(packed) = r.read_bytes() else {
                return vec![Outbound::content(rpc_result(
                    msg_id,
                    &rpc_error(400, "GZIP_MALFORMED"),
                ))];
            };
            let Ok(unpacked) = gunzip_bounded(packed) else {
                return vec![Outbound::content(rpc_result(
                    msg_id,
                    &rpc_error(400, "GZIP_INVALID"),
                ))];
            };
            return self.handle_message_ex(ctx, msg_id, &unpacked);
        }

        if id == MSG_CONTAINER {
            return self.handle_container(ctx, &mut r);
        }

        // Service messages that expect no reply.
        if id == MSGS_ACK || id == HTTP_WAIT {
            return vec![];
        }

        // Unwrap invokeWithLayer / initConnection / invokeAfterMsg* down to the inner query.
        let raw_query = match peel_wrappers_ctx(id, &mut r, ctx, 0) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("[core] wrapper decode error on {id:#010x}: {e}");
                return vec![Outbound::content(rpc_result(
                    msg_id,
                    &rpc_error(400, "QUERY_MALFORMED"),
                ))];
            }
        };
        let layer = if ctx.negotiated_layer > 0 {
            ctx.negotiated_layer
        } else {
            232
        };
        let query = match self.layers.upgrade_ingress_rpc(layer, &raw_query) {
            Ok(q) => q,
            Err(_) => std::borrow::Cow::Borrowed(raw_query.as_slice()),
        };

        let mut qr = Reader::new(&query);
        let Ok(qid) = qr.read_u32() else {
            return vec![Outbound::content(rpc_result(
                msg_id,
                &rpc_error(400, "QUERY_EMPTY"),
            ))];
        };

        // MTProto transport/service messages.
        match qid {
            MSGS_ACK | HTTP_WAIT => return vec![],
            PING => {
                let ping_id = qr.read_i64().unwrap_or(0);
                return vec![Outbound::service(pong(msg_id, ping_id))];
            }
            PING_DELAY_DISCONNECT => {
                let ping_id = qr.read_i64().unwrap_or(0);
                let _delay = qr.read_i32();
                return vec![Outbound::service(pong(msg_id, ping_id))];
            }
            GET_FUTURE_SALTS => {
                let num = qr.read_i32().unwrap_or(1).clamp(1, 64) as usize;
                let salt = if ctx.server_salt != 0 {
                    ctx.server_salt
                } else {
                    0x5a5a_5a5a_5a5a_5a5a
                };
                return vec![Outbound::service(future_salts(msg_id, salt, num))];
            }
            DESTROY_SESSION => {
                let sid = qr.read_i64().unwrap_or(0);
                return vec![Outbound::service(destroy_session_ok(sid))];
            }
            MSGS_STATE_REQ => {
                let count = qr.read_long_vector().map(|v| v.len()).unwrap_or(0);
                return vec![Outbound::service(msgs_state_info(msg_id, count))];
            }
            RPC_DROP_ANSWER => {
                let _req_id = qr.read_i64();
                return vec![Outbound::content(rpc_result(msg_id, &rpc_answer_unknown()))];
            }
            _ => {}
        }

        self.hub.bump_rpc_counter();
        let sniffer_on = self.hub.sniffer_enabled();
        let started = if sniffer_on {
            Some(Instant::now())
        } else {
            None
        };

        let result = self.dispatch_query(ctx, qid, &mut qr);

        if ctx.conn_id != 0 {
            let perm_id = self.keys.resolve_perm(ctx.auth_key_id);
            self.hub.update_session(
                ctx.conn_id,
                ctx.auth_key_id,
                perm_id,
                ctx.session_id,
                ctx.user.as_ref().map(|u| u.id),
                layer,
                ctx.is_push_socket,
                if ctx.device_model.is_empty() {
                    None
                } else {
                    Some(ctx.device_model.as_str())
                },
                if ctx.app_version.is_empty() {
                    None
                } else {
                    Some(ctx.app_version.as_str())
                },
            );
        }

        if let Some(t0) = started {
            let dur_us = t0.elapsed().as_micros().min(u32::MAX as u128) as u32;
            let (err_code, err_msg) = if result.len() >= 8
                && u32::from_le_bytes(result[0..4].try_into().unwrap()) == RPC_ERROR
            {
                let mut er = Reader::new(&result[4..]);
                let c = er.read_i32().unwrap_or(400);
                let m = er.read_string().unwrap_or("").to_string();
                (c, m)
            } else {
                (0, String::new())
            };
            let mname = self.layers.method_name(qid).unwrap_or("unknown");
            self.hub.record_rpc_trace(
                self.dc.dc_id,
                ctx.user.as_ref().map_or(0, |u| u.id),
                ctx.auth_key_id,
                layer,
                qid,
                mname,
                dur_us,
                err_code,
                &err_msg,
            );
        }

        vec![Outbound::content(rpc_result(msg_id, &result))]
    }

    fn handle_container(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<Outbound> {
        let Ok(count) = r.read_u32() else {
            return vec![];
        };
        let mut out = Vec::new();
        for _ in 0..count {
            let (Ok(inner_msg_id), Ok(_seq), Ok(len)) =
                (r.read_i64(), r.read_i32(), r.read_i32())
            else {
                break;
            };
            if len < 0 {
                break;
            }
            let Ok(inner_body) = r.read_raw(len as usize) else {
                break;
            };
            out.extend(self.handle_message_ex(ctx, inner_msg_id, inner_body));
        }
        out
    }

    /// Dispatch a single RPC query, returning the serialized result (or `rpc_error`).
    fn dispatch_query(&self, ctx: &mut ConnContext, qid: u32, r: &mut Reader) -> Vec<u8> {
        match qid {
            AUTH_BIND_TEMP_AUTH_KEY => self.auth_bind_temp_auth_key(ctx, r),
            AUTH_DROP_TEMP_AUTH_KEYS => self.auth_drop_temp_auth_keys(ctx, r),

            AUTH_SEND_CODE => self.auth_send_code(r),
            AUTH_RESEND_CODE => self.auth_resend_code(r),
            AUTH_CANCEL_CODE => self.auth_cancel_code(r),
            AUTH_SIGN_IN => self.auth_sign_in(ctx, r),
            AUTH_SIGN_IN_OLD => self.auth_sign_in_old(ctx, r),
            AUTH_SIGN_UP => self.auth_sign_up(ctx, r, false),
            AUTH_SIGN_UP_LAYER190 => self.auth_sign_up(ctx, r, true),
            AUTH_LOG_OUT => self.auth_log_out(ctx),

            HELP_GET_CONFIG => config(&self.dc),
            HELP_GET_NEAREST_DC => nearest_dc(&self.dc),
            HELP_GET_COUNTRIES_LIST => countries_list(r),
            HELP_GET_APP_CONFIG | HELP_GET_APP_CONFIG_LEGACY => app_config(),
            HELP_GET_TERMS_OF_SERVICE_UPDATE => terms_of_service_empty(),
            HELP_GET_PROMO_DATA => promo_data_empty(),
            HELP_GET_APP_UPDATE => empty_ctor(HELP_NO_APP_UPDATE),
            HELP_SAVE_APP_LOG => bool_result(true),
            HELP_GET_PEER_COLORS | HELP_GET_PEER_PROFILE_COLORS => {
                empty_ctor(HELP_PEER_COLORS_NOT_MODIFIED)
            }
            HELP_GET_CDN_CONFIG => cdn_config_empty(),

            LANGPACK_GET_LANGUAGES
            | LANGPACK_GET_LANGUAGES_LEGACY
            | LANGPACK_GET_STRINGS
            | LANGPACK_GET_STRINGS_LEGACY => empty_vector(),
            LANGPACK_GET_LANG_PACK => langpack_get_lang_pack(r),
            LANGPACK_GET_DIFFERENCE => langpack_get_difference(r),

            UPDATES_GET_STATE => self.updates_get_state_real(ctx),
            UPDATES_GET_DIFFERENCE => self.updates_get_difference_real(ctx, r, false),
            UPDATES_GET_DIFFERENCE_LEGACY => self.updates_get_difference_real(ctx, r, true),

            MESSAGES_GET_DIALOGS => self.messages_get_dialogs_real(ctx, r),
            MESSAGES_GET_PINNED_DIALOGS => self.messages_get_peer_dialogs_real(ctx, r, true),
            MESSAGES_GET_PEER_DIALOGS => self.messages_get_peer_dialogs_real(ctx, r, false),
            0x4423_e6c5 => self.messages_get_history(ctx, r), // messages.getHistory
            0x4222_fa74 => self.messages_get_messages(ctx, r, false), // messages.getMessages
            0x63c6_6523 => self.messages_get_messages(ctx, r, true),  // messages.getMessages (vector<InputMessage>)
            0xfef4_8f62 => self.messages_send_message(ctx, r, false), // messages.sendMessage Layer 232
            0x983f_9745 | 0x280d_096f => self.messages_send_message(ctx, r, true), // messages.sendMessage legacy int reply
            0xb106_e66c | 0xdfd1_4005 => self.messages_edit_message(ctx, r), // messages.editMessage
            0xe58e_95d2 => self.messages_delete_messages(ctx, r), // messages.deleteMessages
            0xb08f_922a => self.messages_delete_history(ctx, r),  // messages.deleteHistory
            0x0e30_6d3a => self.messages_read_history(ctx, r),    // messages.readHistory
            0x5894_3ee2 => self.messages_set_typing(ctx, r),      // messages.setTyping
            0x0034_a818 => self.messages_create_chat(ctx, r, true), // messages.createChat Layer 232
            0x92ce_ddd4 => self.messages_create_chat(ctx, r, false), // messages.createChat legacy
            0x9100_6707 => self.channels_create_channel(ctx, r),   // channels.createChannel
            0x0a7f_6bbb => self.channels_get_channels(ctx, r),     // channels.getChannels
            0x0873_6a09 => self.channels_get_full_channel(ctx, r), // channels.getFullChannel
            0x24b5_24c5 => self.channels_join_channel(ctx, r),     // channels.joinChannel
            0xf836_aa95 => self.channels_leave_channel(ctx, r),    // channels.leaveChannel
            0x10e6_bd2c => self.channels_check_username(ctx, r),   // channels.checkUsername
            0x3514_b3de => self.channels_update_username(ctx, r),  // channels.updateUsername
            0xcc10_4937 => self.channels_read_history(ctx, r),     // channels.readHistory
            0x93d7_b347 => self.channels_get_messages(ctx, r, false), // channels.getMessages
            0x0317_3d78 => self.updates_get_channel_difference(ctx, r), // updates.getChannelDifference

            0x7851_5775 => self.account_update_profile(ctx, r),   // account.updateProfile
            0x2714_d86c => self.account_check_username(ctx, r),   // account.checkUsername
            0x3e0b_dd7c => self.account_update_username(ctx, r),  // account.updateUsername

            CONTACTS_GET_CONTACTS => self.contacts_get_contacts(ctx, r),
            0x2c80_0be5 => self.contacts_import_contacts(ctx, r), // contacts.importContacts
            0xd9ba_2e54 => self.contacts_add_contact(ctx, r, true), // contacts.addContact Layer 232
            0xe8f4_e44f => self.contacts_add_contact(ctx, r, false), // contacts.addContact legacy
            0x096a_0e00 => self.contacts_delete_contacts(ctx, r), // contacts.deleteContacts
            0x725a_fbbc => self.contacts_resolve_username(ctx, r, true), // contacts.resolveUsername Layer 232
            0xf93b_bf40 => self.contacts_resolve_username(ctx, r, false), // contacts.resolveUsername legacy
            0x8af9_4344 => self.contacts_resolve_phone(ctx, r),    // contacts.resolvePhone
            0x05f5_8d0f => self.contacts_search(ctx, r, true),     // contacts.search Layer 232
            0x11f8_12d8 => self.contacts_search(ctx, r, false),    // contacts.search legacy
            CONTACTS_GET_STATUSES => self.contacts_get_statuses(ctx),
            0x9a86_8f80 => Self::contacts_get_blocked(),
            MESSAGES_GET_DIALOG_FILTERS | MESSAGES_GET_DIALOG_FILTERS_LEGACY => {
                messages_dialog_filters_empty()
            }
            MESSAGES_GET_SUGGESTED_DIALOG_FILTERS => empty_vector(),
            MESSAGES_UPDATE_DIALOG_FILTER => bool_result(true),
            MESSAGES_GET_ALL_STICKERS
            | MESSAGES_GET_EMOJI_STICKERS
            | MESSAGES_GET_MASK_STICKERS => messages_all_stickers(r),
            MESSAGES_GET_FEATURED_STICKERS | MESSAGES_GET_FEATURED_EMOJI_STICKERS => {
                messages_featured_stickers(r)
            }
            MESSAGES_READ_FEATURED_STICKERS => bool_result(true),
            MESSAGES_GET_ARCHIVED_STICKERS => messages_archived_stickers(),
            MESSAGES_GET_STICKER_SET => messages_get_sticker_set(r),
            MESSAGES_GET_RECENT_STICKERS => empty_ctor(MESSAGES_RECENT_STICKERS_NOT_MODIFIED),
            MESSAGES_GET_FAVED_STICKERS => empty_ctor(MESSAGES_FAVED_STICKERS_NOT_MODIFIED),
            MESSAGES_GET_SAVED_GIFS => messages_saved_gifs(r),
            MESSAGES_GET_AVAILABLE_REACTIONS => {
                empty_ctor(MESSAGES_AVAILABLE_REACTIONS_NOT_MODIFIED)
            }
            MESSAGES_GET_SEARCH_COUNTERS => messages_get_search_counters(r),
            MESSAGES_GET_SEARCH_RESULTS_POSITIONS => messages_search_results_positions(),
            MESSAGES_GET_ATTACH_MENU_BOTS => messages_attach_menu_bots(r),
            MESSAGES_GET_DEFAULT_HISTORY_TTL => default_history_ttl(),
            HELP_DISMISS_SUGGESTION => bool_result(true),

            USERS_GET_USERS => self.users_get_users(ctx, r),
            USERS_GET_FULL_USER => self.users_get_full_user(ctx, r),

            ACCOUNT_REGISTER_DEVICE | ACCOUNT_REGISTER_DEVICE_TGNET => {
                ctx.is_push_socket = true;
                bool_result(true)
            }
            ACCOUNT_UPDATE_STATUS
            | ACCOUNT_UNREGISTER_DEVICE
            | ACCOUNT_UPDATE_NOTIFY_SETTINGS
            | ACCOUNT_RESET_NOTIFY_SETTINGS
            | ACCOUNT_GET_CONTACT_SIGN_UP_NOTIFICATION
            | ACCOUNT_SET_CONTACT_SIGN_UP_NOTIFICATION => bool_result(true),
            ACCOUNT_GET_NOTIFY_SETTINGS => peer_notify_settings_default(),
            ACCOUNT_GET_PASSWORD => account_get_password(),
            ACCOUNT_GET_PRIVACY | ACCOUNT_SET_PRIVACY => account_privacy_rules_empty(),
            ACCOUNT_GET_GLOBAL_PRIVACY_SETTINGS | ACCOUNT_SET_GLOBAL_PRIVACY_SETTINGS => {
                global_privacy_settings_default()
            }
            ACCOUNT_GET_CONTENT_SETTINGS => account_content_settings_default(),
            ACCOUNT_GET_AUTHORIZATIONS => account_authorizations_empty(),

            CONTACTS_GET_TOP_PEERS => empty_ctor(CONTACTS_TOP_PEERS_NOT_MODIFIED),

            PAYMENTS_GET_SAVED_STAR_GIFTS => payments_saved_star_gifts_empty(),
            PAYMENTS_GET_STARS_STATUS => payments_stars_status_empty(),

            STORIES_GET_ALL_STORIES => stories_all_stories_not_modified(),
            STORIES_GET_PEER_STORIES => self.stories_peer_stories_empty(ctx, r),

            other => {
                eprintln!("[core] unknown rpc {other:#010x} (key={:#018x})", ctx.auth_key_id);
                rpc_error(400, &format!("UNKNOWN_METHOD_{other:#010x}"))
            }
        }
    }

    // auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes = Bool
    fn auth_bind_temp_auth_key(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let (Ok(perm_auth_key_id), Ok(nonce), Ok(_expires_at), Ok(encrypted_message)) = (
            r.read_i64(),
            r.read_i64(),
            r.read_i32(),
            r.read_bytes(),
        ) else {
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        };

        // If the server doesn't know perm_auth_key_id (e.g. cached on the phone
        // from before key persistence), returning ENCRYPTED_MESSAGE_INVALID
        // triggers tgnet ConnectionsManager::cleanUp(true, dcId) so the client
        // automatically negotiates a fresh permanent auth key!
        let Some((perm_key, _perm_salt)) = self.keys.get(perm_auth_key_id) else {
            eprintln!(
                "[core] bindTempAuthKey: unknown perm_auth_key_id={perm_auth_key_id:#018x} (temp={:#018x}) -> ENCRYPTED_MESSAGE_INVALID",
                ctx.auth_key_id
            );
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        };

        if encrypted_message.len() < 24 + 32 {
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        }
        let inner_key_id = i64::from_le_bytes(encrypted_message[0..8].try_into().unwrap());
        if inner_key_id != perm_auth_key_id {
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        }
        let msg_key: [u8; 16] = encrypted_message[8..24].try_into().unwrap();
        let ct_slice = &encrypted_message[24..];
        if !ct_slice.len().is_multiple_of(16) {
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        }

        // tgnet encrypts bind_auth_key_inner using MTProto 1.0 SHA-1 KDF; also
        // fall back to MTProto 2.0 SHA-256 KDF for non-tgnet clients.
        let mut ct_v1 = ct_slice.to_vec();
        let inner_body: Vec<u8> = if let Ok(unpadded) =
            kdf::decrypt_message_v1(&perm_key, &msg_key, &mut ct_v1, Direction::ClientToServer)
        {
            unpadded[32..].to_vec()
        } else {
            let mut ct_v2 = ct_slice.to_vec();
            let Ok(pt) =
                kdf::decrypt_message(&perm_key, &msg_key, &mut ct_v2, Direction::ClientToServer)
            else {
                eprintln!(
                    "[core] bindTempAuthKey: inner decrypt failed for perm={perm_auth_key_id:#018x}"
                );
                return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
            };
            if pt.len() < 32 {
                return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
            }
            let len = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
            if 32 + len > pt.len() {
                return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
            }
            pt[32..32 + len].to_vec()
        };

        let mut ir = Reader::new(&inner_body);
        let (
            Ok(inner_ctor),
            Ok(inner_nonce),
            Ok(inner_temp_key_id),
            Ok(inner_perm_key_id),
            Ok(_inner_session_id),
            Ok(_inner_expires_at),
        ) = (
            ir.read_u32(),
            ir.read_i64(),
            ir.read_i64(),
            ir.read_i64(),
            ir.read_i64(),
            ir.read_i32(),
        )
        else {
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        };

        if inner_ctor != BIND_AUTH_KEY_INNER
            || inner_nonce != nonce
            || inner_perm_key_id != perm_auth_key_id
            || (ctx.auth_key_id != 0 && inner_temp_key_id != ctx.auth_key_id)
        {
            eprintln!(
                "[core] bindTempAuthKey: inner field mismatch ctor={inner_ctor:#010x} temp={inner_temp_key_id:#018x} ctx_temp={:#018x}",
                ctx.auth_key_id
            );
            return rpc_error(400, "ENCRYPTED_MESSAGE_INVALID");
        }

        self.keys.bind_temp(inner_temp_key_id, perm_auth_key_id);
        if let Some(user) = self.store.user_for_key(perm_auth_key_id) {
            self.store.bind_key_user(inner_temp_key_id, user.id);
            ctx.user = Some(user);
        }
        eprintln!(
            "[core] bindTempAuthKey OK temp={inner_temp_key_id:#018x} -> perm={perm_auth_key_id:#018x}"
        );
        bool_result(true)
    }

    fn auth_drop_temp_auth_keys(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let keep = r.read_long_vector().unwrap_or_default();
        if ctx.auth_key_id != 0 {
            self.keys.drop_temp_keys_except(ctx.auth_key_id, &keep);
        }
        bool_result(true)
    }

    // auth.sendCode phone_number:string api_id:int api_hash:string settings:CodeSettings
    fn auth_send_code(&self, r: &mut Reader) -> Vec<u8> {
        let Ok(phone) = r.read_string() else {
            return rpc_error(400, "PHONE_NUMBER_INVALID");
        };
        let _ = r.read_i32();
        let _ = r.read_string();

        let (hash, _code) = self.store.start_login(phone);
        // Never log the code (test-server master code must stay private).
        eprintln!("[core] sendCode phone={phone}");

        encode_sent_code(&hash)
    }

    // auth.resendCode#cae47523 flags:# phone_number:string phone_code_hash:string reason:flags.0?string
    fn auth_resend_code(&self, r: &mut Reader) -> Vec<u8> {
        let _flags = r.read_i32().unwrap_or(0);
        let (Ok(phone), Ok(hash)) = (r.read_string(), r.read_string()) else {
            return rpc_error(400, "PHONE_NUMBER_INVALID");
        };
        let next_hash = self.store.resend_code(phone, hash);
        eprintln!("[core] resendCode phone={phone}");
        encode_sent_code(&next_hash)
    }

    // auth.cancelCode#1f040578 phone_number:string phone_code_hash:string = Bool
    fn auth_cancel_code(&self, r: &mut Reader) -> Vec<u8> {
        let _ = r.read_string();
        if let Ok(hash) = r.read_string() {
            self.store.cancel_code(hash);
        }
        bool_result(true)
    }

    // auth.signIn flags:# phone_number:string phone_code_hash:string phone_code:flags.0?string
    fn auth_sign_in(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "SIGN_IN_MALFORMED");
        };
        let (Ok(phone), Ok(hash)) = (r.read_string(), r.read_string()) else {
            return rpc_error(400, "SIGN_IN_MALFORMED");
        };
        let code = if flags & 1 != 0 {
            r.read_string().unwrap_or("")
        } else {
            return rpc_error(400, "PHONE_CODE_EMPTY");
        };

        self.finish_sign_in(ctx, phone, hash, code)
    }

    // auth.signInOld#bcd51581 phone_number:string phone_code_hash:string phone_code:string
    fn auth_sign_in_old(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let (Ok(phone), Ok(hash), Ok(code)) =
            (r.read_string(), r.read_string(), r.read_string())
        else {
            return rpc_error(400, "SIGN_IN_MALFORMED");
        };
        self.finish_sign_in(ctx, phone, hash, code)
    }

    fn finish_sign_in(
        &self,
        ctx: &mut ConnContext,
        phone: &str,
        hash: &str,
        code: &str,
    ) -> Vec<u8> {
        match self.store.check_code(hash, code) {
            Some(user) => {
                self.bind_context_user(ctx, &user);
                eprintln!("[core] signIn OK user_id={} phone={phone}", user.id);
                authorization(&user)
            }
            None => {
                eprintln!("[core] signIn PHONE_CODE_INVALID phone={phone}");
                rpc_error(400, "PHONE_CODE_INVALID")
            }
        }
    }

    // auth.signUp#80eee427 / #aac7b717
    fn auth_sign_up(&self, ctx: &mut ConnContext, r: &mut Reader, has_flags: bool) -> Vec<u8> {
        if has_flags {
            let _ = r.read_i32();
        }
        let (Ok(phone), Ok(hash), Ok(first_name), Ok(last_name)) = (
            r.read_string(),
            r.read_string(),
            r.read_string(),
            r.read_string(),
        ) else {
            return rpc_error(400, "SIGN_UP_MALFORMED");
        };
        match self.store.sign_up(phone, hash, first_name, last_name) {
            Some(user) => {
                self.bind_context_user(ctx, &user);
                eprintln!("[core] signUp OK user_id={} phone={phone}", user.id);
                authorization(&user)
            }
            None => rpc_error(400, "PHONE_CODE_EXPIRED"),
        }
    }

    fn auth_log_out(&self, ctx: &mut ConnContext) -> Vec<u8> {
        if ctx.auth_key_id != 0 {
            let perm_id = self.keys.resolve_perm(ctx.auth_key_id);
            self.store.unbind_key(perm_id);
            self.store.unbind_key(ctx.auth_key_id);
        }
        ctx.user = None;
        let mut w = Writer::new();
        w.write_u32(AUTH_LOGGED_OUT);
        w.write_i32(0); // flags (no future_auth_token)
        w.into_vec()
    }

    fn bind_context_user(&self, ctx: &mut ConnContext, user: &User) {
        ctx.user = Some(user.clone());
        if ctx.auth_key_id != 0 {
            let perm_id = self.keys.resolve_perm(ctx.auth_key_id);
            self.store.bind_key_user(perm_id, user.id);
            if perm_id != ctx.auth_key_id {
                self.store.bind_key_user(ctx.auth_key_id, user.id);
            }
        }
    }

    pub fn resolve_input_user_pub(
        &self,
        ctx: &ConnContext,
        r: &mut Reader,
    ) -> Result<Option<User>, TlError> {
        self.resolve_input_user(ctx, r)
    }

    fn resolve_input_user(&self, ctx: &ConnContext, r: &mut Reader) -> Result<Option<User>, TlError> {
        let ctor = r.read_u32()?;
        match ctor {
            INPUT_USER_EMPTY => Ok(None),
            INPUT_USER_SELF => Ok(ctx.user.clone()),
            INPUT_USER => {
                let uid = r.read_i64()?;
                let _access_hash = r.read_i64()?;
                if ctx.user.as_ref().map(|u| u.id) == Some(uid) {
                    Ok(ctx.user.clone())
                } else {
                    Ok(self.store.user_by_id(uid))
                }
            }
            INPUT_USER_LAYER132 => {
                let uid = r.read_i32()? as i64;
                let _access_hash = r.read_i64()?;
                Ok(self.store.user_by_id(uid))
            }
            INPUT_USER_FROM_MESSAGE => {
                let _ = read_input_peer(r, ctx.user.as_ref().map(|u| u.id))?;
                let _msg_id = r.read_i32()?;
                let uid = r.read_i64()?;
                Ok(self.store.user_by_id(uid))
            }
            other => Err(TlError::UnknownConstructor {
                id: other,
                context: "InputUser",
            }),
        }
    }

    /// `users.getUsers#0d91a548 id:Vector<InputUser> = Vector<User>`
    fn users_get_users(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let self_id = ctx.user.as_ref().map(|u| u.id);
        let Ok(count) = r.read_vector_header() else {
            let mut w = Writer::new();
            if let Some(u) = &ctx.user {
                w.write_vector_header(1);
                w.write_raw(&encode_user_for_viewer(u, self_id));
            } else {
                w.write_vector_header(0);
            }
            return w.into_vec();
        };
        let mut found = Vec::with_capacity(count as usize);
        for _ in 0..count {
            match self.resolve_input_user(ctx, r) {
                Ok(Some(u)) => found.push(u),
                Ok(None) => {}
                Err(_) => break,
            }
        }
        let mut w = Writer::new();
        w.write_vector_header(found.len());
        for u in &found {
            w.write_raw(&encode_user_for_viewer(u, self_id));
        }
        w.into_vec()
    }

    /// `users.getFullUser#b60f5918 id:InputUser = users.UserFull`
    fn users_get_full_user(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let target = match self.resolve_input_user(ctx, r) {
            Ok(Some(u)) => u,
            Ok(None) => match &ctx.user {
                Some(u) => u.clone(),
                None => return rpc_error(400, "USER_ID_INVALID"),
            },
            Err(_) => return rpc_error(400, "USER_ID_INVALID"),
        };
        let self_id = ctx.user.as_ref().map(|u| u.id);

        let mut w = Writer::new();
        w.write_u32(USERS_USER_FULL);
        // TL_userFull#7fe738c4
        w.write_u32(USER_FULL);
        let full_flags = (1 << 4) | (1 << 7) | (1 << 13); // phone_calls_available | can_pin_message | video_calls_available
        w.write_i32(full_flags);
        w.write_i32(0); // flags2
        w.write_i64(target.id);
        // PeerSettings#f47741f7
        w.write_u32(PEER_SETTINGS);
        w.write_i32(0);
        // PeerNotifySettings#99622c0c
        w.write_u32(PEER_NOTIFY_SETTINGS);
        w.write_i32(0);
        w.write_i32(0); // common_chats_count
        w.write_vector_header(0); // chats
        w.write_vector_header(1); // users
        w.write_raw(&encode_user_for_viewer(&target, self_id));
        w.into_vec()
    }

    /// `stories.getPeerStories#2c4ada50 peer:InputPeer = stories.PeerStories`
    fn stories_peer_stories_empty(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let self_id = ctx.user.as_ref().map(|u| u.id);
        let peer_bytes = match read_input_peer(r, self_id) {
            Ok(Some(pb)) => pb,
            _ => encode_peer_user(self_id.unwrap_or(0)),
        };
        let mut w = Writer::new();
        w.write_u32(STORIES_PEER_STORIES);
        w.write_u32(PEER_STORIES);
        w.write_i32(0); // flags
        w.write_raw(&peer_bytes);
        w.write_vector_header(0); // stories
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }
}

fn encode_sent_code(hash: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(AUTH_SENT_CODE);
    w.write_i32(0); // flags
    w.write_u32(AUTH_SENT_CODE_TYPE_APP); // type
    w.write_i32(5); // code length (5 digits)
    w.write_string(hash);
    w.into_vec()
}

fn empty_ctor(ctor: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(ctor);
    w.into_vec()
}

fn empty_vector() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_vector_header(0);
    w.into_vec()
}

fn nearest_dc(dc: &DcEndpoint) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(NEAREST_DC);
    w.write_string("RU");
    w.write_i32(dc.dc_id);
    w.write_i32(dc.dc_id);
    w.into_vec()
}

/// `help.getCountriesList#735787a8 lang_code:string hash:int = help.CountriesList`
///
/// Important: Android `LoginActivity.loadCountries()` sends `hash = 0` and
/// casts the response directly to `TL_help_countriesList` without checking for
/// `TL_help_countriesListNotModified`! Always return the full `TL_help_countriesList`
/// unless `hash` matches `COUNTRIES_HASH`.
fn countries_list(r: &mut Reader) -> Vec<u8> {
    let _lang_code = r.read_string();
    let hash = r.read_i32().unwrap_or(0);
    if hash != 0 && hash == COUNTRIES_HASH {
        return empty_ctor(HELP_COUNTRIES_LIST_NOT_MODIFIED);
    }

    const RAW_COUNTRIES: &str = include_str!("countries.txt");
    let rows: Vec<(&str, &str, &str, Option<&str>)> = RAW_COUNTRIES
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.splitn(4, ';');
            let code = parts.next()?;
            let iso2 = parts.next()?;
            let name = parts.next()?;
            let pattern = parts.next().filter(|p| !p.is_empty());
            Some((code, iso2, name, pattern))
        })
        .collect();

    let mut w = Writer::new();
    w.write_u32(HELP_COUNTRIES_LIST);
    w.write_vector_header(rows.len());
    for (code, iso2, default_name, pattern) in rows {
        // TL_help_country#c3878e23 flags:# hidden:flags.0?true iso2:string default_name:string name:flags.1?string country_codes:Vector<help.CountryCode>
        w.write_u32(HELP_COUNTRY);
        w.write_i32(0); // flags (not hidden, localized name omitted -> client uses default_name)
        w.write_string(iso2);
        w.write_string(default_name);
        w.write_vector_header(1);
        // TL_help_countryCode#4203c5ef flags:# country_code:string prefixes:flags.0?Vector<string> patterns:flags.1?Vector<string>
        w.write_u32(HELP_COUNTRY_CODE);
        if let Some(pat) = pattern {
            w.write_i32(1 << 1); // FLAG_1: patterns present
            w.write_string(code);
            w.write_vector_header(1);
            w.write_string(pat);
        } else {
            w.write_i32(0);
            w.write_string(code);
        }
    }
    w.write_i32(COUNTRIES_HASH);
    w.into_vec()
}

fn app_config() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(HELP_APP_CONFIG);
    w.write_i32(1); // hash
    w.write_u32(JSON_OBJECT);
    w.write_vector_header(0);
    w.into_vec()
}

fn terms_of_service_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(HELP_TERMS_OF_SERVICE_UPDATE_EMPTY);
    w.write_i32(now_unix() + 86_400);
    w.into_vec()
}

fn promo_data_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(HELP_PROMO_DATA_EMPTY);
    w.write_i32(now_unix() + 86_400);
    w.into_vec()
}

fn langpack_get_lang_pack(r: &mut Reader) -> Vec<u8> {
    let _lang_pack = r.read_string().unwrap_or("");
    let lang_code = r.read_string().unwrap_or("en").to_string();
    encode_langpack_difference(&lang_code, 0, 0)
}

fn langpack_get_difference(r: &mut Reader) -> Vec<u8> {
    let _lang_pack = r.read_string().unwrap_or("");
    let lang_code = r.read_string().unwrap_or("en").to_string();
    let from_version = r.read_i32().unwrap_or(0);
    encode_langpack_difference(&lang_code, from_version, from_version)
}

fn encode_langpack_difference(lang_code: &str, from_version: i32, version: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(LANGPACK_DIFFERENCE);
    w.write_string(lang_code);
    w.write_i32(from_version);
    w.write_i32(version);
    w.write_vector_header(0); // strings
    w.into_vec()
}

fn messages_dialog_filters_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(MESSAGES_DIALOG_FILTERS);
    w.write_i32(0); // flags
    w.write_vector_header(0); // filters
    w.into_vec()
}

fn gunzip_bounded(packed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut dec = GzDecoder::new(packed).take((MAX_GZIP_UNPACKED_LEN + 1) as u64);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    if out.len() > MAX_GZIP_UNPACKED_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "gzip payload exceeds limit",
        ));
    }
    Ok(out)
}

fn encode_peer_user(uid: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PEER_USER);
    w.write_i64(uid);
    w.into_vec()
}

fn read_input_peer(r: &mut Reader, self_id: Option<i64>) -> Result<Option<Vec<u8>>, TlError> {
    let ctor = r.read_u32()?;
    match ctor {
        INPUT_PEER_EMPTY => Ok(None),
        INPUT_PEER_SELF => Ok(Some(encode_peer_user(self_id.unwrap_or(0)))),
        INPUT_PEER_USER => {
            let uid = r.read_i64()?;
            let _access_hash = r.read_i64()?;
            Ok(Some(encode_peer_user(uid)))
        }
        INPUT_PEER_USER_LAYER131 => {
            let uid = r.read_i32()? as i64;
            let _access_hash = r.read_i64()?;
            Ok(Some(encode_peer_user(uid)))
        }
        INPUT_PEER_CHAT => {
            let chat_id = r.read_i64()?;
            let mut w = Writer::new();
            w.write_u32(PEER_CHAT);
            w.write_i64(chat_id);
            Ok(Some(w.into_vec()))
        }
        INPUT_PEER_CHAT_LAYER131 => {
            let chat_id = r.read_i32()? as i64;
            let mut w = Writer::new();
            w.write_u32(PEER_CHAT);
            w.write_i64(chat_id);
            Ok(Some(w.into_vec()))
        }
        INPUT_PEER_CHANNEL => {
            let channel_id = r.read_i64()?;
            let _access_hash = r.read_i64()?;
            let mut w = Writer::new();
            w.write_u32(PEER_CHANNEL);
            w.write_i64(channel_id);
            Ok(Some(w.into_vec()))
        }
        INPUT_PEER_CHANNEL_LAYER131 => {
            let channel_id = r.read_i32()? as i64;
            let _access_hash = r.read_i64()?;
            let mut w = Writer::new();
            w.write_u32(PEER_CHANNEL);
            w.write_i64(channel_id);
            Ok(Some(w.into_vec()))
        }
        INPUT_PEER_USER_FROM_MESSAGE => {
            let _ = read_input_peer(r, self_id)?;
            let _msg_id = r.read_i32()?;
            let uid = r.read_i64()?;
            Ok(Some(encode_peer_user(uid)))
        }
        INPUT_PEER_CHANNEL_FROM_MESSAGE => {
            let _ = read_input_peer(r, self_id)?;
            let _msg_id = r.read_i32()?;
            let channel_id = r.read_i64()?;
            let mut w = Writer::new();
            w.write_u32(PEER_CHANNEL);
            w.write_i64(channel_id);
            Ok(Some(w.into_vec()))
        }
        other => Err(TlError::UnknownConstructor {
            id: other,
            context: "InputPeer",
        }),
    }
}

/// `messages.getAllStickers` / `getEmojiStickers` / `getMaskStickers`
fn messages_all_stickers(r: &mut Reader) -> Vec<u8> {
    let hash = r.read_i64().unwrap_or(0);
    if hash == 1 {
        return empty_ctor(MESSAGES_ALL_STICKERS_NOT_MODIFIED);
    }
    let mut w = Writer::new();
    w.write_u32(MESSAGES_ALL_STICKERS);
    w.write_i64(1); // hash
    w.write_vector_header(0); // sets
    w.into_vec()
}

/// `messages.getFeaturedStickers` / `getFeaturedEmojiStickers`
fn messages_featured_stickers(r: &mut Reader) -> Vec<u8> {
    let hash = r.read_i64().unwrap_or(0);
    if hash == 1 {
        let mut w = Writer::new();
        w.write_u32(MESSAGES_FEATURED_STICKERS_NOT_MODIFIED);
        w.write_i32(0); // count
        return w.into_vec();
    }
    let mut w = Writer::new();
    w.write_u32(MESSAGES_FEATURED_STICKERS);
    w.write_i32(0); // flags
    w.write_i64(1); // hash
    w.write_i32(0); // count
    w.write_vector_header(0); // sets
    w.write_vector_header(0); // unread
    w.into_vec()
}

/// `messages.getArchivedStickers` -> `TL_messages_archivedStickers#4fcba9c8`
fn messages_archived_stickers() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(MESSAGES_ARCHIVED_STICKERS);
    w.write_i32(0); // count
    w.write_vector_header(0); // sets
    w.into_vec()
}

fn encode_empty_sticker_set(id: i64, short_name: &str, title: &str, is_emojis: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(MESSAGES_STICKER_SET);
    w.write_u32(STICKER_SET);
    let mut flags = 1 << 2; // official
    if is_emojis {
        flags |= 1 << 7; // emojis
    }
    w.write_i32(flags);
    w.write_i64(id);
    w.write_i64(id.wrapping_mul(0x517c_c1b7_2722_0a95));
    w.write_string(title);
    w.write_string(short_name);
    w.write_i32(0); // count
    w.write_i32(1); // hash
    w.write_vector_header(0); // packs
    w.write_vector_header(0); // keywords
    w.write_vector_header(0); // documents
    w.into_vec()
}

/// `messages.getStickerSet#c8a0ec74 stickerset:InputStickerSet hash:int = messages.StickerSet`
/// Never returns `TL_messages_stickerSetNotModified` when `set` fields are accessed
/// (`TL_messages_stickerSetNotModified` subclasses `TL_messages_stickerSet` in Java with `set == null`!).
fn messages_get_sticker_set(r: &mut Reader) -> Vec<u8> {
    let Ok(ctor) = r.read_u32() else {
        return rpc_error(400, "STICKERSET_INVALID");
    };
    match ctor {
        INPUT_STICKER_SET_ANIMATED_EMOJI => {
            encode_empty_sticker_set(1001, "AnimatedEmoji", "Animated Emoji", true)
        }
        INPUT_STICKER_SET_EMOJI_GENERIC_ANIMATIONS => {
            encode_empty_sticker_set(1002, "EmojiAnimations", "Emoji Animations", false)
        }
        INPUT_STICKER_SET_EMOJI_DEFAULT_TOPIC_ICONS => {
            encode_empty_sticker_set(1003, "TopicIcons", "Topic Icons", true)
        }
        INPUT_STICKER_SET_PREMIUM_GIFTS => {
            encode_empty_sticker_set(1004, "PremiumGifts", "Premium Gifts", false)
        }
        INPUT_STICKER_SET_TON_GIFTS => encode_empty_sticker_set(1005, "TonGifts", "Gifts", false),
        INPUT_STICKER_SET_EMOJI_DEFAULT_STATUSES => {
            encode_empty_sticker_set(1006, "DefaultStatuses", "Statuses", true)
        }
        INPUT_STICKER_SET_EMOJI_CHANNEL_DEFAULT_STATUSES => {
            encode_empty_sticker_set(1007, "ChannelStatuses", "Channel Statuses", true)
        }
        INPUT_STICKER_SET_DICE => {
            let emoticon = r.read_string().unwrap_or("🎲");
            encode_empty_sticker_set(1008, "Dice", emoticon, false)
        }
        INPUT_STICKER_SET_DICE_LAYER111 => encode_empty_sticker_set(1008, "Dice", "Dice", false),
        INPUT_STICKER_SET_SHORT_NAME => {
            let name = r.read_string().unwrap_or("");
            match name {
                "AnimatedEmoji" => {
                    encode_empty_sticker_set(1001, "AnimatedEmoji", "Animated Emoji", true)
                }
                "EmojiAnimations" => {
                    encode_empty_sticker_set(1002, "EmojiAnimations", "Emoji Animations", false)
                }
                "TopicIcons" => encode_empty_sticker_set(1003, "TopicIcons", "Topic Icons", true),
                "PremiumGifts" => {
                    encode_empty_sticker_set(1004, "PremiumGifts", "Premium Gifts", false)
                }
                "TonGifts" => encode_empty_sticker_set(1005, "TonGifts", "Gifts", false),
                "DefaultStatuses" => {
                    encode_empty_sticker_set(1006, "DefaultStatuses", "Statuses", true)
                }
                "ChannelStatuses" => {
                    encode_empty_sticker_set(1007, "ChannelStatuses", "Channel Statuses", true)
                }
                "Dice" | "android_elli" => encode_empty_sticker_set(1008, name, name, false),
                _ => rpc_error(400, "STICKERSET_INVALID"),
            }
        }
        INPUT_STICKER_SET_ID => {
            let id = r.read_i64().unwrap_or(0);
            let _access_hash = r.read_i64();
            match id {
                1001 => encode_empty_sticker_set(1001, "AnimatedEmoji", "Animated Emoji", true),
                1002 => {
                    encode_empty_sticker_set(1002, "EmojiAnimations", "Emoji Animations", false)
                }
                1003 => encode_empty_sticker_set(1003, "TopicIcons", "Topic Icons", true),
                1004 => encode_empty_sticker_set(1004, "PremiumGifts", "Premium Gifts", false),
                1005 => encode_empty_sticker_set(1005, "TonGifts", "Gifts", false),
                1006 => encode_empty_sticker_set(1006, "DefaultStatuses", "Statuses", true),
                1007 => {
                    encode_empty_sticker_set(1007, "ChannelStatuses", "Channel Statuses", true)
                }
                1008 => encode_empty_sticker_set(1008, "Dice", "Dice", false),
                _ => rpc_error(400, "STICKERSET_INVALID"),
            }
        }
        INPUT_STICKER_SET_EMPTY => rpc_error(400, "STICKERSET_INVALID"),
        _ => rpc_error(400, "STICKERSET_INVALID"),
    }
}

fn messages_saved_gifs(r: &mut Reader) -> Vec<u8> {
    let hash = r.read_i64().unwrap_or(0);
    if hash == 1 {
        return empty_ctor(MESSAGES_SAVED_GIFS_NOT_MODIFIED);
    }
    let mut w = Writer::new();
    w.write_u32(MESSAGES_SAVED_GIFS);
    w.write_i64(1); // hash
    w.write_vector_header(0); // gifs
    w.into_vec()
}

/// `messages.getSearchCounters#1bbcf300` -> `Vector<messages.SearchCounter#e844ebff>`
fn messages_get_search_counters(r: &mut Reader) -> Vec<u8> {
    let Ok(flags) = r.read_i32() else {
        return empty_vector();
    };
    if read_input_peer(r, None).is_err() {
        return empty_vector();
    }
    if flags & (1 << 2) != 0 && read_input_peer(r, None).is_err() {
        return empty_vector();
    }
    if flags & 1 != 0 && r.read_i32().is_err() {
        return empty_vector();
    }
    let Ok(count) = r.read_vector_header() else {
        return empty_vector();
    };
    let mut filters: Vec<(u32, Option<i32>)> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Ok(f_ctor) = r.read_u32() else {
            break;
        };
        let extra = if f_ctor == INPUT_MESSAGES_FILTER_PHONE_CALLS {
            Some(r.read_i32().unwrap_or(0))
        } else {
            None
        };
        filters.push((f_ctor, extra));
    }
    let mut w = Writer::new();
    w.write_vector_header(filters.len());
    for (f_ctor, extra) in filters {
        w.write_u32(MESSAGES_SEARCH_COUNTER);
        w.write_i32(0); // flags
        w.write_u32(f_ctor);
        if let Some(f_flags) = extra {
            w.write_i32(f_flags);
        }
        w.write_i32(0); // count
    }
    w.into_vec()
}

fn messages_search_results_positions() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(MESSAGES_SEARCH_RESULTS_POSITIONS);
    w.write_i32(0); // count
    w.write_vector_header(0); // positions
    w.into_vec()
}

fn messages_attach_menu_bots(r: &mut Reader) -> Vec<u8> {
    let hash = r.read_i64().unwrap_or(0);
    if hash == 1 {
        return empty_ctor(ATTACH_MENU_BOTS_NOT_MODIFIED);
    }
    let mut w = Writer::new();
    w.write_u32(ATTACH_MENU_BOTS);
    w.write_i64(1); // hash
    w.write_vector_header(0); // bots
    w.write_vector_header(0); // users
    w.into_vec()
}

fn default_history_ttl() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(DEFAULT_HISTORY_TTL);
    w.write_i32(0); // period
    w.into_vec()
}

fn peer_notify_settings_default() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PEER_NOTIFY_SETTINGS);
    w.write_i32(0); // flags
    w.into_vec()
}

/// `account.getPassword#548a30f5 = account.Password#957b50fb`
fn account_get_password() -> Vec<u8> {
    let dh_params = dh::server_default();
    let mut rng = rand::thread_rng();
    let mut salt1 = [0u8; 8];
    let mut salt2 = [0u8; 16];
    let mut sec_salt = [0u8; 8];
    let mut secure_random = [0u8; 32];
    rng.fill_bytes(&mut salt1);
    rng.fill_bytes(&mut salt2);
    rng.fill_bytes(&mut sec_salt);
    rng.fill_bytes(&mut secure_random);

    let mut w = Writer::new();
    w.write_u32(ACCOUNT_PASSWORD);
    w.write_i32(0); // flags (has_password = false)
    // new_algo: TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow#3a912d4a
    w.write_u32(PASSWORD_KDF_ALGO_MODPOW);
    w.write_bytes(&salt1);
    w.write_bytes(&salt2);
    w.write_i32(dh_params.g as i32);
    w.write_bytes(&dh_params.prime_be());
    // new_secure_algo: TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000#bbf2dda0
    w.write_u32(SECURE_PASSWORD_KDF_ALGO_PBKDF2);
    w.write_bytes(&sec_salt);
    w.write_bytes(&secure_random);
    w.into_vec()
}

fn account_privacy_rules_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(ACCOUNT_PRIVACY_RULES);
    w.write_vector_header(0); // rules
    w.write_vector_header(0); // chats
    w.write_vector_header(0); // users
    w.into_vec()
}

fn global_privacy_settings_default() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(GLOBAL_PRIVACY_SETTINGS);
    w.write_i32(0); // flags
    w.into_vec()
}

fn account_content_settings_default() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(ACCOUNT_CONTENT_SETTINGS);
    w.write_i32(0); // flags
    w.into_vec()
}

fn account_authorizations_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(ACCOUNT_AUTHORIZATIONS);
    w.write_i32(180); // authorization_ttl_days
    w.write_vector_header(0); // authorizations
    w.into_vec()
}

fn payments_saved_star_gifts_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PAYMENTS_SAVED_STAR_GIFTS);
    w.write_i32(0); // flags
    w.write_i32(0); // count
    w.write_vector_header(0); // gifts
    w.write_vector_header(0); // chats
    w.write_vector_header(0); // users
    w.into_vec()
}

fn payments_stars_status_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PAYMENTS_STARS_STATUS);
    w.write_i32(0); // flags
    w.write_u32(STARS_AMOUNT);
    w.write_i64(0); // amount
    w.write_i32(0); // nanos
    w.write_vector_header(0); // chats
    w.write_vector_header(0); // users
    w.into_vec()
}

fn stories_all_stories_not_modified() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(STORIES_ALL_STORIES_NOT_MODIFIED);
    w.write_i32(0); // flags
    w.write_string("0"); // state
    w.write_u32(STORIES_STEALTH_MODE);
    w.write_i32(0); // stealth flags
    w.into_vec()
}

fn cdn_config_empty() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(CDN_CONFIG);
    w.write_vector_header(0); // public_keys: Vector<CdnPublicKey>
    w.into_vec()
}

/// A bare Bool result.
fn bool_result(v: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_bool(v);
    w.into_vec()
}

/// Skip one serialized TL `JSONValue` in `initConnection.params`.
fn skip_json_value(r: &mut Reader, depth: usize) -> Result<(), TlError> {
    if depth > 32 {
        return Err(TlError::UnknownConstructor {
            id: 0,
            context: "JSONValue depth limit",
        });
    }
    let id = r.read_u32()?;
    match id {
        JSON_NULL => Ok(()),
        JSON_BOOL => {
            let _ = r.read_bool()?;
            Ok(())
        }
        JSON_NUMBER => {
            let _ = r.read_f64()?;
            Ok(())
        }
        JSON_STRING => {
            let _ = r.read_string()?;
            Ok(())
        }
        JSON_ARRAY => {
            let count = r.read_vector_header()?;
            for _ in 0..count {
                skip_json_value(r, depth + 1)?;
            }
            Ok(())
        }
        JSON_OBJECT => {
            let count = r.read_vector_header()?;
            for _ in 0..count {
                let elem_id = r.read_u32()?;
                if elem_id != JSON_OBJECT_VALUE {
                    return Err(TlError::UnknownConstructor {
                        id: elem_id,
                        context: "jsonObjectValue",
                    });
                }
                let _key = r.read_string()?;
                skip_json_value(r, depth + 1)?;
            }
            Ok(())
        }
        other => Err(TlError::UnknownConstructor {
            id: other,
            context: "JSONValue",
        }),
    }
}

/// Peel `invokeWithLayer`, `initConnection` (including `proxy` and `JSONValue`
/// `params`), `invokeAfterMsg*`, and Play Integrity / ReCaptcha wrappers,
/// returning the inner query bytes (including its constructor id).
fn peel_wrappers_ctx(
    mut id: u32,
    r: &mut Reader,
    ctx: &mut ConnContext,
    mut depth: u8,
) -> Result<Vec<u8>, TlError> {
    loop {
        if depth > 16 {
            return Err(TlError::WrapperDepthExceeded { max_depth: 16 });
        }
        depth += 1;
        match id {
            INVOKE_WITH_LAYER => {
                let layer = r.read_i32()?;
                if (1..=1000).contains(&layer) {
                    ctx.negotiated_layer = layer as u16;
                }
            }
            INVOKE_AFTER_MSG => {
                let _after = r.read_i64()?;
            }
            INVOKE_AFTER_MSGS => {
                let _after = r.read_long_vector()?;
            }
            INVOKE_WITHOUT_UPDATES => {}
            INVOKE_WITH_MESSAGES_RANGE => {
                // MessageRange#0ae30253 { min_id:int max_id:int }
                let _range_ctor = r.read_u32()?;
                let _min_id = r.read_i32()?;
                let _max_id = r.read_i32()?;
            }
            INVOKE_WITH_TAKEOUT => {
                let _takeout_id = r.read_i64()?;
            }
            INVOKE_WITH_BUSINESS_CONNECTION => {
                let _connection_id = r.read_string()?;
            }
            INVOKE_WITH_GOOGLE_PLAY_INTEGRITY | INVOKE_WITH_APNS_SECRET => {
                let _nonce = r.read_string()?;
                let _token = r.read_string()?;
            }
            INVOKE_WITH_RECAPTCHA => {
                let _token = r.read_string()?;
            }
            GZIP_PACKED => {
                let packed = r.read_bytes()?;
                let unpacked = gunzip_bounded(packed).map_err(|_| TlError::InvalidPadding)?;
                let mut ur = Reader::new(&unpacked);
                let inner_id = ur.read_u32()?;
                return peel_wrappers_ctx(inner_id, &mut ur, ctx, depth);
            }
            INIT_CONNECTION => {
                let flags = r.read_i32()?;
                let _api_id = r.read_i32()?;
                let device_model = r.read_string()?;
                let _system_version = r.read_string()?;
                let app_version = r.read_string()?;
                let _system_lang_code = r.read_string()?;
                let _lang_pack = r.read_string()?;
                let _lang_code = r.read_string()?;
                if !device_model.is_empty() {
                    ctx.device_model = device_model.to_string();
                }
                if !app_version.is_empty() {
                    ctx.app_version = app_version.to_string();
                }
                if flags & 1 != 0 {
                    let proxy_id = r.read_u32()?;
                    if proxy_id != INPUT_CLIENT_PROXY {
                        return Err(TlError::UnknownConstructor {
                            id: proxy_id,
                            context: "initConnection.proxy",
                        });
                    }
                    let _address = r.read_string()?;
                    let _port = r.read_i32()?;
                }
                if flags & 2 != 0 {
                    skip_json_value(r, 0)?;
                }
            }
            _ => {
                let rest = r.read_raw(r.remaining())?;
                let mut q = Vec::with_capacity(4 + rest.len());
                q.extend_from_slice(&id.to_le_bytes());
                q.extend_from_slice(rest);
                return Ok(q);
            }
        }
        id = r.read_u32()?;
    }
}

/// `rpc_result req_msg_id:long result:Object`.
pub fn rpc_result(req_msg_id: i64, result: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(RPC_RESULT);
    w.write_i64(req_msg_id);
    w.write_raw(result);
    w.into_vec()
}

/// `rpc_error error_code:int error_message:string`.
pub fn rpc_error(code: i32, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(RPC_ERROR);
    w.write_i32(code);
    w.write_string(message);
    w.into_vec()
}

/// `pong msg_id:long ping_id:long`.
fn pong(msg_id: i64, ping_id: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PONG);
    w.write_i64(msg_id);
    w.write_i64(ping_id);
    w.into_vec()
}

/// `future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt>`
/// Note: in MTProto `future_salts`, `salts` is a bare `vector` (count only, no
/// `0x1cb5c415` header, and bare `future_salt` items without constructor id),
/// verified against `TL_future_salts::readParams` in `MTProtoScheme.cpp`.
fn future_salts(req_msg_id: i64, salt: i64, count: usize) -> Vec<u8> {
    let now = now_unix();
    let n = count.clamp(1, 16);
    let mut w = Writer::new();
    w.write_u32(FUTURE_SALTS);
    w.write_i64(req_msg_id);
    w.write_i32(now);
    w.write_u32(n as u32);
    for i in 0..n {
        let valid_since = now - 60 + (i as i32) * 1800;
        let valid_until = valid_since + 3600;
        w.write_i32(valid_since);
        w.write_i32(valid_until);
        w.write_i64(salt);
    }
    w.into_vec()
}

fn destroy_session_ok(session_id: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(DESTROY_SESSION_OK);
    w.write_i64(session_id);
    w.into_vec()
}

fn rpc_answer_unknown() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(RPC_ANSWER_UNKNOWN);
    w.into_vec()
}

fn msgs_state_info(req_msg_id: i64, count: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(MSGS_STATE_INFO);
    w.write_i64(req_msg_id);
    w.write_bytes(&vec![4u8; count]); // 4 = received & processed
    w.into_vec()
}

/// `auth.authorization flags:# user:User` (minimal: flags = 0).
fn authorization(user: &User) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(AUTH_AUTHORIZATION);
    w.write_i32(0); // flags
    w.write_raw(&encode_user(user));
    w.into_vec()
}

/// Encode `TL_user#b1b8cc83` for the authenticated user (`self = true`).
fn encode_user(user: &User) -> Vec<u8> {
    encode_user_for_viewer(user, Some(user.id))
}

/// Encode `TL_user#b1b8cc83`, setting `FLAG_10` (`self`) only when `user.id`
/// matches the viewer's `self_id`.
fn encode_user_for_viewer(user: &User, self_id: Option<i64>) -> Vec<u8> {
    const FLAG_0: i32 = 1 << 0; // access_hash
    const FLAG_1: i32 = 1 << 1; // first_name
    const FLAG_2: i32 = 1 << 2; // last_name
    const FLAG_4: i32 = 1 << 4; // phone
    const FLAG_10: i32 = 1 << 10; // self (bitflag only, no extra bytes)
    let include_last = !user.last_name.is_empty() && user.last_name != "User";
    let mut flags = FLAG_0 | FLAG_1 | FLAG_4;
    if Some(user.id) == self_id {
        flags |= FLAG_10;
    }
    if include_last {
        flags |= FLAG_2;
    }
    let mut w = Writer::new();
    w.write_u32(USER);
    w.write_i32(flags);
    w.write_i32(0); // flags2
    w.write_i64(user.id);
    w.write_i64(user.access_hash); // FLAG_0
    w.write_string(&user.first_name); // FLAG_1
    if include_last {
        w.write_string(&user.last_name); // FLAG_2
    }
    w.write_string(&user.phone); // FLAG_4
    w.into_vec()
}

/// Encode a valid `config#cc1a241e` advertising DCs 1..3 at the server endpoint
/// so client multi-DC slots (`initDatacenters`) all point to ShuzaGram.
fn config(dc: &DcEndpoint) -> Vec<u8> {
    let now = now_unix();
    let mut w = Writer::new();
    w.write_u32(CONFIG);
    w.write_i32(0); // flags
    w.write_i32(now); // date
    w.write_i32(now + 3600); // expires
    w.write_bool(false); // test_mode
    w.write_i32(dc.dc_id); // this_dc
    // Advertise DCs 1, 2, 3 (plus dc.dc_id if outside 1..=3) all pointing here.
    let mut dc_ids = vec![1, 2, 3];
    if !dc_ids.contains(&dc.dc_id) {
        dc_ids.push(dc.dc_id);
    }
    w.write_vector_header(dc_ids.len());
    for id in dc_ids {
        encode_dc_option(
            &mut w,
            &DcEndpoint {
                dc_id: id,
                ip: dc.ip.clone(),
                port: dc.port,
            },
        );
    }
    w.write_string(""); // dc_txt_domain_name
    for v in [
        200,      // chat_size_max
        200000,   // megagroup_size_max
        100,      // forwarded_count_max
        120000,   // online_update_period_ms
        30000,    // offline_blur_timeout_ms
        30000,    // offline_idle_timeout_ms
        300000,   // online_cloud_timeout_ms
        30000,    // notify_cloud_delay_ms
        90000,    // notify_default_delay_ms
        60000,    // push_chat_period_ms
        10,       // push_chat_limit
        172800,   // edit_time_limit
        172800,   // revoke_time_limit
        172800,   // revoke_pm_time_limit
        2419200,  // rating_e_decay
        20,       // stickers_recent_limit
        92233720, // channels_read_media_period
    ] {
        w.write_i32(v);
    }
    for v in [
        20000, // call_receive_timeout_ms
        90000, // call_ring_timeout_ms
        30000, // call_connect_timeout_ms
        10000, // call_packet_timeout_ms
    ] {
        w.write_i32(v);
    }
    w.write_string("https://shuzagram.com/"); // me_url_prefix
    w.write_i32(2048); // caption_length_max
    w.write_i32(4096); // message_length_max
    w.write_i32(dc.dc_id); // webfile_dc_id
    w.into_vec()
}

fn encode_dc_option(w: &mut Writer, dc: &DcEndpoint) {
    w.write_u32(DC_OPTION);
    w.write_i32(0); // flags
    w.write_i32(dc.dc_id); // id
    w.write_string(&dc.ip); // ip_address
    w.write_i32(dc.port); // port
}

fn now_unix() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i32)
        .unwrap_or(0)
}

#[cfg(test)]
mod decode_helpers {
    use super::*;

    /// Decode the minimal auth.sentCode -> phone_code_hash (test helper).
    pub fn decode_sent_code(result: &[u8]) -> String {
        let mut r = Reader::new(result);
        assert_eq!(r.read_u32().unwrap(), AUTH_SENT_CODE);
        let _flags = r.read_i32().unwrap();
        assert_eq!(r.read_u32().unwrap(), AUTH_SENT_CODE_TYPE_APP);
        let _len = r.read_i32().unwrap();
        r.read_string().unwrap().to_string()
    }

    /// Decode auth.authorization -> User, mirroring the client's TL_user layout.
    pub fn decode_authorization(result: &[u8]) -> User {
        let mut r = Reader::new(result);
        assert_eq!(r.read_u32().unwrap(), AUTH_AUTHORIZATION);
        let _flags = r.read_i32().unwrap();
        assert_eq!(r.read_u32().unwrap(), USER);
        let flags = r.read_i32().unwrap();
        let _flags2 = r.read_i32().unwrap();
        let id = r.read_i64().unwrap();
        let access_hash = if flags & (1 << 0) != 0 {
            r.read_i64().unwrap()
        } else {
            0
        };
        let first_name = if flags & (1 << 1) != 0 {
            r.read_string().unwrap().to_string()
        } else {
            String::new()
        };
        let last_name = if flags & (1 << 2) != 0 {
            r.read_string().unwrap().to_string()
        } else {
            String::new()
        };
        let phone = if flags & (1 << 4) != 0 {
            r.read_string().unwrap().to_string()
        } else {
            String::new()
        };
        User {
            id,
            home_dc_id: 2,
            phone,
            username: None,
            first_name,
            last_name,
            bio: String::new(),
            flags_bitmask: 0,
            photo_id: None,
            photo_dc_id: None,
            access_hash,
        }
    }

    pub fn is_rpc_error(result: &[u8]) -> Option<(i32, String)> {
        let mut r = Reader::new(result);
        if r.read_u32().ok()? != RPC_ERROR {
            return None;
        }
        let code = r.read_i32().ok()?;
        let msg = r.read_string().ok()?.to_string();
        Some((code, msg))
    }

    /// Unwrap rpc_result -> (req_msg_id, result bytes).
    pub fn unwrap_rpc_result(bytes: &[u8]) -> (i64, Vec<u8>) {
        let mut r = Reader::new(bytes);
        assert_eq!(r.read_u32().unwrap(), RPC_RESULT);
        let req = r.read_i64().unwrap();
        let rest = r.read_raw(r.remaining()).unwrap().to_vec();
        (req, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::decode_helpers::*;
    use super::*;

    fn invoke_with_layer(query: &[u8]) -> Vec<u8> {
        let mut inner = Writer::new();
        inner.write_u32(INIT_CONNECTION);
        inner.write_i32(0); // flags
        inner.write_i32(12345); // api_id
        for s in ["Pixel", "Android 14", "1.0", "en", "", "en"] {
            inner.write_string(s);
        }
        inner.write_raw(query);

        let mut w = Writer::new();
        w.write_u32(INVOKE_WITH_LAYER);
        w.write_i32(232);
        w.write_raw(&inner.into_vec());
        w.into_vec()
    }

    #[test]
    fn init_connection_with_json_params_and_proxy_unwraps() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        let mut q = Writer::new();
        q.write_u32(HELP_GET_NEAREST_DC);

        let mut inner = Writer::new();
        inner.write_u32(INIT_CONNECTION);
        inner.write_i32(1 | 2); // proxy + params:JSONValue
        inner.write_i32(12345);
        for s in ["Pixel 8", "SDK 34", "11.5.0", "ru", "android", "ru"] {
            inner.write_string(s);
        }
        // InputClientProxy
        inner.write_u32(INPUT_CLIENT_PROXY);
        inner.write_string("127.0.0.1");
        inner.write_i32(1080);
        // params: jsonObject { tz_offset: jsonNumber(10800), device_token: jsonString("abc") }
        inner.write_u32(JSON_OBJECT);
        inner.write_vector_header(2);
        inner.write_u32(JSON_OBJECT_VALUE);
        inner.write_string("tz_offset");
        inner.write_u32(JSON_NUMBER);
        inner.write_f64(10800.0);
        inner.write_u32(JSON_OBJECT_VALUE);
        inner.write_string("device_token");
        inner.write_u32(JSON_STRING);
        inner.write_string("abc");
        inner.write_raw(&q.into_vec());

        let mut w = Writer::new();
        w.write_u32(INVOKE_WITH_LAYER);
        w.write_i32(232);
        w.write_raw(&inner.into_vec());

        let mut ctx = ConnContext::default();
        let out = d.handle_message(&mut ctx, 42, &w.into_vec());
        let (_req, res) = unwrap_rpc_result(&out[0]);
        assert_eq!(Reader::new(&res).read_u32().unwrap(), NEAREST_DC);
    }

    #[test]
    fn help_get_countries_list_returns_full_list_when_hash_zero() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        let mut q = Writer::new();
        q.write_u32(HELP_GET_COUNTRIES_LIST);
        q.write_string("ru");
        q.write_i32(0); // hash = 0, as Android LoginActivity sends

        let mut ctx = ConnContext::default();
        let out = d.handle_message(&mut ctx, 43, &invoke_with_layer(&q.into_vec()));
        let (_req, res) = unwrap_rpc_result(&out[0]);

        let mut r = Reader::new(&res);
        assert_eq!(r.read_u32().unwrap(), HELP_COUNTRIES_LIST);
        let n = r.read_vector_header().unwrap();
        assert!(n >= 200, "expected full country list, got {n}");
        for _ in 0..n {
            assert_eq!(r.read_u32().unwrap(), HELP_COUNTRY);
            let cflags = r.read_i32().unwrap();
            let _iso2 = r.read_string().unwrap();
            let _def_name = r.read_string().unwrap();
            if cflags & (1 << 1) != 0 {
                let _name = r.read_string().unwrap();
            }
            let kc = r.read_vector_header().unwrap();
            for _ in 0..kc {
                assert_eq!(r.read_u32().unwrap(), HELP_COUNTRY_CODE);
                let kflags = r.read_i32().unwrap();
                let _code = r.read_string().unwrap();
                if kflags & (1 << 0) != 0 {
                    let pn = r.read_vector_header().unwrap();
                    for _ in 0..pn {
                        let _ = r.read_string().unwrap();
                    }
                }
                if kflags & (1 << 1) != 0 {
                    let pn = r.read_vector_header().unwrap();
                    for _ in 0..pn {
                        let _ = r.read_string().unwrap();
                    }
                }
            }
        }
        assert_eq!(r.read_i32().unwrap(), COUNTRIES_HASH);
        assert!(r.is_empty(), "countriesList must be consumed completely");
    }

    #[test]
    fn bind_temp_auth_key_unknown_perm_returns_encrypted_message_invalid() {
        let store = Arc::new(Store::new());
        let keys = Arc::new(KeyStore::load(None));
        let d = Dispatcher::new(store).with_keys(keys);

        let mut q = Writer::new();
        q.write_u32(AUTH_BIND_TEMP_AUTH_KEY);
        q.write_i64(0x2e9b_192a_1658_1256); // unknown stale perm key
        q.write_i64(12345);
        q.write_i32(1_900_000_000);
        q.write_bytes(&[0u8; 64]);

        let mut ctx = ConnContext {
            auth_key_id: 0x1111_2222_3333_4444,
            ..Default::default()
        };
        let out = d.handle_message(&mut ctx, 100, &q.into_vec());
        let (_req, res) = unwrap_rpc_result(&out[0]);
        assert_eq!(
            is_rpc_error(&res),
            Some((400, "ENCRYPTED_MESSAGE_INVALID".to_string()))
        );
    }

    #[test]
    fn bind_temp_auth_key_valid_v1_links_temp_to_perm() {
        let store = Arc::new(Store::new());
        let keys = Arc::new(KeyStore::load(None));

        let perm_key = [0x42u8; 256];
        let perm_id = kdf::auth_key_id(&perm_key);
        keys.insert(perm_id, perm_key, 99);

        let temp_key = [0x24u8; 256];
        let temp_id = kdf::auth_key_id(&temp_key);
        keys.insert(temp_id, temp_key, 77);

        let d = Dispatcher::new(Arc::clone(&store)).with_keys(Arc::clone(&keys));

        // Build bind_auth_key_inner#75a3f765 encrypted with MTProto 1.0 under perm_key.
        let nonce = 0x1234_5678_9abc_def0i64;
        let expires_at = 1_900_000_000i32;
        let mut inner = Writer::new();
        inner.write_u32(BIND_AUTH_KEY_INNER);
        inner.write_i64(nonce);
        inner.write_i64(temp_id);
        inner.write_i64(perm_id);
        inner.write_i64(0x5555);
        inner.write_i32(expires_at);
        let inner_bytes = inner.into_vec();

        let mut unpadded = Vec::new();
        unpadded.extend_from_slice(&1i64.to_le_bytes()); // rnd salt
        unpadded.extend_from_slice(&2i64.to_le_bytes()); // rnd session
        unpadded.extend_from_slice(&3i64.to_le_bytes()); // msg_id
        unpadded.extend_from_slice(&0i32.to_le_bytes()); // seq_no
        unpadded.extend_from_slice(&(inner_bytes.len() as u32).to_le_bytes());
        unpadded.extend_from_slice(&inner_bytes);

        let (msg_key, ct) =
            kdf::encrypt_message_v1(&perm_key, &unpadded, Direction::ClientToServer).unwrap();
        let mut enc_msg = Vec::new();
        enc_msg.extend_from_slice(&perm_id.to_le_bytes());
        enc_msg.extend_from_slice(&msg_key);
        enc_msg.extend_from_slice(&ct);

        let mut q = Writer::new();
        q.write_u32(AUTH_BIND_TEMP_AUTH_KEY);
        q.write_i64(perm_id);
        q.write_i64(nonce);
        q.write_i32(expires_at);
        q.write_bytes(&enc_msg);

        let mut ctx = ConnContext {
            auth_key_id: temp_id,
            ..Default::default()
        };
        let out = d.handle_message(&mut ctx, 101, &q.into_vec());
        let (_req, res) = unwrap_rpc_result(&out[0]);
        assert!(Reader::new(&res).read_bool().unwrap());
        assert_eq!(keys.resolve_perm(temp_id), perm_id);
    }

    #[test]
    fn ping_returns_pong_through_wrappers() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        let mut q = Writer::new();
        q.write_u32(PING);
        q.write_i64(0x1234);
        let msg = invoke_with_layer(&q.into_vec());

        let mut ctx = ConnContext::default();
        let out = d.handle_message_ex(&mut ctx, 777, &msg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, OutboundKind::Service);
        let mut r = Reader::new(&out[0].body);
        assert_eq!(r.read_u32().unwrap(), PONG);
        assert_eq!(r.read_i64().unwrap(), 777); // pong.msg_id = request msg_id
        assert_eq!(r.read_i64().unwrap(), 0x1234); // ping_id echoed
    }

    #[test]
    fn help_get_config_parses_exactly() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        let mut q = Writer::new();
        q.write_u32(HELP_GET_CONFIG);
        let mut ctx = ConnContext::default();
        let out = d.handle_message(&mut ctx, 5, &invoke_with_layer(&q.into_vec()));
        let (_req, result) = unwrap_rpc_result(&out[0]);

        let mut r = Reader::new(&result);
        assert_eq!(r.read_u32().unwrap(), CONFIG);
        assert_eq!(r.read_i32().unwrap(), 0); // flags
        let _date = r.read_i32().unwrap();
        let _expires = r.read_i32().unwrap();
        let _test_mode = r.read_bool().unwrap();
        let _this_dc = r.read_i32().unwrap();
        let n = r.read_vector_header().unwrap();
        assert_eq!(n, 3);
        for _ in 0..n {
            assert_eq!(r.read_u32().unwrap(), DC_OPTION);
            let _f = r.read_i32().unwrap();
            let _id = r.read_i32().unwrap();
            let _ip = r.read_string().unwrap();
            let _port = r.read_i32().unwrap();
        }
        let _dc_txt = r.read_string().unwrap();
        for _ in 0..17 {
            r.read_i32().unwrap();
        }
        for _ in 0..4 {
            r.read_i32().unwrap();
        }
        let _me_url = r.read_string().unwrap();
        let _caption = r.read_i32().unwrap();
        let _message = r.read_i32().unwrap();
        let _webfile = r.read_i32().unwrap();
        assert!(r.is_empty(), "config must be fully consumed (layout matches client)");
    }

    #[test]
    fn full_login_flow() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);
        let mut ctx = ConnContext::default();

        // 1) auth.sendCode
        let mut sc = Writer::new();
        sc.write_u32(AUTH_SEND_CODE);
        sc.write_string("+99900099999");
        sc.write_i32(12345);
        sc.write_string("apihash");
        let out = d.handle_message(&mut ctx, 10, &invoke_with_layer(&sc.into_vec()));
        let (req, result) = unwrap_rpc_result(&out[0]);
        assert_eq!(req, 10);
        let hash = decode_sent_code(&result);
        assert!(!hash.is_empty());

        // 2a) auth.signIn with the wrong code -> PHONE_CODE_INVALID
        let bad = build_sign_in("+99900099999", &hash, "00000");
        let out = d.handle_message(&mut ctx, 11, &invoke_with_layer(&bad));
        let (_, result) = unwrap_rpc_result(&out[0]);
        assert_eq!(is_rpc_error(&result).unwrap().1, "PHONE_CODE_INVALID");

        // 2b) auth.signIn with the correct code -> authorization + user
        let ok = build_sign_in("+99900099999", &hash, "22222");
        let out = d.handle_message(&mut ctx, 12, &invoke_with_layer(&ok));
        let (_, result) = unwrap_rpc_result(&out[0]);
        let user = decode_authorization(&result);
        assert_eq!(user.phone, "+99900099999");
        assert!(user.id >= 1000);

        // 3) post-login: the main screen RPCs must return valid objects.
        let mut q = Writer::new();
        q.write_u32(UPDATES_GET_STATE);
        let (_, result) = unwrap_rpc_result(&d.handle_message(&mut ctx, 13, &q.into_vec())[0]);
        assert_eq!(Reader::new(&result).read_u32().unwrap(), UPDATES_STATE);

        let mut q = Writer::new();
        q.write_u32(MESSAGES_GET_DIALOGS);
        let (_, result) = unwrap_rpc_result(&d.handle_message(&mut ctx, 14, &q.into_vec())[0]);
        let mut rr = Reader::new(&result);
        assert_eq!(rr.read_u32().unwrap(), MESSAGES_DIALOGS);
        for _ in 0..4 {
            assert_eq!(rr.read_vector_header().unwrap(), 0); // all empty
        }

        // users.getUsers returns the logged-in user from the connection context.
        let mut q = Writer::new();
        q.write_u32(USERS_GET_USERS);
        q.write_vector_header(1);
        q.write_u32(0xf7c1b13f); // inputUserSelf
        let (_, result) = unwrap_rpc_result(&d.handle_message(&mut ctx, 15, &q.into_vec())[0]);
        let mut rr = Reader::new(&result);
        assert_eq!(rr.read_vector_header().unwrap(), 1);
        assert_eq!(rr.read_u32().unwrap(), USER);

        // A msgs_ack produces no reply.
        let mut ack = Writer::new();
        ack.write_u32(MSGS_ACK);
        ack.write_long_vector(&[1, 2, 3]);
        assert!(d.handle_message(&mut ctx, 16, &ack.into_vec()).is_empty());
    }

    fn build_sign_in(phone: &str, hash: &str, code: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(AUTH_SIGN_IN);
        w.write_i32(1); // flags: has phone_code
        w.write_string(phone);
        w.write_string(hash);
        w.write_string(code);
        w.into_vec()
    }

    // --- end to end over the encrypted session ------------------------------
    use crate::session::Session;

    fn test_auth_key() -> [u8; 256] {
        let mut k = [0u8; 256];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        k
    }

    fn client_encrypt(
        key: &[u8; 256],
        salt: i64,
        session_id: i64,
        msg_id: i64,
        body: &[u8],
    ) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&salt.to_le_bytes());
        pt.extend_from_slice(&session_id.to_le_bytes());
        pt.extend_from_slice(&msg_id.to_le_bytes());
        pt.extend_from_slice(&0i32.to_le_bytes()); // seq_no
        pt.extend_from_slice(&(body.len() as u32).to_le_bytes());
        pt.extend_from_slice(body);
        let base = pt.len();
        let mut pad = 16 - (base % 16);
        if pad < 12 {
            pad += 16;
        }
        pt.resize(base + pad, 0);
        let (msg_key, ct) = kdf::encrypt_message(key, &pt, Direction::ClientToServer).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&kdf::auth_key_id(key).to_le_bytes());
        out.extend_from_slice(&msg_key);
        out.extend_from_slice(&ct);
        out
    }

    fn client_decrypt(key: &[u8; 256], payload: &[u8]) -> Vec<u8> {
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let pt = kdf::decrypt_message(key, &msg_key, &mut ct, Direction::ServerToClient).unwrap();
        let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
        pt[32..32 + length].to_vec()
    }

    #[test]
    fn encrypted_login_roundtrip() {
        let key = test_auth_key();
        let salt = 0x0102_0304_0506_0708;
        let session_id = 0x1111_2222_3333_4444;

        let store = Arc::new(Store::new());
        let dispatcher = Dispatcher::new(store);
        let mut server = Session::new(key, salt, session_id);

        let mut sc = Writer::new();
        sc.write_u32(AUTH_SEND_CODE);
        sc.write_string("+99900099999");
        sc.write_i32(12345);
        sc.write_string("apihash");
        let request_body = invoke_with_layer(&sc.into_vec());
        let client_msg_id = 0x6000_0000_0000_0004;
        let enc = client_encrypt(&key, salt, session_id, client_msg_id, &request_body);

        let incoming = server.decrypt(&enc).unwrap();
        assert_eq!(incoming.msg_id, client_msg_id);
        let mut ctx = ConnContext::default();
        let replies = dispatcher.handle_message(&mut ctx, incoming.msg_id, &incoming.body);
        assert_eq!(replies.len(), 1);
        let seq = server.next_content_seq();
        let reply_enc = server.encrypt(0x7000_0000_0000_0001, seq, &replies[0]);

        let reply_body = client_decrypt(&key, &reply_enc);
        let (req, result) = unwrap_rpc_result(&reply_body);
        assert_eq!(req, client_msg_id);
        let hash = decode_sent_code(&result);
        assert!(!hash.is_empty(), "got a phone_code_hash over the encrypted session");
    }

    #[test]
    fn post_login_rpcs_and_gzip_packed_work() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let store = Arc::new(Store::with_test_code(Some("12345".into())));
        let d = Dispatcher::new(store.clone());

        let alice = store.sign_up("88888888888", "h1", "Alice", "").unwrap();
        let bob = store.sign_up("88888888889", "h2", "Bob", "Builder").unwrap();

        let mut ctx = ConnContext {
            user: Some(alice.clone()),
            auth_key_id: 0x1111,
            session_id: 0x2222,
            server_salt: 0x3333,
            ..Default::default()
        };

        // 1. users.getUsers with [inputUserSelf, inputUser(bob)] -> self flag set ONLY on alice!
        let mut gu = Writer::new();
        gu.write_u32(USERS_GET_USERS);
        gu.write_vector_header(2);
        gu.write_u32(INPUT_USER_SELF);
        gu.write_u32(INPUT_USER);
        gu.write_i64(bob.id);
        gu.write_i64(bob.access_hash);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 100, &gu.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_vector_header().unwrap(), 2);
        assert_eq!(r.read_u32().unwrap(), USER);
        let alice_flags = r.read_i32().unwrap();
        assert_ne!(alice_flags & (1 << 10), 0, "viewer must have self flag");
        // Find Bob's constructor in remaining bytes:
        let rest = r.read_raw(r.remaining()).unwrap();
        let bob_pos = rest
            .windows(4)
            .position(|w| w == USER.to_le_bytes())
            .expect("second TL_user present");
        let bob_flags = i32::from_le_bytes(rest[bob_pos + 4..bob_pos + 8].try_into().unwrap());
        assert_eq!(bob_flags & (1 << 10), 0, "other user must NOT have self flag");

        // 2. users.getFullUser(inputUserSelf)
        let mut gfu = Writer::new();
        gfu.write_u32(USERS_GET_FULL_USER);
        gfu.write_u32(INPUT_USER_SELF);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 101, &gfu.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_u32().unwrap(), USERS_USER_FULL);
        assert_eq!(r.read_u32().unwrap(), USER_FULL);

        // 3. messages.getStickerSet(AnimatedEmoji) -> full TL_messages_stickerSet#6e153f16
        let mut gss = Writer::new();
        gss.write_u32(MESSAGES_GET_STICKER_SET);
        gss.write_u32(INPUT_STICKER_SET_ANIMATED_EMOJI);
        gss.write_i32(0);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 102, &gss.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_u32().unwrap(), MESSAGES_STICKER_SET);
        assert_eq!(r.read_u32().unwrap(), STICKER_SET);

        // Unknown custom stickerset -> STICKERSET_INVALID
        let mut gss_bad = Writer::new();
        gss_bad.write_u32(MESSAGES_GET_STICKER_SET);
        gss_bad.write_u32(INPUT_STICKER_SET_SHORT_NAME);
        gss_bad.write_string("nonexistent_custom_pack");
        gss_bad.write_i32(0);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 103, &gss_bad.into_vec())[0]);
        let mut er = Reader::new(&res);
        assert_eq!(er.read_u32().unwrap(), RPC_ERROR);
        assert_eq!(er.read_i32().unwrap(), 400);
        assert_eq!(er.read_string().unwrap(), "STICKERSET_INVALID");

        // 4. Featured / Emoji / Archived stickers hash transitions
        let mut gfs = Writer::new();
        gfs.write_u32(MESSAGES_GET_FEATURED_STICKERS);
        gfs.write_i64(0);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 104, &gfs.into_vec())[0]);
        assert_eq!(
            u32::from_le_bytes(res[0..4].try_into().unwrap()),
            MESSAGES_FEATURED_STICKERS
        );
        let mut gfs2 = Writer::new();
        gfs2.write_u32(MESSAGES_GET_FEATURED_STICKERS);
        gfs2.write_i64(1);
        let (_, res2) = unwrap_rpc_result(&d.handle_message(&mut ctx, 105, &gfs2.into_vec())[0]);
        assert_eq!(
            u32::from_le_bytes(res2[0..4].try_into().unwrap()),
            MESSAGES_FEATURED_STICKERS_NOT_MODIFIED
        );

        // 5. account.getPassword -> TL_account.TL_password#957b50fb
        let mut gp = Writer::new();
        gp.write_u32(ACCOUNT_GET_PASSWORD);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 106, &gp.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_u32().unwrap(), ACCOUNT_PASSWORD);
        assert_eq!(r.read_i32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), PASSWORD_KDF_ALGO_MODPOW);

        // 6. messages.getSearchCounters -> Vector<messages.SearchCounter#e844ebff>
        let mut gsc = Writer::new();
        gsc.write_u32(MESSAGES_GET_SEARCH_COUNTERS);
        gsc.write_i32(0); // flags
        gsc.write_u32(INPUT_PEER_SELF);
        gsc.write_vector_header(2);
        gsc.write_u32(0x9609a51c); // inputMessagesFilterPhotos
        gsc.write_u32(INPUT_MESSAGES_FILTER_PHONE_CALLS);
        gsc.write_i32(1); // missed flag
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 107, &gsc.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_vector_header().unwrap(), 2);
        assert_eq!(r.read_u32().unwrap(), MESSAGES_SEARCH_COUNTER);

        // 7. payments.getSavedStarGifts & payments.getStarsStatus wrapped in gzip_packed!
        let mut inner = Writer::new();
        inner.write_u32(PAYMENTS_GET_STARS_STATUS);
        inner.write_u32(INPUT_PEER_SELF);
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&inner.into_vec()).unwrap();
        let compressed = enc.finish().unwrap();

        let mut gz = Writer::new();
        gz.write_u32(GZIP_PACKED);
        gz.write_bytes(&compressed);
        let (_, res) = unwrap_rpc_result(&d.handle_message(&mut ctx, 108, &gz.into_vec())[0]);
        let mut r = Reader::new(&res);
        assert_eq!(r.read_u32().unwrap(), PAYMENTS_STARS_STATUS);
        assert_eq!(r.read_i32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), STARS_AMOUNT);
    }
}
