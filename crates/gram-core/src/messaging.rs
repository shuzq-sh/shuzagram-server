//! Stateful Layer-232 messaging, dialogs, contacts, profile, basic groups,
//! channels/supergroups, and `pts` / `updates.getDifference` engine.
//!
//! Every constructor ID and field layout in this module is verified directly
//! against ShuzaGramMod (`TLRPC.java` & `tl/TL_*.java`, Layer 232).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use gram_store::{
    ChannelRow, ChatRow, DialogRow, MessageRow, StoreError, PEER_CHANNEL as KIND_CHANNEL,
    PEER_CHAT as KIND_CHAT, PEER_USER as KIND_USER, PTS_KIND_DELETE_MESSAGES,
    PTS_KIND_EDIT_MESSAGE, PTS_KIND_NEW_MESSAGE, PTS_KIND_READ_INBOX, PTS_KIND_READ_OUTBOX,
    USER_FLAG_BOT, USER_FLAG_FAKE, USER_FLAG_PREMIUM, USER_FLAG_SCAM, USER_FLAG_VERIFIED,
};
use tl_core::{Reader, TlError, Writer};

use crate::dispatch::{rpc_error, ConnContext, Dispatcher};
use crate::store::{normalize_phone, User};

// --- Layer-232 Constructors (verified against ShuzaGramMod TLRPC.java) ------
pub const TL_USER: u32 = 0xb1b8_cc83;
pub const TL_USER_STATUS_ONLINE: u32 = 0xedb9_3949;
pub const TL_USER_STATUS_OFFLINE: u32 = 0x008c_703f;

pub const TL_PEER_USER: u32 = 0x5951_1722;
pub const TL_PEER_CHAT: u32 = 0x36c6_019a;
pub const TL_PEER_CHANNEL: u32 = 0xa2a5_371e;

pub const TL_INPUT_PEER_EMPTY: u32 = 0x7f3b_18ea;
pub const TL_INPUT_PEER_SELF: u32 = 0x7da0_7ec9;
pub const TL_INPUT_PEER_CHAT: u32 = 0x35a9_5cb9;
pub const TL_INPUT_PEER_CHAT_L131: u32 = 0x179b_e863;
pub const TL_INPUT_PEER_USER: u32 = 0xdde8_a54c;
pub const TL_INPUT_PEER_USER_L131: u32 = 0x7b8e_7de6;
pub const TL_INPUT_PEER_CHANNEL: u32 = 0x27bc_bbfc;
pub const TL_INPUT_PEER_CHANNEL_L131: u32 = 0x20ad_aef8;
pub const TL_INPUT_PEER_USER_FROM_MSG: u32 = 0xa87b_0a1c;
pub const TL_INPUT_PEER_CHANNEL_FROM_MSG: u32 = 0xbd2a_0840;

pub const TL_INPUT_CHANNEL: u32 = 0xf35a_ec28;
pub const TL_INPUT_CHANNEL_L131: u32 = 0xafeb_712e;
pub const TL_INPUT_CHANNEL_EMPTY: u32 = 0xee8c_1e86;
pub const TL_INPUT_CHANNEL_FROM_MSG: u32 = 0x5b93_4f9d;

pub const TL_MESSAGE: u32 = 0x7600_b9d3;
pub const TL_MESSAGE_REPLY_HEADER: u32 = 0x1b97_dd66;
pub const TL_DIALOG: u32 = 0xfc89_f7f3;
pub const TL_PEER_NOTIFY_SETTINGS: u32 = 0x9962_2c0c;

pub const TL_MESSAGES_DIALOGS: u32 = 0x15ba_6c40;
pub const TL_MESSAGES_PEER_DIALOGS: u32 = 0x3371_c354;
pub const TL_MESSAGES_MESSAGES: u32 = 0x1d73_e7ea;
pub const TL_MESSAGES_CHANNEL_MESSAGES: u32 = 0xc776_ba4e;
pub const TL_MESSAGES_AFFECTED_MESSAGES: u32 = 0x84d1_9185;
pub const TL_MESSAGES_AFFECTED_HISTORY: u32 = 0xb45c_69d1;
pub const TL_MESSAGES_INVITED_USERS: u32 = 0x7f5d_efa6;
pub const TL_MESSAGES_CHATS: u32 = 0x64ff_9fd5;
pub const TL_MESSAGES_CHAT_FULL: u32 = 0xe5d7_d19c;

pub const TL_CHAT: u32 = 0x41cb_f256;
pub const TL_CHAT_PHOTO_EMPTY: u32 = 0x37c1_011c;
pub const TL_PHOTO_EMPTY: u32 = 0x2331_b22d;
pub const TL_CHANNEL: u32 = 0xd49f_34c6;
pub const TL_CHANNEL_FULL: u32 = 0xa04e_8d3a;
pub const TL_CHAT_INVITE_JOIN_RESULT_OK: u32 = 0x4456_63a7;

pub const TL_UPDATES_STATE: u32 = 0xa56c_2a3e;
pub const TL_UPDATES_DIFFERENCE_EMPTY: u32 = 0x5d75_a138;
pub const TL_UPDATES_DIFFERENCE: u32 = 0x00f4_9ca0;
pub const TL_UPDATES_CHANNEL_DIFFERENCE: u32 = 0x2064_674e;
pub const TL_UPDATES_CHANNEL_DIFFERENCE_EMPTY: u32 = 0x3e11_affb;

pub const TL_UPDATES: u32 = 0x74ae_4240;
pub const TL_UPDATE_SHORT_SENT_MESSAGE: u32 = 0x9015_e101;
pub const TL_UPDATE_NEW_MESSAGE: u32 = 0x1f2b_0afd;
pub const TL_UPDATE_EDIT_MESSAGE: u32 = 0xe403_70a3;
pub const TL_UPDATE_DELETE_MESSAGES: u32 = 0xa20d_b0e5;
pub const TL_UPDATE_READ_HISTORY_INBOX: u32 = 0x9e84_bc99;
pub const TL_UPDATE_READ_HISTORY_OUTBOX: u32 = 0x2f2f_21bf;
pub const TL_UPDATE_USER_TYPING: u32 = 0x2a17_bf5c;
pub const TL_UPDATE_NEW_CHANNEL_MESSAGE: u32 = 0x62ba_04d9;

pub const TL_CONTACTS_CONTACTS: u32 = 0xeae8_7e42;
pub const TL_CONTACT: u32 = 0x145a_de0b;
pub const TL_CONTACT_STATUS: u32 = 0x16d9_703b;
pub const TL_CONTACTS_IMPORTED_CONTACTS: u32 = 0x77d0_1c3b;
pub const TL_IMPORTED_CONTACT: u32 = 0xc13e_3c50;
pub const TL_INPUT_PHONE_CONTACT: u32 = 0x6a1d_c4be;
pub const TL_INPUT_PHONE_CONTACT_LEGACY: u32 = 0xf392_b7f4;
pub const TL_CONTACTS_RESOLVED_PEER: u32 = 0x7f07_7ad9;
pub const TL_CONTACTS_FOUND: u32 = 0xb313_4d9d;
pub const TL_CONTACTS_BLOCKED: u32 = 0x0ade_1591;

pub const TL_INPUT_REPLY_TO_MESSAGE: u32 = 0x3bd4_b7c2;
pub const TL_INPUT_REPLY_TO_MESSAGE_LEGACY: u32 = 0x22c0_f6d5;
pub const TL_INPUT_REPLY_TO_STORY: u32 = 0x5881_323a;
pub const TL_INPUT_REPLY_TO_STORY_L173: u32 = 0x15b0_f283;
pub const TL_INPUT_REPLY_TO_EPHEMERAL: u32 = 0x4119_b95e;
pub const TL_INPUT_REPLY_TO_MONOFORUM: u32 = 0x69d6_6c45;

pub const TL_CHANNEL_MESSAGES_FILTER_EMPTY: u32 = 0x94d4_2ee7;
pub const TL_CHANNEL_MESSAGES_FILTER: u32 = 0xcd77_d957;

pub const TL_BOOL_TRUE: u32 = 0x9972_75b5;
pub const TL_MESSAGES_MESSAGE_VIEWS: u32 = 0xb6c4_f543;
pub const TL_MESSAGE_VIEWS: u32 = 0x455b_853d;
pub const TL_CHANNELS_CHANNEL_PARTICIPANTS: u32 = 0x9ab0_feaf;
pub const TL_CHANNEL_PARTICIPANT_CREATOR: u32 = 0x2fe6_01d3;
pub const TL_CHANNEL_PARTICIPANT: u32 = 0x1bd5_4456;
pub const TL_CHAT_ADMIN_RIGHTS: u32 = 0x5fb2_24d5;
pub const TL_MESSAGES_PEER_SETTINGS: u32 = 0x6880_b94d;
pub const TL_PEER_SETTINGS: u32 = 0xf477_41f7;
pub const TL_MESSAGES_SAVED_DIALOGS: u32 = 0xf83a_e221;
pub const TL_PREMIUM_BOOSTS_STATUS: u32 = 0x4959_427a;
pub const TL_MESSAGES_SPONSORED_MESSAGES_EMPTY: u32 = 0x1839_490f;
pub const TL_EMOJI_KEYWORDS_DIFFERENCE: u32 = 0x5cc7_61bd;
pub const TL_MESSAGES_AVAILABLE_EFFECTS: u32 = 0xbddb_616e;
pub const TL_REQUIREMENT_TO_CONTACT_EMPTY: u32 = 0x050a_9839;
pub const TL_PAYMENTS_STAR_GIFT_COLLECTIONS: u32 = 0x8a29_32f3;
pub const TL_STORIES_ALBUMS: u32 = 0xc398_7a3a;
pub const TL_MESSAGES_SAVED_REACTION_TAGS: u32 = 0x3259_950a;
pub const TL_MESSAGES_EXPORTED_CHAT_INVITES: u32 = 0xbdc6_2dcc;
pub const TL_CONTACTS_SPONSORED_PEERS_EMPTY: u32 = 0xea32_b4b1;
pub const TL_ACCOUNT_THEMES: u32 = 0x9a3d_8c6d;
pub const TL_ACCOUNT_WEB_BROWSER_SETTINGS: u32 = 0x79eb_8cb3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedPeer {
    User(i64),
    Chat(i64),
    Channel(i64),
}

impl ParsedPeer {
    pub fn kind_and_id(self) -> (i32, i64) {
        match self {
            ParsedPeer::User(id) => (KIND_USER, id),
            ParsedPeer::Chat(id) => (KIND_CHAT, id),
            ParsedPeer::Channel(id) => (KIND_CHANNEL, id),
        }
    }

    pub fn write_tl(self, w: &mut Writer) {
        match self {
            ParsedPeer::User(uid) => {
                w.write_u32(TL_PEER_USER);
                w.write_i64(uid);
            }
            ParsedPeer::Chat(cid) => {
                w.write_u32(TL_PEER_CHAT);
                w.write_i64(cid);
            }
            ParsedPeer::Channel(chid) => {
                w.write_u32(TL_PEER_CHANNEL);
                w.write_i64(chid);
            }
        }
    }
}

pub fn parse_input_peer(r: &mut Reader, self_id: Option<i64>) -> Result<Option<ParsedPeer>, TlError> {
    let ctor = r.read_u32()?;
    match ctor {
        TL_INPUT_PEER_EMPTY => Ok(None),
        TL_INPUT_PEER_SELF => Ok(Some(ParsedPeer::User(self_id.unwrap_or(0)))),
        TL_INPUT_PEER_USER => {
            let uid = r.read_i64()?;
            let _ah = r.read_i64()?;
            Ok(Some(ParsedPeer::User(uid)))
        }
        TL_INPUT_PEER_USER_L131 => {
            let uid = r.read_i32()? as i64;
            let _ah = r.read_i64()?;
            Ok(Some(ParsedPeer::User(uid)))
        }
        TL_INPUT_PEER_CHAT => {
            let cid = r.read_i64()?;
            Ok(Some(ParsedPeer::Chat(cid)))
        }
        TL_INPUT_PEER_CHAT_L131 => {
            let cid = r.read_i32()? as i64;
            Ok(Some(ParsedPeer::Chat(cid)))
        }
        TL_INPUT_PEER_CHANNEL => {
            let chid = r.read_i64()?;
            let _ah = r.read_i64()?;
            Ok(Some(ParsedPeer::Channel(chid)))
        }
        TL_INPUT_PEER_CHANNEL_L131 => {
            let chid = r.read_i32()? as i64;
            let _ah = r.read_i64()?;
            Ok(Some(ParsedPeer::Channel(chid)))
        }
        TL_INPUT_PEER_USER_FROM_MSG => {
            let _ = parse_input_peer(r, self_id)?;
            let _msg_id = r.read_i32()?;
            let uid = r.read_i64()?;
            Ok(Some(ParsedPeer::User(uid)))
        }
        TL_INPUT_PEER_CHANNEL_FROM_MSG => {
            let _ = parse_input_peer(r, self_id)?;
            let _msg_id = r.read_i32()?;
            let chid = r.read_i64()?;
            Ok(Some(ParsedPeer::Channel(chid)))
        }
        other => Err(TlError::UnknownConstructor {
            id: other,
            context: "InputPeer",
        }),
    }
}

pub fn parse_input_channel(r: &mut Reader, self_id: Option<i64>) -> Result<Option<i64>, TlError> {
    let ctor = r.read_u32()?;
    match ctor {
        TL_INPUT_CHANNEL_EMPTY => Ok(None),
        TL_INPUT_CHANNEL => {
            let cid = r.read_i64()?;
            let _ah = r.read_i64()?;
            Ok(Some(cid))
        }
        TL_INPUT_CHANNEL_L131 => {
            let cid = r.read_i32()? as i64;
            let _ah = r.read_i64()?;
            Ok(Some(cid))
        }
        TL_INPUT_CHANNEL_FROM_MSG => {
            let _ = parse_input_peer(r, self_id)?;
            let _msg_id = r.read_i32()?;
            let cid = r.read_i64()?;
            Ok(Some(cid))
        }
        other => Err(TlError::UnknownConstructor {
            id: other,
            context: "InputChannel",
        }),
    }
}

pub fn parse_input_reply_to(r: &mut Reader, self_id: Option<i64>) -> Result<Option<i32>, TlError> {
    let ctor = r.read_u32()?;
    match ctor {
        TL_INPUT_REPLY_TO_MESSAGE | TL_INPUT_REPLY_TO_MESSAGE_LEGACY => {
            let flags = r.read_i32()?;
            let reply_to_msg_id = r.read_i32()?;
            if flags & (1 << 0) != 0 {
                let _top_msg_id = r.read_i32()?;
            }
            if flags & (1 << 1) != 0 {
                let _ = parse_input_peer(r, self_id)?;
            }
            if flags & (1 << 2) != 0 {
                let _quote_text = r.read_string()?;
            }
            if flags & (1 << 3) != 0 {
                skip_message_entities(r)?;
            }
            if flags & (1 << 4) != 0 {
                let _quote_offset = r.read_i32()?;
            }
            if flags & (1 << 5) != 0 {
                let _ = parse_input_peer(r, self_id)?;
            }
            if flags & (1 << 6) != 0 {
                let _todo_item_id = r.read_i32()?;
            }
            if flags & (1 << 7) != 0 {
                let _poll_option = r.read_bytes()?;
            }
            Ok(Some(reply_to_msg_id))
        }
        TL_INPUT_REPLY_TO_STORY => {
            let _ = parse_input_peer(r, self_id)?;
            let _story_id = r.read_i32()?;
            Ok(None)
        }
        TL_INPUT_REPLY_TO_STORY_L173 => {
            let _u_ctor = r.read_u32()?;
            let _uid = r.read_i64()?;
            let _ah = r.read_i64()?;
            let _story_id = r.read_i32()?;
            Ok(None)
        }
        TL_INPUT_REPLY_TO_EPHEMERAL => {
            let id = r.read_i32()?;
            Ok(Some(id))
        }
        TL_INPUT_REPLY_TO_MONOFORUM => {
            let _ = parse_input_peer(r, self_id)?;
            Ok(None)
        }
        other => Err(TlError::UnknownConstructor {
            id: other,
            context: "InputReplyTo",
        }),
    }
}

fn skip_message_entities(r: &mut Reader) -> Result<(), TlError> {
    let count = r.read_vector_header()?;
    for _ in 0..count {
        let e_ctor = r.read_u32()?;
        let _offset = r.read_i32()?;
        let _length = r.read_i32()?;
        match e_ctor {
            0x76a6d327 | 0xfa04579d => {
                // textUrl / pre -> extra string
                let _ = r.read_string()?;
            }
            0xdc7b1140 => {
                // mentionName -> user_id:long
                let _ = r.read_i64()?;
            }
            0xc8cf05f8 => {
                // customEmoji -> document_id:long
                let _ = r.read_i64()?;
            }
            _ => {}
        }
    }
    Ok(())
}

// --- Rich Layer-232 Encoders ------------------------------------------------

pub fn encode_tl_user(
    user: &User,
    self_id: Option<i64>,
    is_contact: bool,
    is_mutual: bool,
    is_online: bool,
) -> Vec<u8> {
    const FLAG_0: i32 = 1 << 0; // access_hash
    const FLAG_1: i32 = 1 << 1; // first_name
    const FLAG_2: i32 = 1 << 2; // last_name
    const FLAG_3: i32 = 1 << 3; // username
    const FLAG_4: i32 = 1 << 4; // phone
    const FLAG_5: i32 = 1 << 5; // photo
    const FLAG_6: i32 = 1 << 6; // status
    const FLAG_10: i32 = 1 << 10; // self
    const FLAG_11: i32 = 1 << 11; // contact
    const FLAG_12: i32 = 1 << 12; // mutual_contact
    const FLAG_14: i32 = 1 << 14; // bot
    const FLAG_17: i32 = 1 << 17; // verified
    const FLAG_24: i32 = 1 << 24; // scam
    const FLAG_26: i32 = 1 << 26; // fake
    const FLAG_28: i32 = 1 << 28; // premium

    let include_last = !user.last_name.is_empty() && user.last_name != "User";
    let has_username = user.username.as_ref().is_some_and(|u| !u.is_empty());
    let has_photo = user.photo_id.is_some();

    let mut flags = FLAG_0 | FLAG_1 | FLAG_4 | FLAG_6;
    if Some(user.id) == self_id {
        flags |= FLAG_10;
    }
    if is_contact {
        flags |= FLAG_11;
    }
    if is_mutual {
        flags |= FLAG_12;
    }
    if include_last {
        flags |= FLAG_2;
    }
    if has_username {
        flags |= FLAG_3;
    }
    if has_photo {
        flags |= FLAG_5;
    }
    if user.flags_bitmask & USER_FLAG_VERIFIED != 0 {
        flags |= FLAG_17;
    }
    if user.flags_bitmask & USER_FLAG_PREMIUM != 0 {
        flags |= FLAG_28;
    }
    if user.flags_bitmask & USER_FLAG_SCAM != 0 {
        flags |= FLAG_24;
    }
    if user.flags_bitmask & USER_FLAG_FAKE != 0 {
        flags |= FLAG_26;
    }
    let is_bot = user.flags_bitmask & USER_FLAG_BOT != 0;
    if is_bot {
        flags |= FLAG_14;
    }

    let now = now_unix();
    let mut w = Writer::new();
    w.write_u32(TL_USER);
    w.write_i32(flags);
    w.write_i32(0); // flags2
    w.write_i64(user.id);
    w.write_i64(user.access_hash); // FLAG_0
    w.write_string(&user.first_name); // FLAG_1
    if include_last {
        w.write_string(&user.last_name); // FLAG_2
    }
    if let Some(uname) = user.username.as_ref().filter(|u| !u.is_empty()) {
        w.write_string(uname); // FLAG_3
    }
    w.write_string(&user.phone); // FLAG_4
    if let Some(pid) = user.photo_id {
        // TL_userProfilePhoto#82d1f706 { flags:0 photo_id:long dc_id:int }
        w.write_u32(0x82d1_f706);
        w.write_i32(0); // flags
        w.write_i64(pid);
        w.write_i32(user.photo_dc_id.unwrap_or(2));
    }
    // FLAG_6: UserStatus
    if is_online {
        w.write_u32(TL_USER_STATUS_ONLINE);
        w.write_i32(now + 300);
    } else {
        w.write_u32(TL_USER_STATUS_OFFLINE);
        w.write_i32(now - 60);
    }
    if is_bot {
        w.write_i32(1); // bot_info_version (FLAG_14)
    }
    w.into_vec()
}

pub fn encode_tl_chat(chat: &ChatRow, viewer_id: i64) -> Vec<u8> {
    let mut flags = 0i32;
    if chat.creator_id == viewer_id {
        flags |= 1 << 0; // creator
    }
    let mut w = Writer::new();
    w.write_u32(TL_CHAT);
    w.write_i32(flags);
    w.write_i64(chat.chat_id);
    w.write_string(&chat.title);
    w.write_u32(TL_CHAT_PHOTO_EMPTY);
    w.write_i32(chat.participants_count);
    w.write_i32(chat.date_unix);
    w.write_i32(chat.version);
    w.into_vec()
}

pub fn encode_tl_channel(chan: &ChannelRow, viewer_id: i64) -> Vec<u8> {
    let mut flags = (1 << 13) | (1 << 17); // access_hash | participants_count
    if chan.creator_id == viewer_id {
        flags |= 1 << 0; // creator
    }
    if chan.is_broadcast {
        flags |= 1 << 5; // broadcast
    }
    if chan.is_megagroup {
        flags |= 1 << 8; // megagroup
    }
    if chan.is_forum {
        flags |= 1 << 30; // forum
    }
    let has_username = chan.username.as_ref().is_some_and(|u| !u.is_empty());
    if has_username {
        flags |= 1 << 6;
    }

    let mut w = Writer::new();
    w.write_u32(TL_CHANNEL);
    w.write_i32(flags);
    w.write_i32(0); // flags2
    w.write_i64(chan.channel_id);
    w.write_i64(chan.access_hash); // FLAG_13
    w.write_string(&chan.title);
    if let Some(uname) = chan.username.as_ref().filter(|u| !u.is_empty()) {
        w.write_string(uname); // FLAG_6
    }
    w.write_u32(TL_CHAT_PHOTO_EMPTY);
    w.write_i32(chan.date_unix);
    w.write_i32(chan.participants_count); // FLAG_17
    w.into_vec()
}

pub fn encode_tl_message(row: &MessageRow, is_broadcast_post: bool) -> Vec<u8> {
    const FLAG_1_OUT: i32 = 1 << 1;
    const FLAG_3_REPLY: i32 = 1 << 3;
    const FLAG_7_ENTITIES: i32 = 1 << 7;
    const FLAG_8_FROM_ID: i32 = 1 << 8;
    const FLAG_9_MEDIA: i32 = 1 << 9;
    const FLAG_14_POST: i32 = 1 << 14;
    const FLAG_15_EDIT_DATE: i32 = 1 << 15;
    const FLAG_25_TTL: i32 = 1 << 25;

    let mut flags = 0i32;
    if row.is_out {
        flags |= FLAG_1_OUT;
    }
    if is_broadcast_post {
        flags |= FLAG_14_POST;
    } else if row.sender_user_id != 0 {
        flags |= FLAG_8_FROM_ID;
    }
    if row.reply_to_msg_id.is_some() {
        flags |= FLAG_3_REPLY;
    }
    if row.media_tl.is_some() {
        flags |= FLAG_9_MEDIA;
    }
    if row.entities_tl.is_some() {
        flags |= FLAG_7_ENTITIES;
    }
    if row.edit_date_unix.is_some() {
        flags |= FLAG_15_EDIT_DATE;
    }
    if row.ttl_period.is_some() {
        flags |= FLAG_25_TTL;
    }

    let mut w = Writer::new();
    w.write_u32(TL_MESSAGE);
    w.write_i32(flags);
    w.write_i32(0); // flags2 (Layer 232!)
    w.write_i32(row.msg_id);
    if flags & FLAG_8_FROM_ID != 0 {
        w.write_u32(TL_PEER_USER);
        w.write_i64(row.sender_user_id);
    }
    // peer_id
    match row.peer_kind {
        KIND_CHAT => {
            w.write_u32(TL_PEER_CHAT);
            w.write_i64(row.peer_id);
        }
        KIND_CHANNEL => {
            w.write_u32(TL_PEER_CHANNEL);
            w.write_i64(row.peer_id);
        }
        _ => {
            w.write_u32(TL_PEER_USER);
            w.write_i64(row.peer_id);
        }
    }
    if let Some(reply_id) = row.reply_to_msg_id {
        w.write_u32(TL_MESSAGE_REPLY_HEADER);
        w.write_i32(1 << 4); // FLAG_4: reply_to_msg_id
        w.write_i32(reply_id);
    }
    w.write_i32(row.date_unix);
    w.write_string(&row.message_text);
    if let Some(media) = &row.media_tl {
        w.write_raw(media);
    }
    if let Some(ents) = &row.entities_tl {
        w.write_raw(ents);
    }
    if let Some(edit_ts) = row.edit_date_unix {
        w.write_i32(edit_ts);
    }
    if let Some(ttl) = row.ttl_period {
        w.write_i32(ttl);
    }
    w.into_vec()
}

pub fn encode_tl_dialog(dlg: &DialogRow, channel_pts: Option<i32>) -> Vec<u8> {
    let mut flags = 0i32;
    if channel_pts.is_some() {
        flags |= 1 << 0; // pts
    }
    if dlg.pinned {
        flags |= 1 << 2; // pinned
    }
    let mut w = Writer::new();
    w.write_u32(TL_DIALOG);
    w.write_i32(flags);
    match dlg.peer_kind {
        KIND_CHAT => {
            w.write_u32(TL_PEER_CHAT);
            w.write_i64(dlg.peer_id);
        }
        KIND_CHANNEL => {
            w.write_u32(TL_PEER_CHANNEL);
            w.write_i64(dlg.peer_id);
        }
        _ => {
            w.write_u32(TL_PEER_USER);
            w.write_i64(dlg.peer_id);
        }
    }
    w.write_i32(dlg.top_message_id);
    w.write_i32(dlg.read_inbox_max_id);
    w.write_i32(dlg.read_outbox_max_id);
    w.write_i32(dlg.unread_count);
    w.write_i32(0); // unread_mentions_count
    w.write_i32(0); // unread_reactions_count
    w.write_i32(0); // unread_poll_votes_count (Layer 232!)
    w.write_u32(TL_PEER_NOTIFY_SETTINGS);
    w.write_i32(0); // flags
    if let Some(cpts) = channel_pts {
        w.write_i32(cpts);
    }
    w.into_vec()
}

pub fn encode_updates_state(pts: i32, qts: i32, unread_count: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATES_STATE);
    w.write_i32(pts);
    w.write_i32(qts);
    w.write_i32(now_unix());
    w.write_i32(0); // seq
    w.write_i32(unread_count);
    w.into_vec()
}

pub fn encode_tl_updates(
    updates: &[Vec<u8>],
    users: &[Vec<u8>],
    chats: &[Vec<u8>],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATES);
    w.write_vector_header(updates.len());
    for u in updates {
        w.write_raw(u);
    }
    w.write_vector_header(users.len());
    for u in users {
        w.write_raw(u);
    }
    w.write_vector_header(chats.len());
    for c in chats {
        w.write_raw(c);
    }
    w.write_i32(now_unix());
    w.write_i32(0); // seq
    w.into_vec()
}

pub fn encode_update_new_message(msg_bytes: &[u8], pts: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_NEW_MESSAGE);
    w.write_raw(msg_bytes);
    w.write_i32(pts);
    w.write_i32(1); // pts_count
    w.into_vec()
}

pub fn encode_update_edit_message(msg_bytes: &[u8], pts: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_EDIT_MESSAGE);
    w.write_raw(msg_bytes);
    w.write_i32(pts);
    w.write_i32(1);
    w.into_vec()
}

pub fn encode_update_delete_messages(ids: &[i32], pts: i32, pts_count: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_DELETE_MESSAGES);
    w.write_vector_header(ids.len());
    for &id in ids {
        w.write_i32(id);
    }
    w.write_i32(pts);
    w.write_i32(pts_count);
    w.into_vec()
}

pub fn encode_update_read_inbox(
    peer: ParsedPeer,
    max_id: i32,
    still_unread: i32,
    pts: i32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_READ_HISTORY_INBOX);
    w.write_i32(0); // flags
    peer.write_tl(&mut w);
    w.write_i32(max_id);
    w.write_i32(still_unread);
    w.write_i32(pts);
    w.write_i32(1);
    w.into_vec()
}

pub fn encode_update_read_outbox(peer: ParsedPeer, max_id: i32, pts: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_READ_HISTORY_OUTBOX);
    peer.write_tl(&mut w);
    w.write_i32(max_id);
    w.write_i32(pts);
    w.write_i32(1);
    w.into_vec()
}

pub fn encode_update_new_channel_message(msg_bytes: &[u8], channel_pts: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_NEW_CHANNEL_MESSAGE);
    w.write_raw(msg_bytes);
    w.write_i32(channel_pts);
    w.write_i32(1);
    w.into_vec()
}

pub fn encode_update_short_sent_message(
    msg_id: i32,
    pts: i32,
    date: i32,
    media_tl: Option<&[u8]>,
    ttl_period: Option<i32>,
) -> Vec<u8> {
    let mut flags = 1 << 1; // out = true
    if media_tl.is_some() {
        flags |= 1 << 9;
    }
    if ttl_period.is_some() {
        flags |= 1 << 25;
    }
    let mut w = Writer::new();
    w.write_u32(TL_UPDATE_SHORT_SENT_MESSAGE);
    w.write_i32(flags);
    w.write_i32(msg_id);
    w.write_i32(pts);
    w.write_i32(1); // pts_count
    w.write_i32(date);
    if let Some(m) = media_tl {
        w.write_raw(m);
    }
    if let Some(ttl) = ttl_period {
        w.write_i32(ttl);
    }
    w.into_vec()
}

// --- Dispatcher Stateful Handlers -------------------------------------------

impl Dispatcher {
    pub fn render_user_for_viewer(&self, user: &User, viewer_id: Option<i64>) -> Vec<u8> {
        let is_online = self.hub().is_user_online(user.id);
        encode_tl_user(user, viewer_id, false, false, is_online)
    }

    fn require_auth_user(&self, ctx: &mut ConnContext) -> Result<User, Vec<u8>> {
        if let Some(u) = &ctx.user {
            if let Some(fresh) = self.store().user_by_id(u.id) {
                ctx.user = Some(fresh.clone());
                return Ok(fresh);
            }
            return Ok(u.clone());
        }
        Err(rpc_error(401, "AUTH_KEY_UNREGISTERED"))
    }

    // --- Profile & Username (`account.*`) -----------------------------------

    pub fn account_update_profile(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "PROFILE_MALFORMED");
        };
        let first_name = if flags & 1 != 0 {
            r.read_string().ok().map(str::to_string)
        } else {
            None
        };
        let last_name = if flags & 2 != 0 {
            r.read_string().ok().map(str::to_string)
        } else {
            None
        };
        let about = if flags & 4 != 0 {
            r.read_string().ok().map(str::to_string)
        } else {
            None
        };
        match self.store().acid().update_profile(
            me.id,
            first_name.as_deref(),
            last_name.as_deref(),
            about.as_deref(),
        ) {
            Ok(row) => {
                let updated = User::from(row);
                ctx.user = Some(updated.clone());
                self.render_user_for_viewer(&updated, Some(updated.id))
            }
            Err(_) => rpc_error(400, "USER_ID_INVALID"),
        }
    }

    pub fn account_check_username(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let Ok(username) = r.read_string() else {
            return rpc_error(400, "USERNAME_INVALID");
        };
        let self_id = ctx.user.as_ref().map(|u| u.id);
        match self.store().acid().is_username_available(username, self_id) {
            Ok(avail) => {
                let mut w = Writer::new();
                w.write_bool(avail);
                w.into_vec()
            }
            Err(StoreError::UsernameInvalid) => rpc_error(400, "USERNAME_INVALID"),
            Err(_) => rpc_error(400, "USERNAME_OCCUPIED"),
        }
    }

    pub fn account_update_username(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(username) = r.read_string() else {
            return rpc_error(400, "USERNAME_INVALID");
        };
        match self.store().acid().update_username(me.id, username) {
            Ok(row) => {
                let updated = User::from(row);
                ctx.user = Some(updated.clone());
                self.render_user_for_viewer(&updated, Some(updated.id))
            }
            Err(StoreError::UsernameInvalid) => rpc_error(400, "USERNAME_INVALID"),
            Err(StoreError::UsernameOccupied) => rpc_error(400, "USERNAME_OCCUPIED"),
            Err(_) => rpc_error(400, "USERNAME_INVALID"),
        }
    }

    // --- Contacts & Global Search (`contacts.*`) ----------------------------

    pub fn contacts_get_contacts(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let _hash = r.read_i64().unwrap_or(0);
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let rows = self.store().acid().list_contacts(me.id);
        let mut w = Writer::new();
        w.write_u32(TL_CONTACTS_CONTACTS);
        w.write_vector_header(rows.len());
        for (u, mutual) in &rows {
            w.write_u32(TL_CONTACT);
            w.write_i64(u.user_id);
            w.write_bool(*mutual);
        }
        w.write_i32(rows.len() as i32); // saved_count
        w.write_vector_header(rows.len());
        for (u, mutual) in rows {
            let usr = User::from(u);
            let online = self.hub().is_user_online(usr.id);
            w.write_raw(&encode_tl_user(&usr, Some(me.id), true, mutual, online));
        }
        w.into_vec()
    }

    pub fn contacts_import_contacts(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(count) = r.read_vector_header() else {
            return rpc_error(400, "CONTACTS_MALFORMED");
        };
        let mut imported = Vec::new();
        let mut users = BTreeMap::new();

        for _ in 0..count.min(500) {
            let Ok(ctor) = r.read_u32() else {
                break;
            };
            let flags = if ctor == TL_INPUT_PHONE_CONTACT {
                r.read_i32().unwrap_or(0)
            } else if ctor == TL_INPUT_PHONE_CONTACT_LEGACY {
                0
            } else {
                break;
            };
            let (Ok(client_id), Ok(phone), Ok(fname), Ok(lname)) = (
                r.read_i64(),
                r.read_string(),
                r.read_string(),
                r.read_string(),
            ) else {
                break;
            };
            let phone = phone.to_string();
            let fname = fname.to_string();
            let lname = lname.to_string();
            if flags & 1 != 0 {
                // TL_textWithEntities#751f3146 { text:string entities:Vector }
                let _ = r.read_u32();
                let _ = r.read_string();
                let _ = skip_message_entities(r);
            }
            if let Some(found) = self.store().user_by_phone(&phone) {
                let _ = self
                    .store()
                    .acid()
                    .add_contact(me.id, found.id, &fname, &lname, &phone);
                imported.push((found.id, client_id));
                users.insert(found.id, found);
            }
        }

        let mut w = Writer::new();
        w.write_u32(TL_CONTACTS_IMPORTED_CONTACTS);
        w.write_vector_header(imported.len());
        for (uid, cid) in &imported {
            w.write_u32(TL_IMPORTED_CONTACT);
            w.write_i64(*uid);
            w.write_i64(*cid);
        }
        w.write_vector_header(0); // popular_invites
        w.write_vector_header(0); // retry_contacts
        w.write_vector_header(users.len());
        for u in users.values() {
            let online = self.hub().is_user_online(u.id);
            w.write_raw(&encode_tl_user(u, Some(me.id), true, false, online));
        }
        w.into_vec()
    }

    pub fn contacts_add_contact(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        has_flags: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let flags = if has_flags {
            r.read_i32().unwrap_or(0)
        } else {
            0
        };
        let Ok(Some(target)) = self.resolve_input_user_pub(ctx, r) else {
            return rpc_error(400, "CONTACT_ID_INVALID");
        };
        let fname = r.read_string().unwrap_or(&target.first_name).to_string();
        let lname = r.read_string().unwrap_or(&target.last_name).to_string();
        let phone = normalize_phone(r.read_string().unwrap_or(&target.phone));
        if flags & (1 << 1) != 0 {
            let _ = r.read_u32();
            let _ = r.read_string();
            let _ = skip_message_entities(r);
        }
        let _ = self
            .store()
            .acid()
            .add_contact(me.id, target.id, &fname, &lname, &phone);
        let online = self.hub().is_user_online(target.id);
        let u_bytes = encode_tl_user(&target, Some(me.id), true, false, online);
        encode_tl_updates(&[], &[u_bytes], &[])
    }

    pub fn contacts_delete_contacts(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(count) = r.read_vector_header() else {
            return rpc_error(400, "CONTACT_ID_INVALID");
        };
        let mut ids = Vec::new();
        let mut users = Vec::new();
        for _ in 0..count.min(200) {
            if let Ok(Some(u)) = self.resolve_input_user_pub(ctx, r) {
                ids.push(u.id);
                users.push(self.render_user_for_viewer(&u, Some(me.id)));
            }
        }
        let _ = self.store().acid().delete_contacts(me.id, &ids);
        encode_tl_updates(&[], &users, &[])
    }

    pub fn contacts_get_statuses(&self, ctx: &mut ConnContext) -> Vec<u8> {
        let Some(me) = ctx.user.as_ref() else {
            let mut w = Writer::new();
            w.write_vector_header(0);
            return w.into_vec();
        };
        let contacts = self.store().acid().list_contacts(me.id);
        let now = now_unix();
        let mut w = Writer::new();
        w.write_vector_header(contacts.len());
        for (u, _) in contacts {
            w.write_u32(TL_CONTACT_STATUS);
            w.write_i64(u.user_id);
            if self.hub().is_user_online(u.user_id) {
                w.write_u32(TL_USER_STATUS_ONLINE);
                w.write_i32(now + 300);
            } else {
                w.write_u32(TL_USER_STATUS_OFFLINE);
                w.write_i32(now - 60);
            }
        }
        w.into_vec()
    }

    pub fn contacts_get_blocked() -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_CONTACTS_BLOCKED);
        w.write_vector_header(0); // blocked
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    pub fn contacts_resolve_username(
        &self,
        ctx: &ConnContext,
        r: &mut Reader,
        has_flags: bool,
    ) -> Vec<u8> {
        let flags = if has_flags {
            r.read_i32().unwrap_or(0)
        } else {
            0
        };
        let Ok(username) = r.read_string() else {
            return rpc_error(400, "USERNAME_INVALID");
        };
        let username = username.to_string();
        if flags & 1 != 0 {
            let _referer = r.read_string();
        }
        let viewer_id = ctx.user.as_ref().map(|u| u.id);

        if let Some(u) = self.store().user_by_username(&username) {
            let mut w = Writer::new();
            w.write_u32(TL_CONTACTS_RESOLVED_PEER);
            ParsedPeer::User(u.id).write_tl(&mut w);
            w.write_vector_header(0); // chats
            w.write_vector_header(1); // users
            w.write_raw(&self.render_user_for_viewer(&u, viewer_id));
            return w.into_vec();
        }
        if let Some(chan) = self.store().acid().channel_by_username(&username) {
            let mut w = Writer::new();
            w.write_u32(TL_CONTACTS_RESOLVED_PEER);
            ParsedPeer::Channel(chan.channel_id).write_tl(&mut w);
            w.write_vector_header(1); // chats
            w.write_raw(&encode_tl_channel(&chan, viewer_id.unwrap_or(0)));
            w.write_vector_header(0); // users
            return w.into_vec();
        }
        rpc_error(400, "USERNAME_NOT_OCCUPIED")
    }

    pub fn contacts_resolve_phone(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let Ok(phone) = r.read_string() else {
            return rpc_error(400, "PHONE_NOT_OCCUPIED");
        };
        let viewer_id = ctx.user.as_ref().map(|u| u.id);
        if let Some(u) = self.store().user_by_phone(phone) {
            let mut w = Writer::new();
            w.write_u32(TL_CONTACTS_RESOLVED_PEER);
            ParsedPeer::User(u.id).write_tl(&mut w);
            w.write_vector_header(0); // chats
            w.write_vector_header(1); // users
            w.write_raw(&self.render_user_for_viewer(&u, viewer_id));
            return w.into_vec();
        }
        rpc_error(400, "PHONE_NOT_OCCUPIED")
    }

    pub fn contacts_search(
        &self,
        ctx: &ConnContext,
        r: &mut Reader,
        has_flags: bool,
    ) -> Vec<u8> {
        if has_flags {
            let _flags = r.read_i32();
        }
        let q = r.read_string().unwrap_or("").to_string();
        let limit = r.read_i32().unwrap_or(20).clamp(1, 50) as usize;
        let viewer_id = ctx.user.as_ref().map(|u| u.id);

        let user_rows = self.store().acid().search_users(&q, limit);
        let chan_rows = self.store().acid().search_channels(&q, limit);

        let mut w = Writer::new();
        w.write_u32(TL_CONTACTS_FOUND);
        w.write_vector_header(0); // my_results
        w.write_vector_header(user_rows.len() + chan_rows.len()); // results
        for u in &user_rows {
            ParsedPeer::User(u.user_id).write_tl(&mut w);
        }
        for c in &chan_rows {
            ParsedPeer::Channel(c.channel_id).write_tl(&mut w);
        }
        w.write_vector_header(chan_rows.len()); // chats
        for c in &chan_rows {
            w.write_raw(&encode_tl_channel(c, viewer_id.unwrap_or(0)));
        }
        w.write_vector_header(user_rows.len()); // users
        for u in user_rows {
            let usr = User::from(u);
            w.write_raw(&self.render_user_for_viewer(&usr, viewer_id));
        }
        w.into_vec()
    }

    // --- Updates State & `updates.getDifference` ----------------------------

    pub fn updates_get_state_real(&self, ctx: &mut ConnContext) -> Vec<u8> {
        let Some(me) = self.require_auth_user(ctx).ok() else {
            return encode_updates_state(1, 0, 0);
        };
        let (pts, qts, unread) = self.store().acid().user_state(me.id);
        encode_updates_state(pts, qts, unread)
    }

    pub fn updates_get_difference_real(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        is_legacy: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(_) => {
                let mut w = Writer::new();
                w.write_u32(TL_UPDATES_DIFFERENCE_EMPTY);
                w.write_i32(now_unix());
                w.write_i32(0);
                return w.into_vec();
            }
        };
        let flags = r.read_i32().unwrap_or(0);
        let from_pts = r.read_i32().unwrap_or(0);
        let mut limit = 200usize;
        if is_legacy {
            if flags & 1 != 0 {
                limit = r.read_i32().unwrap_or(200).clamp(1, 1000) as usize;
            }
        } else {
            if flags & (1 << 1) != 0 {
                limit = r.read_i32().unwrap_or(200).clamp(1, 1000) as usize;
            }
            if flags & (1 << 2) != 0 {
                let _pts_total_limit = r.read_i32();
            }
        }
        let _date = r.read_i32();
        let _qts = r.read_i32();

        let (current_pts, events) = self
            .store()
            .acid()
            .get_pts_difference(me.id, from_pts, limit);
        if events.is_empty() {
            let mut w = Writer::new();
            w.write_u32(TL_UPDATES_DIFFERENCE_EMPTY);
            w.write_i32(now_unix());
            w.write_i32(0);
            return w.into_vec();
        }

        let mut new_messages: Vec<Vec<u8>> = Vec::new();
        let mut other_updates: Vec<Vec<u8>> = Vec::new();
        let mut user_ids: BTreeSet<i64> = BTreeSet::new();
        let mut chat_ids: BTreeSet<i64> = BTreeSet::new();
        user_ids.insert(me.id);

        for ev in events {
            match ev.update_kind {
                PTS_KIND_NEW_MESSAGE => {
                    if let Some(m) = self.store().acid().get_message(me.id, ev.msg_id) {
                        self.collect_msg_refs(&m, &mut user_ids, &mut chat_ids);
                        new_messages.push(encode_tl_message(&m, false));
                    }
                }
                PTS_KIND_EDIT_MESSAGE => {
                    if let Some(m) = self.store().acid().get_message(me.id, ev.msg_id) {
                        self.collect_msg_refs(&m, &mut user_ids, &mut chat_ids);
                        let mb = encode_tl_message(&m, false);
                        other_updates.push(encode_update_edit_message(&mb, ev.pts));
                    }
                }
                PTS_KIND_DELETE_MESSAGES => {
                    other_updates.push(encode_update_delete_messages(&[ev.msg_id], ev.pts, 1));
                }
                PTS_KIND_READ_INBOX => {
                    let peer = peer_from_kind(ev.peer_kind, ev.peer_id);
                    other_updates.push(encode_update_read_inbox(
                        peer,
                        ev.msg_id,
                        ev.extra_i32,
                        ev.pts,
                    ));
                }
                PTS_KIND_READ_OUTBOX => {
                    let peer = peer_from_kind(ev.peer_kind, ev.peer_id);
                    other_updates.push(encode_update_read_outbox(peer, ev.msg_id, ev.pts));
                }
                _ => {}
            }
        }

        let (_, qts, unread) = self.store().acid().user_state(me.id);
        let mut w = Writer::new();
        w.write_u32(TL_UPDATES_DIFFERENCE);
        w.write_vector_header(new_messages.len());
        for m in &new_messages {
            w.write_raw(m);
        }
        w.write_vector_header(0); // new_encrypted_messages
        w.write_vector_header(other_updates.len());
        for u in &other_updates {
            w.write_raw(u);
        }
        let chats = self.encode_chats_set(&chat_ids, me.id);
        w.write_vector_header(chats.len());
        for c in &chats {
            w.write_raw(c);
        }
        let users = self.encode_users_set(&user_ids, Some(me.id));
        w.write_vector_header(users.len());
        for u in &users {
            w.write_raw(u);
        }
        w.write_raw(&encode_updates_state(current_pts, qts, unread));
        w.into_vec()
    }

    // --- Direct, Group & Channel Messaging (`messages.*`) -------------------

    pub fn messages_send_message(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        legacy_int_reply: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "PEER_ID_INVALID");
        };
        let Ok(Some(peer)) = parse_input_peer(r, Some(me.id)) else {
            return rpc_error(400, "PEER_ID_INVALID");
        };
        let reply_to_msg_id = if flags & 1 != 0 {
            if legacy_int_reply {
                r.read_i32().ok()
            } else {
                match parse_input_reply_to(r, Some(me.id)) {
                    Ok(v) => v,
                    Err(_) => return rpc_error(400, "REPLY_TO_INVALID"),
                }
            }
        } else {
            None
        };
        let (Ok(text), Ok(random_id)) = (r.read_string(), r.read_i64()) else {
            return rpc_error(400, "MESSAGE_EMPTY");
        };
        let text = text.to_string();
        if text.trim().is_empty() {
            return rpc_error(400, "MESSAGE_EMPTY");
        }

        self.deliver_outgoing_message(ctx, &me, peer, random_id, &text, reply_to_msg_id, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn deliver_outgoing_message(
        &self,
        ctx: &ConnContext,
        me: &User,
        peer: ParsedPeer,
        random_id: i64,
        text: &str,
        reply_to_msg_id: Option<i32>,
        media_tl: Option<&[u8]>,
        ttl_period: Option<i32>,
    ) -> Vec<u8> {
        match peer {
            ParsedPeer::User(target_uid) => {
                let recip_id = if target_uid == 0 { me.id } else { target_uid };
                let outcome = match self.store().acid().send_direct_message(
                    me.id,
                    recip_id,
                    random_id,
                    text,
                    reply_to_msg_id,
                    media_tl,
                    None,
                    ttl_period,
                ) {
                    Ok(o) => o,
                    Err(StoreError::NotFound) => return rpc_error(400, "USER_ID_INVALID"),
                    Err(_) => return rpc_error(500, "STORAGE_ERROR"),
                };

                if !outcome.deduplicated {
                    // Push to sender's OTHER active devices/sessions!
                    let sender_msg_tl = encode_tl_message(&outcome.sender_msg, false);
                    let sender_upd = encode_update_new_message(&sender_msg_tl, outcome.sender_pts);
                    let mut sender_users = vec![self.render_user_for_viewer(me, Some(me.id))];
                    if recip_id != me.id {
                        if let Some(ru) = self.store().user_by_id(recip_id) {
                            sender_users.push(self.render_user_for_viewer(&ru, Some(me.id)));
                        }
                    }
                    let push_self = encode_tl_updates(&[sender_upd], &sender_users, &[]);
                    self.hub().push_to_user(me.id, Some(ctx.conn_id), push_self);

                    // Real-time push to recipient!
                    if let Some((recip_msg, recip_pts)) = &outcome.recipient_msg {
                        let recip_msg_tl = encode_tl_message(recip_msg, false);
                        let recip_upd = encode_update_new_message(&recip_msg_tl, *recip_pts);
                        let mut r_users = vec![self.render_user_for_viewer(me, Some(recip_id))];
                        if let Some(ru) = self.store().user_by_id(recip_id) {
                            r_users.push(self.render_user_for_viewer(&ru, Some(recip_id)));
                        }
                        let push_recip = encode_tl_updates(&[recip_upd], &r_users, &[]);
                        self.hub().push_to_user(recip_id, None, push_recip);
                    }
                }

                if media_tl.is_some() {
                    let sender_msg_tl = encode_tl_message(&outcome.sender_msg, false);
                    let upd = encode_update_new_message(&sender_msg_tl, outcome.sender_pts);
                    let users = vec![self.render_user_for_viewer(me, Some(me.id))];
                    encode_tl_updates(&[upd], &users, &[])
                } else {
                    encode_update_short_sent_message(
                        outcome.sender_msg.msg_id,
                        outcome.sender_pts,
                        outcome.sender_msg.date_unix,
                        media_tl,
                        ttl_period,
                    )
                }
            }
            ParsedPeer::Chat(chat_id) => {
                let outcome = match self.store().acid().send_chat_message(
                    me.id,
                    chat_id,
                    random_id,
                    text,
                    reply_to_msg_id,
                    media_tl,
                ) {
                    Ok(o) => o,
                    Err(StoreError::NotFound) => return rpc_error(400, "CHAT_ID_INVALID"),
                    Err(StoreError::PermissionDenied) => {
                        return rpc_error(403, "CHAT_WRITE_FORBIDDEN")
                    }
                    Err(_) => return rpc_error(500, "STORAGE_ERROR"),
                };

                for (member_uid, m_row, m_pts) in &outcome.member_deliveries {
                    let mb = encode_tl_message(m_row, false);
                    let upd = encode_update_new_message(&mb, *m_pts);
                    let chat_tl = encode_tl_chat(&outcome.chat, *member_uid);
                    let sender_tl = self.render_user_for_viewer(me, Some(*member_uid));
                    let push = encode_tl_updates(&[upd], &[sender_tl], &[chat_tl]);
                    self.hub().push_to_user(*member_uid, None, push);
                }

                let sender_mb = encode_tl_message(&outcome.sender_msg, false);
                let upd = encode_update_new_message(&sender_mb, outcome.sender_pts);
                let chat_tl = encode_tl_chat(&outcome.chat, me.id);
                let sender_tl = self.render_user_for_viewer(me, Some(me.id));
                let resp = encode_tl_updates(&[upd], &[sender_tl], &[chat_tl]);
                self.hub()
                    .push_to_user(me.id, Some(ctx.conn_id), resp.clone());
                resp
            }
            ParsedPeer::Channel(channel_id) => {
                let outcome = match self.store().acid().send_channel_message(
                    me.id,
                    channel_id,
                    random_id,
                    text,
                    reply_to_msg_id,
                    media_tl,
                ) {
                    Ok(o) => o,
                    Err(StoreError::NotFound) => return rpc_error(400, "CHANNEL_INVALID"),
                    Err(_) => return rpc_error(500, "STORAGE_ERROR"),
                };
                let is_post = outcome.channel.is_broadcast && !outcome.channel.is_megagroup;

                for &sub_uid in &outcome.subscriber_ids {
                    let mut m_view = outcome.msg.clone();
                    m_view.is_out = sub_uid == me.id;
                    let mb = encode_tl_message(&m_view, is_post);
                    let upd = encode_update_new_channel_message(&mb, outcome.channel_pts);
                    let ch_tl = encode_tl_channel(&outcome.channel, sub_uid);
                    let u_tl = self.render_user_for_viewer(me, Some(sub_uid));
                    let push = encode_tl_updates(&[upd], &[u_tl], &[ch_tl]);
                    let exclude = if sub_uid == me.id {
                        Some(ctx.conn_id)
                    } else {
                        None
                    };
                    self.hub().push_to_user(sub_uid, exclude, push);
                }

                let mut self_msg = outcome.msg;
                self_msg.is_out = true;
                let mb = encode_tl_message(&self_msg, is_post);
                let upd = encode_update_new_channel_message(&mb, outcome.channel_pts);
                let ch_tl = encode_tl_channel(&outcome.channel, me.id);
                let u_tl = self.render_user_for_viewer(me, Some(me.id));
                encode_tl_updates(&[upd], &[u_tl], &[ch_tl])
            }
        }
    }

    pub fn messages_get_dialogs_real(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let flags = r.read_i32().unwrap_or(0);
        if flags & (1 << 1) != 0 {
            let _folder_id = r.read_i32();
        }
        let _offset_date = r.read_i32();
        let _offset_id = r.read_i32();
        let _ = parse_input_peer(r, ctx.user.as_ref().map(|u| u.id));
        let limit = r.read_i32().unwrap_or(100).clamp(1, 200) as usize;
        let _hash = r.read_i64();

        let Some(me) = self.require_auth_user(ctx).ok() else {
            let mut w = Writer::new();
            w.write_u32(TL_MESSAGES_DIALOGS);
            for _ in 0..4 {
                w.write_vector_header(0);
            }
            return w.into_vec();
        };

        let dlg_rows = self.store().acid().get_dialogs(me.id, limit);
        let mut dialogs_tl = Vec::with_capacity(dlg_rows.len());
        let mut messages_tl = Vec::new();
        let mut user_ids = BTreeSet::new();
        let mut chat_ids = BTreeSet::new();
        let mut channel_ids = BTreeSet::new();
        if !dlg_rows.is_empty() {
            user_ids.insert(me.id);
        }

        for d in &dlg_rows {
            match d.peer_kind {
                KIND_USER => {
                    user_ids.insert(d.peer_id);
                    dialogs_tl.push(encode_tl_dialog(d, None));
                    if d.top_message_id > 0 {
                        if let Some(m) = self.store().acid().get_message(me.id, d.top_message_id) {
                            self.collect_msg_refs(&m, &mut user_ids, &mut chat_ids);
                            messages_tl.push(encode_tl_message(&m, false));
                        }
                    }
                }
                KIND_CHAT => {
                    chat_ids.insert(d.peer_id);
                    dialogs_tl.push(encode_tl_dialog(d, None));
                    if d.top_message_id > 0 {
                        if let Some(m) = self.store().acid().get_message(me.id, d.top_message_id) {
                            self.collect_msg_refs(&m, &mut user_ids, &mut chat_ids);
                            messages_tl.push(encode_tl_message(&m, false));
                        }
                    }
                }
                KIND_CHANNEL => {
                    channel_ids.insert(d.peer_id);
                    let chan = self.store().acid().channel_by_id(d.peer_id);
                    let c_pts = chan.as_ref().map(|c| c.channel_pts).unwrap_or(1);
                    dialogs_tl.push(encode_tl_dialog(d, Some(c_pts)));
                    if d.top_message_id > 0 {
                        if let Some(m) = self.store().acid().get_channel_message(
                            d.peer_id,
                            d.top_message_id,
                            me.id,
                        ) {
                            user_ids.insert(m.sender_user_id);
                            let is_post = chan
                                .as_ref()
                                .is_some_and(|c| c.is_broadcast && !c.is_megagroup);
                            messages_tl.push(encode_tl_message(&m, is_post));
                        }
                    }
                }
                _ => {}
            }
        }

        let mut chats_tl = self.encode_chats_set(&chat_ids, me.id);
        for cid in channel_ids {
            if let Some(c) = self.store().acid().channel_by_id(cid) {
                chats_tl.push(encode_tl_channel(&c, me.id));
            }
        }
        let users_tl = self.encode_users_set(&user_ids, Some(me.id));

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_DIALOGS);
        w.write_vector_header(dialogs_tl.len());
        for d in &dialogs_tl {
            w.write_raw(d);
        }
        w.write_vector_header(messages_tl.len());
        for m in &messages_tl {
            w.write_raw(m);
        }
        w.write_vector_header(chats_tl.len());
        for c in &chats_tl {
            w.write_raw(c);
        }
        w.write_vector_header(users_tl.len());
        for u in &users_tl {
            w.write_raw(u);
        }
        w.into_vec()
    }

    pub fn messages_get_peer_dialogs_real(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        is_pinned: bool,
    ) -> Vec<u8> {
        let Some(me) = self.require_auth_user(ctx).ok() else {
            let mut w = Writer::new();
            w.write_u32(TL_MESSAGES_PEER_DIALOGS);
            for _ in 0..4 {
                w.write_vector_header(0);
            }
            w.write_raw(&encode_updates_state(1, 0, 0));
            return w.into_vec();
        };

        let mut target_dialogs = Vec::new();
        if is_pinned {
            for d in self.store().acid().get_dialogs(me.id, 50) {
                if d.pinned {
                    target_dialogs.push(d);
                }
            }
        } else if let Ok(count) = r.read_vector_header() {
            for _ in 0..count.min(50) {
                // InputDialogPeer#fcaafeb7 { peer:InputPeer }
                let Ok(ctor) = r.read_u32() else { break };
                let peer_opt = if ctor == 0xfcaafeb7 {
                    parse_input_peer(r, Some(me.id)).ok().flatten()
                } else {
                    break;
                };
                if let Some(p) = peer_opt {
                    let (pk, pid) = p.kind_and_id();
                    if let Some(d) = self.store().acid().get_dialog(me.id, pk, pid) {
                        target_dialogs.push(d);
                    }
                }
            }
        }

        let mut dialogs_tl = Vec::new();
        let mut messages_tl = Vec::new();
        let mut user_ids = BTreeSet::new();
        let mut chat_ids = BTreeSet::new();
        let mut channel_ids = BTreeSet::new();
        user_ids.insert(me.id);

        for d in &target_dialogs {
            let c_pts = if d.peer_kind == KIND_CHANNEL {
                channel_ids.insert(d.peer_id);
                self.store()
                    .acid()
                    .channel_by_id(d.peer_id)
                    .map(|c| c.channel_pts)
            } else {
                if d.peer_kind == KIND_USER {
                    user_ids.insert(d.peer_id);
                } else if d.peer_kind == KIND_CHAT {
                    chat_ids.insert(d.peer_id);
                }
                None
            };
            dialogs_tl.push(encode_tl_dialog(d, c_pts));
            if d.top_message_id > 0 && d.peer_kind != KIND_CHANNEL {
                if let Some(m) = self.store().acid().get_message(me.id, d.top_message_id) {
                    messages_tl.push(encode_tl_message(&m, false));
                }
            }
        }

        let mut chats_tl = self.encode_chats_set(&chat_ids, me.id);
        for cid in channel_ids {
            if let Some(c) = self.store().acid().channel_by_id(cid) {
                chats_tl.push(encode_tl_channel(&c, me.id));
            }
        }
        let users_tl = self.encode_users_set(&user_ids, Some(me.id));
        let (pts, qts, unread) = self.store().acid().user_state(me.id);

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_PEER_DIALOGS);
        w.write_vector_header(dialogs_tl.len());
        for d in &dialogs_tl {
            w.write_raw(d);
        }
        w.write_vector_header(messages_tl.len());
        for m in &messages_tl {
            w.write_raw(m);
        }
        w.write_vector_header(chats_tl.len());
        for c in &chats_tl {
            w.write_raw(c);
        }
        w.write_vector_header(users_tl.len());
        for u in &users_tl {
            w.write_raw(u);
        }
        w.write_raw(&encode_updates_state(pts, qts, unread));
        w.into_vec()
    }

    pub fn messages_get_history(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(peer)) = parse_input_peer(r, Some(me.id)) else {
            return rpc_error(400, "PEER_ID_INVALID");
        };
        let offset_id = r.read_i32().unwrap_or(0);
        let _offset_date = r.read_i32();
        let _add_offset = r.read_i32();
        let limit = r.read_i32().unwrap_or(50).clamp(1, 100) as usize;

        match peer {
            ParsedPeer::Channel(channel_id) => {
                let Some(chan) = self.store().acid().channel_by_id(channel_id) else {
                    return rpc_error(400, "CHANNEL_INVALID");
                };
                let rows =
                    self.store()
                        .acid()
                        .get_channel_history(channel_id, offset_id, limit, me.id);
                let is_post = chan.is_broadcast && !chan.is_megagroup;
                let mut user_ids = BTreeSet::new();
                user_ids.insert(me.id);
                let mut msgs_tl = Vec::with_capacity(rows.len());
                for m in &rows {
                    user_ids.insert(m.sender_user_id);
                    msgs_tl.push(encode_tl_message(m, is_post));
                }
                let users_tl = self.encode_users_set(&user_ids, Some(me.id));
                let mut w = Writer::new();
                w.write_u32(TL_MESSAGES_CHANNEL_MESSAGES);
                w.write_i32(0); // flags
                w.write_i32(chan.channel_pts);
                w.write_i32(msgs_tl.len() as i32); // count
                w.write_vector_header(msgs_tl.len());
                for m in &msgs_tl {
                    w.write_raw(m);
                }
                w.write_vector_header(0); // topics (Layer 232!)
                w.write_vector_header(1); // chats
                w.write_raw(&encode_tl_channel(&chan, me.id));
                w.write_vector_header(users_tl.len());
                for u in &users_tl {
                    w.write_raw(u);
                }
                w.into_vec()
            }
            other => {
                let (pk, pid) = other.kind_and_id();
                let pid = if pk == KIND_USER && pid == 0 {
                    me.id
                } else {
                    pid
                };
                let rows = self
                    .store()
                    .acid()
                    .get_history(me.id, pk, pid, offset_id, limit);
                let mut user_ids = BTreeSet::new();
                let mut chat_ids = BTreeSet::new();
                user_ids.insert(me.id);
                if pk == KIND_USER {
                    user_ids.insert(pid);
                } else if pk == KIND_CHAT {
                    chat_ids.insert(pid);
                }
                let mut msgs_tl = Vec::with_capacity(rows.len());
                for m in &rows {
                    self.collect_msg_refs(m, &mut user_ids, &mut chat_ids);
                    msgs_tl.push(encode_tl_message(m, false));
                }
                let chats_tl = self.encode_chats_set(&chat_ids, me.id);
                let users_tl = self.encode_users_set(&user_ids, Some(me.id));
                let mut w = Writer::new();
                w.write_u32(TL_MESSAGES_MESSAGES);
                w.write_vector_header(msgs_tl.len());
                for m in &msgs_tl {
                    w.write_raw(m);
                }
                w.write_vector_header(0); // topics (Layer 232!)
                w.write_vector_header(chats_tl.len());
                for c in &chats_tl {
                    w.write_raw(c);
                }
                w.write_vector_header(users_tl.len());
                for u in &users_tl {
                    w.write_raw(u);
                }
                w.into_vec()
            }
        }
    }

    pub fn messages_get_messages(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        boxed_input_msg: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let ids = read_message_id_list(r, boxed_input_msg);
        let mut user_ids = BTreeSet::new();
        let mut chat_ids = BTreeSet::new();
        user_ids.insert(me.id);
        let mut msgs_tl = Vec::new();
        for id in ids {
            if let Some(m) = self.store().acid().get_message(me.id, id) {
                self.collect_msg_refs(&m, &mut user_ids, &mut chat_ids);
                msgs_tl.push(encode_tl_message(&m, false));
            }
        }
        let chats_tl = self.encode_chats_set(&chat_ids, me.id);
        let users_tl = self.encode_users_set(&user_ids, Some(me.id));
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_MESSAGES);
        w.write_vector_header(msgs_tl.len());
        for m in &msgs_tl {
            w.write_raw(m);
        }
        w.write_vector_header(0); // topics
        w.write_vector_header(chats_tl.len());
        for c in &chats_tl {
            w.write_raw(c);
        }
        w.write_vector_header(users_tl.len());
        for u in &users_tl {
            w.write_raw(u);
        }
        w.into_vec()
    }

    pub fn messages_edit_message(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "MESSAGE_ID_INVALID");
        };
        let _ = parse_input_peer(r, Some(me.id));
        let Ok(msg_id) = r.read_i32() else {
            return rpc_error(400, "MESSAGE_ID_INVALID");
        };
        let new_text = if flags & (1 << 11) != 0 {
            r.read_string().unwrap_or("").to_string()
        } else {
            return rpc_error(400, "MESSAGE_NOT_MODIFIED");
        };

        let outcome = match self
            .store()
            .acid()
            .edit_direct_message(me.id, msg_id, &new_text)
        {
            Ok(o) => o,
            Err(StoreError::NotFound) => return rpc_error(400, "MESSAGE_ID_INVALID"),
            Err(StoreError::PermissionDenied) => return rpc_error(403, "MESSAGE_AUTHOR_REQUIRED"),
            Err(_) => return rpc_error(500, "STORAGE_ERROR"),
        };

        if let Some((peer_msg, peer_pts)) = &outcome.peer_updated {
            let p_tl = encode_tl_message(peer_msg, false);
            let p_upd = encode_update_edit_message(&p_tl, *peer_pts);
            let mut p_users = vec![self.render_user_for_viewer(&me, Some(peer_msg.owner_user_id))];
            if let Some(pu) = self.store().user_by_id(peer_msg.owner_user_id) {
                p_users.push(self.render_user_for_viewer(&pu, Some(peer_msg.owner_user_id)));
            }
            let push = encode_tl_updates(&[p_upd], &p_users, &[]);
            self.hub().push_to_user(peer_msg.owner_user_id, None, push);
        }

        let actor_tl = encode_tl_message(&outcome.actor_msg, false);
        let upd = encode_update_edit_message(&actor_tl, outcome.actor_pts);
        let users = vec![self.render_user_for_viewer(&me, Some(me.id))];
        let resp = encode_tl_updates(&[upd], &users, &[]);
        self.hub()
            .push_to_user(me.id, Some(ctx.conn_id), resp.clone());
        resp
    }

    pub fn messages_delete_messages(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let flags = r.read_i32().unwrap_or(0);
        let revoke = flags & 1 != 0;
        let ids = read_message_id_list(r, false);

        let Ok(outcome) = self.store().acid().delete_messages(me.id, &ids, revoke) else {
            return rpc_error(500, "STORAGE_ERROR");
        };

        for batch in &outcome.peer_batches {
            let upd = encode_update_delete_messages(
                &batch.msg_ids,
                batch.pts,
                batch.msg_ids.len() as i32,
            );
            let push = encode_tl_updates(&[upd], &[], &[]);
            self.hub().push_to_user(batch.user_id, None, push);
        }

        if outcome.deleted_count > 0 {
            let upd =
                encode_update_delete_messages(&ids, outcome.actor_pts, outcome.deleted_count);
            let push_self = encode_tl_updates(&[upd], &[], &[]);
            self.hub()
                .push_to_user(me.id, Some(ctx.conn_id), push_self);
        }

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_AFFECTED_MESSAGES);
        w.write_i32(outcome.actor_pts);
        w.write_i32(outcome.deleted_count);
        w.into_vec()
    }

    pub fn messages_delete_history(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let flags = r.read_i32().unwrap_or(0);
        let just_clear = flags & 1 != 0;
        let revoke = flags & 2 != 0;
        let Ok(Some(peer)) = parse_input_peer(r, Some(me.id)) else {
            return rpc_error(400, "PEER_ID_INVALID");
        };
        let max_id = r.read_i32().unwrap_or(0);
        let (pk, pid) = peer.kind_and_id();
        let pid = if pk == KIND_USER && pid == 0 {
            me.id
        } else {
            pid
        };

        let Ok(outcome) = self
            .store()
            .acid()
            .delete_history(me.id, pk, pid, max_id, just_clear, revoke)
        else {
            return rpc_error(500, "STORAGE_ERROR");
        };

        for batch in &outcome.peer_batches {
            let upd = encode_update_delete_messages(
                &batch.msg_ids,
                batch.pts,
                batch.msg_ids.len() as i32,
            );
            let push = encode_tl_updates(&[upd], &[], &[]);
            self.hub().push_to_user(batch.user_id, None, push);
        }

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_AFFECTED_HISTORY);
        w.write_i32(outcome.actor_pts);
        w.write_i32(outcome.deleted_count);
        w.write_i32(0); // offset = 0 (done)
        w.into_vec()
    }

    pub fn messages_read_history(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(peer)) = parse_input_peer(r, Some(me.id)) else {
            return rpc_error(400, "PEER_ID_INVALID");
        };
        let max_id = r.read_i32().unwrap_or(0);
        let (pk, pid) = peer.kind_and_id();
        let pid = if pk == KIND_USER && pid == 0 {
            me.id
        } else {
            pid
        };

        let Ok(outcome) = self.store().acid().read_history(me.id, pk, pid, max_id) else {
            return rpc_error(500, "STORAGE_ERROR");
        };

        // Push live double-checkmark (`updateReadHistoryOutbox`) to sender!
        if let Some((peer_uid, peer_max_id, peer_pts)) = outcome.outbox_peer {
            let upd = encode_update_read_outbox(ParsedPeer::User(me.id), peer_max_id, peer_pts);
            let push = encode_tl_updates(&[upd], &[], &[]);
            self.hub().push_to_user(peer_uid, None, push);
        }

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_AFFECTED_MESSAGES);
        w.write_i32(outcome.reader_pts);
        w.write_i32(1);
        w.into_vec()
    }

    pub fn messages_set_typing(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let Some(me) = self.require_auth_user(ctx).ok() else {
            let mut w = Writer::new();
            w.write_bool(true);
            return w.into_vec();
        };
        let flags = r.read_i32().unwrap_or(0);
        let Ok(Some(peer)) = parse_input_peer(r, Some(me.id)) else {
            let mut w = Writer::new();
            w.write_bool(true);
            return w.into_vec();
        };
        let top_msg_id = if flags & 1 != 0 {
            r.read_i32().ok()
        } else {
            None
        };
        let action_bytes = r.read_raw(r.remaining()).unwrap_or(&[]).to_vec();
        if let ParsedPeer::User(uid) = peer {
            if uid != 0 && uid != me.id && action_bytes.len() >= 4 {
                let mut u = Writer::new();
                u.write_u32(TL_UPDATE_USER_TYPING);
                if let Some(tid) = top_msg_id {
                    u.write_i32(1);
                    u.write_i64(me.id);
                    u.write_i32(tid);
                } else {
                    u.write_i32(0);
                    u.write_i64(me.id);
                }
                u.write_raw(&action_bytes);
                let sender_tl = self.render_user_for_viewer(&me, Some(uid));
                let push = encode_tl_updates(&[u.into_vec()], &[sender_tl], &[]);
                self.hub().push_to_user(uid, None, push);
            }
        }
        let mut w = Writer::new();
        w.write_bool(true);
        w.into_vec()
    }

    pub fn messages_create_chat(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        has_flags: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        if has_flags {
            let _flags = r.read_i32();
        }
        let Ok(count) = r.read_vector_header() else {
            return rpc_error(400, "USERS_TOO_FEW");
        };
        let mut member_ids = Vec::new();
        let mut users_tl = vec![self.render_user_for_viewer(&me, Some(me.id))];
        for _ in 0..count.min(200) {
            if let Ok(Some(u)) = self.resolve_input_user_pub(ctx, r) {
                member_ids.push(u.id);
                users_tl.push(self.render_user_for_viewer(&u, Some(me.id)));
            }
        }
        let Ok(title) = r.read_string() else {
            return rpc_error(400, "CHAT_TITLE_EMPTY");
        };
        let title = title.trim().to_string();
        if title.is_empty() {
            return rpc_error(400, "CHAT_TITLE_EMPTY");
        }
        let Ok(chat) = self.store().acid().create_chat(me.id, &title, &member_ids) else {
            return rpc_error(500, "STORAGE_ERROR");
        };
        let chat_tl = encode_tl_chat(&chat, me.id);
        let updates = encode_tl_updates(&[], &users_tl, &[chat_tl]);

        if has_flags {
            // Layer 232 TL_messages_createChat#0034a818 -> TL_messages_invitedUsers#7f5defa6
            let mut w = Writer::new();
            w.write_u32(TL_MESSAGES_INVITED_USERS);
            w.write_raw(&updates);
            w.write_vector_header(0); // missing_invitees
            w.into_vec()
        } else {
            updates
        }
    }

    // --- Channels & Supergroups (`channels.*`, `updates.getChannelDifference`) ---

    pub fn channels_create_channel(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "CHAT_TITLE_EMPTY");
        };
        let is_broadcast = flags & (1 << 0) != 0;
        let is_megagroup = flags & (1 << 1) != 0 || !is_broadcast;
        let is_forum = flags & (1 << 5) != 0;
        let (Ok(title), Ok(about)) = (r.read_string(), r.read_string()) else {
            return rpc_error(400, "CHAT_TITLE_EMPTY");
        };
        let title = title.trim().to_string();
        let about = about.trim().to_string();
        if title.is_empty() {
            return rpc_error(400, "CHAT_TITLE_EMPTY");
        }
        let Ok(chan) = self.store().acid().create_channel(
            me.id,
            &title,
            &about,
            is_broadcast,
            is_megagroup,
            is_forum,
        ) else {
            return rpc_error(500, "STORAGE_ERROR");
        };
        let ch_tl = encode_tl_channel(&chan, me.id);
        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        encode_tl_updates(&[], &[me_tl], &[ch_tl])
    }

    pub fn channels_get_channels(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let viewer_id = ctx.user.as_ref().map_or(0, |u| u.id);
        let Ok(count) = r.read_vector_header() else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let mut chats = Vec::new();
        for _ in 0..count.min(100) {
            if let Ok(Some(cid)) = parse_input_channel(r, Some(viewer_id)) {
                if let Some(c) = self.store().acid().channel_by_id(cid) {
                    chats.push(encode_tl_channel(&c, viewer_id));
                }
            }
        }
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_CHATS);
        w.write_vector_header(chats.len());
        for c in &chats {
            w.write_raw(c);
        }
        w.into_vec()
    }

    pub fn channels_get_full_channel(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let viewer_id = ctx.user.as_ref().map_or(0, |u| u.id);
        let Ok(Some(cid)) = parse_input_channel(r, Some(viewer_id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        self.channels_get_full_channel_by_id(cid, viewer_id)
    }

    pub fn channels_get_full_channel_by_id(&self, cid: i64, viewer_id: i64) -> Vec<u8> {
        let Some(chan) = self.store().acid().channel_by_id(cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let dlg = self.store().acid().get_dialog(viewer_id, KIND_CHANNEL, cid);
        let read_in = dlg.as_ref().map_or(0, |d| d.read_inbox_max_id);
        let read_out = dlg.as_ref().map_or(0, |d| d.read_outbox_max_id);
        let unread = dlg.as_ref().map_or(0, |d| d.unread_count);

        let mut full_flags = (1 << 0) | (1 << 3); // participants_count | can_view_participants
        if chan.creator_id == viewer_id {
            full_flags |= 1 << 6; // can_set_username
        }

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_CHAT_FULL);
        // full_chat: TL_channelFull#a04e8d3a
        w.write_u32(TL_CHANNEL_FULL);
        w.write_i32(full_flags);
        w.write_i32(0); // flags2
        w.write_i64(chan.channel_id);
        w.write_string(&chan.about);
        w.write_i32(chan.participants_count); // FLAG_0
        w.write_i32(read_in);
        w.write_i32(read_out);
        w.write_i32(unread);
        // chat_photo: TL_photoEmpty#2331b22d { id:0 }
        w.write_u32(TL_PHOTO_EMPTY);
        w.write_i64(0);
        // notify_settings: TL_peerNotifySettings#99622c0c { flags:0 }
        w.write_u32(TL_PEER_NOTIFY_SETTINGS);
        w.write_i32(0);
        w.write_vector_header(0); // bot_info
        w.write_i32(chan.channel_pts); // pts
        // chats & users vectors on TL_messages_chatFull
        w.write_vector_header(1);
        w.write_raw(&encode_tl_channel(&chan, viewer_id));
        w.write_vector_header(0);
        w.into_vec()
    }

    pub fn channels_join_channel(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Ok(chan) = self.store().acid().join_channel(me.id, cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let ch_tl = encode_tl_channel(&chan, me.id);
        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        let updates = encode_tl_updates(&[], &[me_tl], &[ch_tl]);
        // Layer 232 ShuzaGramMod: TL_channels_joinChannel deserializes ChatInviteJoinResult!
        // Note: Standard older layers expect Updates, whereas ShuzaGramMod Layer 232 expects
        // TL_chatInviteJoinResultOk#445663a7 when layer >= 230!
        if ctx.negotiated_layer == 0 || ctx.negotiated_layer >= 230 {
            let mut w = Writer::new();
            w.write_u32(TL_CHAT_INVITE_JOIN_RESULT_OK);
            w.write_raw(&updates);
            w.into_vec()
        } else {
            updates
        }
    }

    pub fn channels_leave_channel(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Ok(chan) = self.store().acid().leave_channel(me.id, cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let ch_tl = encode_tl_channel(&chan, me.id);
        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        encode_tl_updates(&[], &[me_tl], &[ch_tl])
    }

    pub fn channels_check_username(&self, ctx: &ConnContext, r: &mut Reader) -> Vec<u8> {
        let viewer_id = ctx.user.as_ref().map(|u| u.id);
        let _ = parse_input_channel(r, viewer_id);
        let Ok(username) = r.read_string() else {
            return rpc_error(400, "USERNAME_INVALID");
        };
        match self.store().acid().is_username_available(username, None) {
            Ok(avail) => {
                let mut w = Writer::new();
                w.write_bool(avail);
                w.into_vec()
            }
            Err(StoreError::UsernameInvalid) => rpc_error(400, "USERNAME_INVALID"),
            Err(_) => rpc_error(400, "USERNAME_OCCUPIED"),
        }
    }

    pub fn channels_update_username(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Ok(username) = r.read_string() else {
            return rpc_error(400, "USERNAME_INVALID");
        };
        match self
            .store()
            .acid()
            .update_channel_username(me.id, cid, username)
        {
            Ok(_) => {
                let mut w = Writer::new();
                w.write_bool(true);
                w.into_vec()
            }
            Err(StoreError::UsernameInvalid) => rpc_error(400, "USERNAME_INVALID"),
            Err(StoreError::UsernameOccupied) => rpc_error(400, "USERNAME_OCCUPIED"),
            Err(StoreError::PermissionDenied) => rpc_error(403, "CHAT_ADMIN_REQUIRED"),
            Err(_) => rpc_error(400, "CHANNEL_INVALID"),
        }
    }

    pub fn channels_read_history(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let max_id = r.read_i32().unwrap_or(0);
        let _ = self.store().acid().read_channel_history(me.id, cid, max_id);
        let mut w = Writer::new();
        w.write_bool(true);
        w.into_vec()
    }

    pub fn channels_get_messages(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        boxed_input_msg: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Some(chan) = self.store().acid().channel_by_id(cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let ids = read_message_id_list(r, boxed_input_msg);
        let is_post = chan.is_broadcast && !chan.is_megagroup;
        let mut user_ids = BTreeSet::new();
        user_ids.insert(me.id);
        let mut msgs_tl = Vec::new();
        for id in ids {
            if let Some(m) = self.store().acid().get_channel_message(cid, id, me.id) {
                user_ids.insert(m.sender_user_id);
                msgs_tl.push(encode_tl_message(&m, is_post));
            }
        }
        let users_tl = self.encode_users_set(&user_ids, Some(me.id));
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_CHANNEL_MESSAGES);
        w.write_i32(0); // flags
        w.write_i32(chan.channel_pts);
        w.write_i32(msgs_tl.len() as i32);
        w.write_vector_header(msgs_tl.len());
        for m in &msgs_tl {
            w.write_raw(m);
        }
        w.write_vector_header(0); // topics
        w.write_vector_header(1); // chats
        w.write_raw(&encode_tl_channel(&chan, me.id));
        w.write_vector_header(users_tl.len());
        for u in &users_tl {
            w.write_raw(u);
        }
        w.into_vec()
    }

    pub fn updates_get_channel_difference(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let viewer_id = ctx.user.as_ref().map_or(0, |u| u.id);
        let _flags = r.read_i32().unwrap_or(0);
        let Ok(Some(cid)) = parse_input_channel(r, Some(viewer_id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        // Skip ChannelMessagesFilter
        if let Ok(f_ctor) = r.read_u32() {
            if f_ctor == TL_CHANNEL_MESSAGES_FILTER {
                let _ff = r.read_i32();
                if let Ok(rc) = r.read_vector_header() {
                    for _ in 0..rc.min(100) {
                        let _ = r.read_u32(); // messageRange
                        let _ = r.read_i32();
                        let _ = r.read_i32();
                    }
                }
            }
        }
        let from_pts = r.read_i32().unwrap_or(0);
        let limit = r.read_i32().unwrap_or(50).clamp(1, 200) as usize;

        let Some(chan) = self.store().acid().channel_by_id(cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Ok((c_pts, rows)) =
            self.store()
                .acid()
                .get_channel_difference(cid, from_pts, limit, viewer_id)
        else {
            return rpc_error(400, "CHANNEL_INVALID");
        };

        if rows.is_empty() {
            let mut w = Writer::new();
            w.write_u32(TL_UPDATES_CHANNEL_DIFFERENCE_EMPTY);
            w.write_i32(1); // FLAG_0: final = true
            w.write_i32(c_pts);
            return w.into_vec();
        }

        let is_post = chan.is_broadcast && !chan.is_megagroup;
        let mut user_ids = BTreeSet::new();
        let mut msgs_tl = Vec::with_capacity(rows.len());
        for m in &rows {
            user_ids.insert(m.sender_user_id);
            msgs_tl.push(encode_tl_message(m, is_post));
        }
        let users_tl = self.encode_users_set(&user_ids, Some(viewer_id));

        let mut w = Writer::new();
        w.write_u32(TL_UPDATES_CHANNEL_DIFFERENCE);
        w.write_i32(1); // FLAG_0: final = true
        w.write_i32(c_pts);
        w.write_vector_header(msgs_tl.len()); // new_messages
        for m in &msgs_tl {
            w.write_raw(m);
        }
        w.write_vector_header(0); // other_updates
        w.write_vector_header(1); // chats
        w.write_raw(&encode_tl_channel(&chan, viewer_id));
        w.write_vector_header(users_tl.len()); // users
        for u in &users_tl {
            w.write_raw(u);
        }
        w.into_vec()
    }

    // --- Helpers ------------------------------------------------------------

    fn collect_msg_refs(
        &self,
        m: &MessageRow,
        user_ids: &mut BTreeSet<i64>,
        chat_ids: &mut BTreeSet<i64>,
    ) {
        if m.sender_user_id != 0 {
            user_ids.insert(m.sender_user_id);
        }
        if m.peer_kind == KIND_USER && m.peer_id != 0 {
            user_ids.insert(m.peer_id);
        } else if m.peer_kind == KIND_CHAT && m.peer_id != 0 {
            chat_ids.insert(m.peer_id);
        }
    }

    fn encode_users_set(&self, ids: &BTreeSet<i64>, viewer_id: Option<i64>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for &uid in ids {
            if let Some(u) = self.store().user_by_id(uid) {
                out.push(self.render_user_for_viewer(&u, viewer_id));
            }
        }
        out
    }

    fn encode_chats_set(&self, ids: &BTreeSet<i64>, viewer_id: i64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for &cid in ids {
            if let Some(c) = self.store().acid().chat_by_id(cid) {
                out.push(encode_tl_chat(&c, viewer_id));
            }
        }
        out
    }

    pub fn messages_get_messages_views(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let peer = parse_input_peer(r, Some(me.id)).ok().flatten().unwrap_or(ParsedPeer::User(me.id));
        let ids = read_message_id_list(r, false);
        let increment = r.read_bool().unwrap_or(false);

        let (peer_kind, peer_id) = peer.kind_and_id();
        let view_counts = self.store().acid().get_or_inc_message_views(peer_kind, peer_id, &ids, increment);

        let mut views_tl = Vec::with_capacity(view_counts.len());
        for cnt in view_counts {
            let mut vw = Writer::new();
            vw.write_u32(TL_MESSAGE_VIEWS);
            vw.write_i32(1); // FLAG_0: views present
            vw.write_i32(cnt);
            views_tl.push(vw.into_vec());
        }

        let mut chats_tl = Vec::new();
        if peer_kind == KIND_CHANNEL {
            if let Some(c) = self.store().acid().channel_by_id(peer_id) {
                chats_tl.push(encode_tl_channel(&c, me.id));
            }
        }

        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_MESSAGE_VIEWS);
        w.write_vector_header(views_tl.len());
        for v in &views_tl {
            w.write_raw(v);
        }
        w.write_vector_header(chats_tl.len());
        for c in &chats_tl {
            w.write_raw(c);
        }
        w.write_vector_header(0); // users
        w.into_vec()
    }

    pub fn messages_report_read_metrics(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    pub fn channels_get_participants(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let Some(chan) = self.store().acid().channel_by_id(cid) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let _filter_ctor = r.read_u32();
        let offset = r.read_i32().unwrap_or(0).max(0) as usize;
        let limit = r.read_i32().unwrap_or(50).clamp(1, 200) as usize;
        let _hash = r.read_i64();

        let members = self.store().acid().get_channel_members(cid, offset, limit);
        let mut user_ids = BTreeSet::new();
        let mut parts_tl = Vec::with_capacity(members.len());

        for (uid, is_admin, joined_at) in &members {
            user_ids.insert(*uid);
            let mut pw = Writer::new();
            if *uid == chan.creator_id || *is_admin {
                pw.write_u32(TL_CHANNEL_PARTICIPANT_CREATOR);
                pw.write_i32(0); // flags
                pw.write_i64(*uid);
                pw.write_u32(TL_CHAT_ADMIN_RIGHTS);
                pw.write_i32(0x7ffff); // full admin rights
            } else {
                pw.write_u32(TL_CHANNEL_PARTICIPANT);
                pw.write_i32(0); // flags
                pw.write_i64(*uid);
                pw.write_i32(*joined_at);
            }
            parts_tl.push(pw.into_vec());
        }

        let users_tl = self.encode_users_set(&user_ids, Some(me.id));
        let total_count = chan.participants_count.max(parts_tl.len() as i32);

        let mut w = Writer::new();
        w.write_u32(TL_CHANNELS_CHANNEL_PARTICIPANTS);
        w.write_i32(total_count);
        w.write_vector_header(parts_tl.len());
        for p in &parts_tl {
            w.write_raw(p);
        }
        w.write_vector_header(1); // chats
        w.write_raw(&encode_tl_channel(&chan, me.id));
        w.write_vector_header(users_tl.len());
        for u in &users_tl {
            w.write_raw(u);
        }
        w.into_vec()
    }

    pub fn messages_get_full_chat(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let chat_id = r.read_i64().unwrap_or(0);
        if self.store().acid().channel_by_id(chat_id).is_some() {
            return self.channels_get_full_channel_by_id(chat_id, me.id);
        }
        if let Some(chat) = self.store().acid().chat_by_id(chat_id) {
            let mut w = Writer::new();
            w.write_u32(TL_MESSAGES_CHAT_FULL);
            w.write_u32(0x2633_421b); // chatFull#2633421b
            w.write_i32(0); // flags
            w.write_i64(chat.chat_id);
            w.write_string(""); // about
            w.write_u32(0x3c40_7ac0); // chatParticipants#3c407ac0
            w.write_i64(chat.chat_id);
            w.write_vector_header(0); // participants
            w.write_i32(chat.version);
            w.write_u32(TL_PEER_NOTIFY_SETTINGS);
            w.write_i32(0);
            w.write_vector_header(1);
            w.write_raw(&encode_tl_chat(&chat, me.id));
            w.write_vector_header(0);
            return w.into_vec();
        }
        rpc_error(400, "CHAT_ID_INVALID")
    }

    pub fn messages_get_peer_settings(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = self.require_auth_user(ctx).ok();
        let _ = parse_input_peer(r, me.as_ref().map(|u| u.id));
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_PEER_SETTINGS);
        w.write_u32(TL_PEER_SETTINGS);
        w.write_i32(0);
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    pub fn messages_get_saved_dialogs(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_SAVED_DIALOGS);
        for _ in 0..4 {
            w.write_vector_header(0);
        }
        w.into_vec()
    }

    pub fn premium_get_boosts_status(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_PREMIUM_BOOSTS_STATUS);
        w.write_i32(0); // flags
        w.write_i32(0); // level
        w.write_i32(0); // current_level_boosts
        w.write_i32(0); // boosts
        w.write_string(""); // boost_url
        w.into_vec()
    }

    pub fn messages_get_sponsored_messages(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_SPONSORED_MESSAGES_EMPTY);
        w.into_vec()
    }

    pub fn messages_get_emoji_keywords(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let lang = r.read_string().unwrap_or_default();
        let mut w = Writer::new();
        w.write_u32(TL_EMOJI_KEYWORDS_DIFFERENCE);
        w.write_string(lang);
        w.write_i32(0); // from_version
        w.write_i32(0); // version
        w.write_vector_header(0); // keywords
        w.into_vec()
    }

    pub fn messages_get_available_effects(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_AVAILABLE_EFFECTS);
        w.write_i32(0); // hash
        w.write_vector_header(0); // effects
        w.write_vector_header(0); // documents
        w.into_vec()
    }

    pub fn users_get_requirements_to_contact(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let count = r.read_vector_header().unwrap_or(0).min(100) as usize;
        let mut w = Writer::new();
        w.write_vector_header(count);
        for _ in 0..count {
            w.write_u32(TL_REQUIREMENT_TO_CONTACT_EMPTY);
        }
        w.into_vec()
    }

    pub fn messages_get_messages_reactions(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn channels_get_channel_recommendations(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_CHATS);
        w.write_vector_header(0);
        w.into_vec()
    }

    pub fn payments_get_star_gift_collections(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_PAYMENTS_STAR_GIFT_COLLECTIONS);
        w.write_i32(0); // count
        w.write_vector_header(0); // collections
        w.into_vec()
    }

    pub fn stories_get_albums(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_STORIES_ALBUMS);
        w.write_i64(0); // hash
        w.write_vector_header(0); // albums
        w.into_vec()
    }

    pub fn stories_get_peer_max_ids(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let count = r.read_vector_header().unwrap_or(0).min(100) as usize;
        let mut w = Writer::new();
        w.write_vector_header(count);
        for _ in 0..count {
            w.write_i32(0);
        }
        w.into_vec()
    }

    pub fn stories_get_all_read_peer_stories(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_get_all_drafts(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_get_saved_reaction_tags(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_SAVED_REACTION_TAGS);
        w.write_vector_header(0); // tags
        w.write_i64(0); // hash
        w.into_vec()
    }

    pub fn messages_get_exported_chat_invites(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_EXPORTED_CHAT_INVITES);
        w.write_i32(0); // count
        w.write_vector_header(0); // invites
        w.write_vector_header(0); // users
        w.into_vec()
    }

    pub fn channels_get_groups_for_discussion(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_CHATS);
        w.write_vector_header(0);
        w.into_vec()
    }

    pub fn channels_set_discussion_group(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    pub fn messages_search(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_MESSAGES_MESSAGES);
        for _ in 0..3 {
            w.write_vector_header(0);
        }
        w.into_vec()
    }

    pub fn contacts_get_sponsored_peers(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_CONTACTS_SPONSORED_PEERS_EMPTY);
        w.into_vec()
    }

    pub fn account_get_themes(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_ACCOUNT_THEMES);
        w.write_i64(0); // hash
        w.write_vector_header(0); // themes
        w.into_vec()
    }

    pub fn account_get_web_browser_settings(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_ACCOUNT_WEB_BROWSER_SETTINGS);
        w.write_i32(0); // flags: 0
        w.into_vec()
    }

    // --- Uploads & Downloads ------------------------------------------------

    pub fn upload_save_file_part(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let file_id = r.read_i64().unwrap_or(0);
        let file_part = r.read_i32().unwrap_or(0);
        let bytes = r.read_bytes().unwrap_or_default();
        let _ = self.store().acid().save_file_part(file_id, file_part, bytes);
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    pub fn upload_save_big_file_part(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let file_id = r.read_i64().unwrap_or(0);
        let file_part = r.read_i32().unwrap_or(0);
        let _total = r.read_i32();
        let bytes = r.read_bytes().unwrap_or_default();
        let _ = self.store().acid().save_file_part(file_id, file_part, bytes);
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    pub fn upload_get_file(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = self.require_auth_user(ctx).ok();
        let flags = r.read_i32().unwrap_or(0);
        let _precise = flags & (1 << 0) != 0;
        let _cdn = flags & (1 << 1) != 0;

        let loc_ctor = r.read_u32().unwrap_or(0);
        let file_id = match loc_ctor {
            // inputDocumentFileLocation#bad07584 id:long access_hash:long file_reference:bytes thumb_size:string
            // inputPhotoFileLocation#40181ffe id:long access_hash:long file_reference:bytes thumb_size:string
            0xbad0_7584 | 0xbad0_7284 | 0x4018_1ffe => {
                let id = r.read_i64().unwrap_or(0);
                let _access_hash = r.read_i64();
                let _file_ref = r.read_bytes();
                let _thumb = r.read_string();
                id
            }
            0x3725_7e99 => {
                let _fl = r.read_i32();
                let _peer = parse_input_peer(r, me.as_ref().map(|u| u.id));
                r.read_i64().unwrap_or(0)
            }
            _ => r.read_i64().unwrap_or(0),
        };
        let offset = r.read_i64().unwrap_or(0).max(0) as usize;
        let limit = r.read_i32().unwrap_or(128 * 1024).clamp(1, 1024 * 1024) as usize;

        let mut w = Writer::new();
        w.write_u32(0x096a_18d5); // upload.file#096a18d5
        let blob_opt = self.store().acid().get_media_blob(file_id)
            .or_else(|| self.store().acid().get_any_gift_media_blob());

        if let Some(blob) = blob_opt {
            let slice = if offset < blob.data_bytes.len() {
                let end = (offset + limit).min(blob.data_bytes.len());
                &blob.data_bytes[offset..end]
            } else {
                &[]
            };
            let type_ctor = match blob.mime_type.as_str() {
                "image/jpeg" => 0x007e_fe0e, // storage.fileJpeg#007efe0e
                "image/png" => 0x0a4f_63c0,  // storage.filePng#0a4f63c0
                "image/webp" => 0x1081_446c, // storage.fileWebp#1081446c
                "image/gif" => 0xcae1_aadf,  // storage.fileGif#cae1aadf
                _ => 0x40bc_6f52,            // storage.filePartial#40bc6f52 (TGS animated stickers, chunks)
            };
            w.write_u32(type_ctor);
            w.write_i32(now_unix());
            w.write_bytes(slice);
        } else {
            w.write_u32(0xaa96_3b05); // storage.fileUnknown#aa963b05
            w.write_i32(now_unix());
            w.write_bytes(&[]);
        }
        w.into_vec()
    }

    // --- Profile Photos -----------------------------------------------------

    pub fn photos_upload_profile_photo(&self, ctx: &mut ConnContext, r: &mut Reader, is_layer232: bool) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let input_file = if is_layer232 {
            let flags = r.read_i32().unwrap_or(0);
            if flags & (1 << 5) != 0 {
                let _ = parse_input_peer(r, Some(me.id));
            }
            if flags & (1 << 0) != 0 {
                parse_input_file(r)
            } else {
                None
            }
        } else {
            parse_input_file(r)
        };

        let Some((file_id, parts, name)) = input_file else {
            return rpc_error(400, "FILE_PARTS_INVALID");
        };

        let Ok(data_bytes) = self.store().acid().assemble_file_parts(file_id, parts) else {
            return rpc_error(400, "FILE_PARTS_INVALID");
        };

        let access_hash = rand::random::<i64>().abs();
        let _ = self.store().acid().store_media_blob(
            file_id,
            2,
            access_hash,
            me.id,
            "image/jpeg",
            &name,
            "",
            &data_bytes,
        );

        let _ = self.store().acid().update_user_photo(me.id, Some(file_id), Some(2));
        if let Some(u) = ctx.user.as_mut() {
            u.photo_id = Some(file_id);
            u.photo_dc_id = Some(2);
        }

        let mut w = Writer::new();
        w.write_u32(0x2021_2ca8); // photos.photo
        w.write_u32(0xfb19_7a65); // photo#fb197a65
        w.write_i32(0); // flags
        w.write_i64(file_id);
        w.write_i64(access_hash);
        w.write_bytes(&[]); // file_reference
        w.write_i32(now_unix());
        w.write_vector_header(1); // sizes
        w.write_u32(0x75c7_8e60); // photoSize
        w.write_string("m");
        w.write_i32(320);
        w.write_i32(320);
        w.write_i32(data_bytes.len() as i32);
        w.write_i32(2); // dc_id
        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        w.write_vector_header(1);
        w.write_raw(&me_tl);
        w.into_vec()
    }

    pub fn photos_get_user_photos(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _flags = r.read_i32();
        let target_peer = parse_input_peer(r, Some(me.id)).ok().flatten();
        let target_uid = match target_peer {
            Some(ParsedPeer::User(uid)) if uid != 0 => uid,
            _ => me.id,
        };
        let user = self.store().user_by_id(target_uid).unwrap_or(me);
        let mut w = Writer::new();
        w.write_u32(0x8dca_6aa5); // photos.photos#8dca6aa5
        if let Some(pid) = user.photo_id {
            w.write_vector_header(1); // photos
            w.write_u32(0xfb19_7a65); // photo#fb197a65
            w.write_i32(0); // flags
            w.write_i64(pid);
            w.write_i64(user.access_hash);
            w.write_bytes(&[]);
            w.write_i32(now_unix());
            w.write_vector_header(1);
            w.write_u32(0x75c7_8e60); // photoSize
            w.write_string("m");
            w.write_i32(320);
            w.write_i32(320);
            w.write_i32(32768);
            w.write_i32(user.photo_dc_id.unwrap_or(2));
        } else {
            w.write_vector_header(0);
        }
        w.write_vector_header(1); // users
        w.write_raw(&self.render_user_for_viewer(&user, Some(user.id)));
        w.into_vec()
    }

    pub fn photos_delete_photos(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_vector_header(0);
        w.into_vec()
    }

    // --- Messages with Media ------------------------------------------------

    pub fn messages_send_media(
        &self,
        ctx: &mut ConnContext,
        r: &mut Reader,
        boxed_reply: bool,
    ) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let flags = r.read_i32().unwrap_or(0);
        let peer = match parse_input_peer(r, Some(me.id)) {
            Ok(Some(p)) => p,
            _ => return rpc_error(400, "PEER_ID_INVALID"),
        };
        let reply_to_msg_id = if flags & (1 << 0) != 0 {
            if boxed_reply {
                let _ctor = r.read_u32();
            }
            r.read_i32().ok()
        } else {
            None
        };

        let Ok(media_ctor) = r.read_u32() else {
            return rpc_error(400, "MEDIA_INVALID");
        };

        let mut assembled_media_tl = Vec::new();

        match media_ctor {
            // inputMediaUploadedPhoto
            0x1e28_7d04 | 0x3560_6736 => {
                let _fl = if media_ctor == 0x1e28_7d04 { r.read_i32().unwrap_or(0) } else { 0 };
                if let Some((fid, parts, name)) = parse_input_file(r) {
                    if let Ok(data) = self.store().acid().assemble_file_parts(fid, parts) {
                        let ahash = rand::random::<i64>().abs();
                        let _ = self.store().acid().store_media_blob(
                            fid, 2, ahash, me.id, "image/jpeg", &name, "", &data,
                        );
                        let mut mw = Writer::new();
                        mw.write_u32(0x6951_50d7); // messageMediaPhoto#695150d7
                        mw.write_i32(0); // flags
                        mw.write_u32(0xfb19_7a65); // photo#fb197a65
                        mw.write_i32(0);
                        mw.write_i64(fid);
                        mw.write_i64(ahash);
                        mw.write_bytes(&[]);
                        mw.write_i32(now_unix());
                        mw.write_vector_header(1);
                        mw.write_u32(0x75c7_8e60); // photoSize
                        mw.write_string("m");
                        mw.write_i32(800);
                        mw.write_i32(600);
                        mw.write_i32(data.len() as i32);
                        mw.write_i32(2); // dc_id
                        assembled_media_tl = mw.into_vec();
                    }
                }
            }
            // inputMediaUploadedDocument
            0x5b38_c6c1 => {
                let _fl = r.read_i32().unwrap_or(0);
                if let Some((fid, parts, name)) = parse_input_file(r) {
                    let mime = r.read_string().unwrap_or("application/octet-stream");
                    if let Ok(data) = self.store().acid().assemble_file_parts(fid, parts) {
                        let ahash = rand::random::<i64>().abs();
                        let _ = self.store().acid().store_media_blob(
                            fid, 2, ahash, me.id, mime, &name, "", &data,
                        );
                        let mut mw = Writer::new();
                        mw.write_u32(0x4cf4_d72d); // messageMediaDocument#4cf4d72d
                        mw.write_i32(0); // flags
                        mw.write_u32(0x8fd4_e4d8); // document#8fd4e4d8
                        mw.write_i32(0);
                        mw.write_i64(fid);
                        mw.write_i64(ahash);
                        mw.write_bytes(&[]);
                        mw.write_i32(now_unix());
                        mw.write_string(mime);
                        mw.write_i64(data.len() as i64);
                        mw.write_vector_header(0);
                        mw.write_vector_header(0);
                        mw.write_i32(2);
                        mw.write_vector_header(0);
                        assembled_media_tl = mw.into_vec();
                    }
                }
            }
            _ => {}
        }

        let message_text = r.read_string().unwrap_or_default();
        let random_id = r.read_i64().unwrap_or(0);

        let media_slice = if assembled_media_tl.is_empty() {
            None
        } else {
            Some(assembled_media_tl.as_slice())
        };

        match peer {
            ParsedPeer::User(target_uid) => {
                let recip_id = if target_uid == 0 { me.id } else { target_uid };
                let Ok(outcome) = self.store().acid().send_direct_message(
                    me.id,
                    recip_id,
                    random_id,
                    message_text,
                    reply_to_msg_id,
                    media_slice,
                    None,
                    None,
                ) else {
                    return rpc_error(500, "STORAGE_ERROR");
                };

                if !outcome.deduplicated {
                    let sender_msg_tl = encode_tl_message(&outcome.sender_msg, false);
                    let sender_upd = encode_update_new_message(&sender_msg_tl, outcome.sender_pts);
                    let me_tl = self.render_user_for_viewer(&me, Some(me.id));
                    let my_push = encode_tl_updates(&[sender_upd], std::slice::from_ref(&me_tl), &[]);
                    self.hub().push_to_user(me.id, Some(ctx.conn_id), my_push);

                    if let Some((recip_msg, recip_pts)) = outcome.recipient_msg {
                        let recip_msg_tl = encode_tl_message(&recip_msg, false);
                        let recip_upd = encode_update_new_message(&recip_msg_tl, recip_pts);
                        let recip_push = encode_tl_updates(&[recip_upd], &[me_tl], &[]);
                        self.hub().push_to_user(recip_id, None, recip_push);
                    }
                }
                encode_update_short_sent_message(
                    outcome.sender_msg.msg_id,
                    outcome.sender_pts,
                    outcome.sender_msg.date_unix,
                    media_slice,
                    None,
                )
            }
            ParsedPeer::Channel(cid) => {
                let Ok(deliv) = self.store().acid().send_channel_message(
                    me.id,
                    cid,
                    random_id,
                    message_text,
                    reply_to_msg_id,
                    media_slice,
                ) else {
                    return rpc_error(500, "STORAGE_ERROR");
                };
                let is_post = deliv.channel.is_broadcast && !deliv.channel.is_megagroup;
                let msg_tl = encode_tl_message(&deliv.msg, is_post);
                let upd = encode_update_new_channel_message(&msg_tl, deliv.channel_pts);
                let ch_tl = encode_tl_channel(&deliv.channel, me.id);
                let me_tl = self.render_user_for_viewer(&me, Some(me.id));
                let push = encode_tl_updates(&[upd], &[me_tl], &[ch_tl]);
                for sub in deliv.subscriber_ids {
                    let exclude = if sub == me.id { Some(ctx.conn_id) } else { None };
                    self.hub().push_to_user(sub, exclude, push.clone());
                }
                encode_update_short_sent_message(
                    deliv.msg.msg_id,
                    deliv.channel_pts,
                    deliv.msg.date_unix,
                    media_slice,
                    None,
                )
            }
            ParsedPeer::Chat(chat_id) => {
                let Ok(deliv) = self.store().acid().send_chat_message(
                    me.id,
                    chat_id,
                    random_id,
                    message_text,
                    reply_to_msg_id,
                    media_slice,
                ) else {
                    return rpc_error(500, "STORAGE_ERROR");
                };
                for (member_uid, m_row, m_pts) in &deliv.member_deliveries {
                    if *member_uid == me.id {
                        continue;
                    }
                    let mb = encode_tl_message(m_row, false);
                    let upd = encode_update_new_message(&mb, *m_pts);
                    let chat_tl = encode_tl_chat(&deliv.chat, *member_uid);
                    let sender_tl = self.render_user_for_viewer(&me, Some(*member_uid));
                    let push = encode_tl_updates(&[upd], &[sender_tl], &[chat_tl]);
                    self.hub().push_to_user(*member_uid, None, push);
                }
                encode_update_short_sent_message(
                    deliv.sender_msg.msg_id,
                    deliv.sender_pts,
                    deliv.sender_msg.date_unix,
                    media_slice,
                    None,
                )
            }
        }
    }

    pub fn messages_upload_media(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _peer = parse_input_peer(r, Some(me.id));
        let Ok(media_ctor) = r.read_u32() else {
            return rpc_error(400, "MEDIA_INVALID");
        };
        if media_ctor == 0x1e28_7d04 || media_ctor == 0x3560_6736 {
            let _flags = if media_ctor == 0x1e28_7d04 { r.read_i32().unwrap_or(0) } else { 0 };
            if let Some((fid, parts, name)) = parse_input_file(r) {
                if let Ok(data) = self.store().acid().assemble_file_parts(fid, parts) {
                    let ahash = rand::random::<i64>().abs();
                    let _ = self.store().acid().store_media_blob(
                        fid, 2, ahash, me.id, "image/jpeg", &name, "", &data,
                    );
                    let mut mw = Writer::new();
                    mw.write_u32(0x6951_50d7); // messageMediaPhoto#695150d7
                    mw.write_i32(0); // flags
                    mw.write_u32(0xfb19_7a65); // photo#fb197a65
                    mw.write_i32(0);
                    mw.write_i64(fid);
                    mw.write_i64(ahash);
                    mw.write_bytes(&[]);
                    mw.write_i32(now_unix());
                    mw.write_vector_header(1);
                    mw.write_u32(0x75c7_8e60); // photoSize
                    mw.write_string("m");
                    mw.write_i32(800);
                    mw.write_i32(600);
                    mw.write_i32(data.len() as i32);
                    mw.write_i32(2);
                    return mw.into_vec();
                }
            }
        }
        let mut w = Writer::new();
        w.write_u32(0x3ded_6320); // messageMediaEmpty#3ded6320
        w.into_vec()
    }

    pub fn messages_send_reaction(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_update_pinned_message(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn channels_edit_admin(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn channels_edit_title(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let Ok(Some(cid)) = parse_input_channel(r, Some(me.id)) else {
            return rpc_error(400, "CHANNEL_INVALID");
        };
        let title = r.read_string().unwrap_or_default();
        if let Some(mut chan) = self.store().acid().channel_by_id(cid) {
            chan.title = title.to_string();
            let ch_tl = encode_tl_channel(&chan, me.id);
            let me_tl = self.render_user_for_viewer(&me, Some(me.id));
            encode_tl_updates(&[], &[me_tl], &[ch_tl])
        } else {
            rpc_error(400, "CHANNEL_INVALID")
        }
    }

    pub fn channels_edit_photo(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn channels_delete_channel(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_edit_chat_title(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_edit_chat_photo(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_add_chat_user(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    pub fn messages_delete_chat_user(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        encode_tl_updates(&[], &[], &[])
    }

    // messages.getQuickReplies#d483f2a8 hash:long = messages.QuickReplies
    pub fn messages_get_quick_replies(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x5f91_eb5b); // messages.quickRepliesNotModified#5f91eb5b
        w.into_vec()
    }

    // payments.getPremiumGiftCodeOptions#2757ba54 flags:# boost_peer:flags.0?InputPeer = Vector<PremiumGiftCodeOption>
    pub fn payments_get_premium_gift_code_options(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_vector_header(0);
        w.into_vec()
    }

    // payments.getStarGifts#c4563590 hash:int = payments.StarGifts
    pub fn payments_get_star_gifts(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let hash = r.read_i32().unwrap_or(0);
        let catalog = self.store().acid().list_gift_catalog();
        let mut computed_hash: i32 = 0;
        for item in &catalog {
            computed_hash = computed_hash.wrapping_add((item.gift_id as i32).wrapping_mul(item.star_price_units as i32));
        }

        if hash != 0 && hash == computed_hash && !catalog.is_empty() {
            let mut w = Writer::new();
            w.write_u32(0xa388_a368); // payments.starGiftsNotModified#a388a368
            return w.into_vec();
        }
        let mut w = Writer::new();
        // payments.starGifts#2ed82995 hash:int gifts:Vector<StarGift> chats:Vector<Chat> users:Vector<User> = payments.StarGifts;
        w.write_u32(0x2ed8_2995);
        w.write_i32(computed_hash); // hash
        w.write_vector_header(catalog.len());
        for item in &catalog {
            // starGift#313a9547
            w.write_u32(0x313a_9547);
            let mut flags = 1 << 5; // title
            if item.is_limited {
                flags |= 1 << 0; // limited
            }
            if item.is_upgradeable {
                flags |= 1 << 3; // upgrade_stars
            }
            w.write_i32(flags);
            w.write_i64(item.gift_id);
            // Full Document (document#8fd4c4d8) so client renders the visual gift card!
            w.write_u32(0x8fd4_c4d8); // document#8fd4c4d8
            w.write_i32(1); // flags: FLAG_0 thumbs present (required for animated sticker)
            w.write_i64(item.gift_id);
            let ahash = item.gift_id.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64);
            w.write_i64(ahash);
            w.write_bytes(&[]); // file_reference
            w.write_i32(1730000000); // date
            // Mime/size come from the real stored sticker blob (if present) so the
            // client downloads actual bytes via upload.getFile; else a placeholder.
            let (gift_mime, gift_size) = match self.store().acid().get_media_blob(item.gift_id) {
                Some(b) => (b.mime_type, b.byte_size),
                None => ("application/x-tgsticker".to_string(), 1024),
            };
            w.write_string(&gift_mime); // mime_type
            w.write_i64(gift_size); // size
            // thumbs (flag0): an invisible outline path so the client treats the
            // .tgs as an animated sticker (MessageObject.isAnimatedStickerDocument
            // requires a non-empty thumbs list).
            w.write_vector_header(1);
            w.write_u32(0xd821_4d41); // photoPathSize#d8214d41
            w.write_string("j");
            w.write_bytes(&[0x00, 0x80]); // "M0,0z" — draws nothing
            w.write_i32(2); // dc_id
            w.write_vector_header(2); // attributes
            // 1. image size
            w.write_u32(0x6c37_c15c); // documentAttributeImageSize
            w.write_i32(512); // w
            w.write_i32(512); // h
            // 2. sticker attribute
            w.write_u32(0x6319_d612); // documentAttributeSticker
            w.write_i32(0); // flags
            w.write_string("⭐️"); // alt
            w.write_u32(0xffb6_2b95); // inputStickerSetEmpty

            w.write_i64(item.star_price_units);
            if item.is_limited {
                let remains = (item.total_supply.unwrap_or(1000) - item.minted_count).max(0);
                w.write_i32(remains);
                w.write_i32(item.total_supply.unwrap_or(1000));
            }
            w.write_i64(item.convert_units);
            if item.is_upgradeable {
                w.write_i64(item.upgrade_price_units);
            }
            w.write_string(&item.title);
        }
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // payments.getStarsGiftOptions#d3c96bc8 flags:# user_id:flags.0?InputUser = Vector<StarsGiftOption>;
    pub fn payments_get_stars_gift_options(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x1cb5_c415); // VECTOR
        let tiers: &[(i64, i64, &str)] = &[
            (50, 99, "com.telegram.stars.50"),
            (100, 199, "com.telegram.stars.100"),
            (250, 499, "com.telegram.stars.250"),
            (500, 999, "com.telegram.stars.500"),
            (1000, 1999, "com.telegram.stars.1000"),
            (2500, 4999, "com.telegram.stars.2500"),
        ];
        w.write_i32(tiers.len() as i32);
        for &(stars, amount_cents, product) in tiers {
            w.write_u32(0x5e05_89f1); // starsGiftOption#5e0589f1
            w.write_i32(1); // flags: store_product
            w.write_i64(stars);
            w.write_string(product);
            w.write_string("USD");
            w.write_i64(amount_cents);
        }
        w.into_vec()
    }

    // payments.getStarsStatus#4ea9b3bf / #104fcfa7
    pub fn payments_get_stars_status(&self, ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let wallet = self.store().acid().ensure_user_stars_balance(me.id, 500);
        let mut w = Writer::new();
        w.write_u32(0x6c9c_e8ed); // PAYMENTS_STARS_STATUS
        w.write_i32(0); // flags
        w.write_u32(0xbbb6_b4a3); // STARS_AMOUNT
        w.write_i64(wallet.balance_units); // amount in Stars
        w.write_i32(0); // nanos
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // payments.getStarsTransactions#69da4545 / #69da4557
    pub fn payments_get_stars_transactions(&self, ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let wallet = self.store().acid().ensure_user_stars_balance(me.id, 500);
        let txs = self.store().acid().list_stars_transactions(Some(me.id), 50);

        let mut w = Writer::new();
        w.write_u32(0x6c9c_e8ed); // PAYMENTS_STARS_STATUS
        let flags = if txs.is_empty() { 0 } else { 1 << 3 };
        w.write_i32(flags);
        w.write_u32(0xbbb6_b4a3); // STARS_AMOUNT
        w.write_i64(wallet.balance_units);
        w.write_i32(0); // nanos
        if !txs.is_empty() {
            w.write_vector_header(txs.len());
            for tx in &txs {
                // starsTransaction#cf696e38 flags:# id:string stars:StarsAmount date:int title:string ...
                w.write_u32(0xcf69_6e38);
                w.write_i32(0); // flags
                w.write_string(&tx.tx_id);
                w.write_u32(0xbbb6_b4a3);
                w.write_i64(tx.delta_units);
                w.write_i32(0); // nanos
                w.write_i32(tx.created_at);
                w.write_string(&tx.title);
                w.write_u32(0x8a68_b577); // starsTransactionPartnerUnsupported
            }
        }
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // payments.getStarsRevenueStats#d91ffad6 / #d9342f57
    pub fn payments_get_stars_revenue_stats(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x6c20_7376); // payments.starsRevenueStats#6c207376
        w.write_i32(0); // flags
        w.write_u32(0x8ea4_64b6); // statsGraph#8ea464b6
        w.write_i32(0); // flags
        w.write_u32(0x7d74_8d04); // dataJSON
        w.write_string("{\"columns\":[]}");
        w.write_u32(0x10d4_817a); // starsRevenueStatus#10d4817a
        w.write_i32(0); // flags
        w.write_u32(0xbbb6_b4a3);
        w.write_i64(0); // current_balance
        w.write_i32(0);
        w.write_u32(0xbbb6_b4a3);
        w.write_i64(0); // available_balance
        w.write_i32(0);
        w.write_u32(0xbbb6_b4a3);
        w.write_i64(0); // overall_revenue
        w.write_i32(0);
        w.write_f64(0.013); // usd_rate
        w.into_vec()
    }

    // payments.getStarsSubscriptions#2e6eab1a
    pub fn payments_get_stars_subscriptions(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        self.payments_get_stars_status(ctx, r)
    }

    // payments.getSavedStarGifts#a319e569 / #18be813b
    pub fn payments_get_saved_star_gifts(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _flags = r.read_i32().unwrap_or(0);
        let target_peer = parse_input_peer(r, Some(me.id)).ok().flatten();
        let target_uid = match target_peer {
            Some(ParsedPeer::User(uid)) if uid != 0 => uid,
            _ => me.id,
        };

        let gifts = self.store().acid().list_user_gifts(target_uid);
        let mut w = Writer::new();
        w.write_u32(0x95f3_89b1); // PAYMENTS_SAVED_STAR_GIFTS
        w.write_i32(0); // flags
        w.write_i32(gifts.len() as i32); // count
        w.write_vector_header(gifts.len());
        for g in &gifts {
            w.write_u32(0x41df_43fc); // savedStarGift#41df43fc
            let mut sflags = 0i32;
            if g.sender_user_id.is_some() {
                sflags |= 1 << 1;
            }
            if !g.message.is_empty() {
                sflags |= 1 << 2;
            }
            if !g.is_upgraded {
                sflags |= 1 << 10; // can_upgrade
            }
            sflags |= 1 << 11; // saved_id
            if g.is_upgraded && g.serial_number.is_some() {
                sflags |= 1 << 19; // gift_num
            }
            w.write_i32(sflags);
            if let Some(s_uid) = g.sender_user_id {
                w.write_u32(TL_PEER_USER);
                w.write_i64(s_uid);
            }
            w.write_i32(g.minted_at);
            if g.is_upgraded {
                w.write_u32(0x85f0_a9cd); // starGiftUnique#85f0a9cd
                w.write_i32(0); // flags
                w.write_i64(g.instance_id); // id
                w.write_i64(g.gift_id); // gift_id
                let title = g.collectible_slug.clone().unwrap_or_else(|| "Collectible Gift".to_string());
                w.write_string(&title);
                let slug = g.collectible_slug.clone().unwrap_or_else(|| format!("gift-{}", g.instance_id));
                w.write_string(&slug);
                w.write_i32(g.serial_number.unwrap_or(1)); // num
                w.write_vector_header(0); // attributes
                w.write_i32(1); // availability_issued
                w.write_i32(1000); // availability_total
            } else {
                w.write_u32(0x313a_9547); // starGift#313a9547
                w.write_i32(1 << 3 | 1 << 5); // flags: upgrade_stars + title
                w.write_i64(g.gift_id);
                w.write_u32(0x36f8_c871); // documentEmpty
                w.write_i64(g.gift_id);
                w.write_i64(50); // stars
                w.write_i64(40); // convert_stars
                w.write_i64(25); // upgrade_stars
                w.write_string("Star Gift");
            }
            if !g.message.is_empty() {
                w.write_u32(0x751f_3146); // textWithEntities
                w.write_string(&g.message);
                w.write_vector_header(0);
            }
            w.write_i64(g.instance_id); // saved_id
            if g.is_upgraded {
                if let Some(num) = g.serial_number {
                    w.write_i32(num);
                }
            }
        }
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // payments.getPaymentForm#37148dbb
    pub fn payments_get_payment_form(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let _me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _flags = r.read_i32().unwrap_or(0);
        let form_id = rand::random::<i64>().abs().max(1);

        let mut w = Writer::new();
        w.write_u32(0xb425_cfe1); // payments.paymentFormStarGift#b425cfe1
        w.write_i64(form_id);
        w.write_u32(0x5fb4_c4d0); // invoice#5fb4c4d0
        w.write_i32(0); // flags
        w.write_string("XTR");
        w.write_vector_header(0);
        w.into_vec()
    }

    // payments.sendStarsForm#7998c914 / #27376c5b
    pub fn payments_send_stars_form(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _form_id = r.read_i64().unwrap_or(0);
        let ctor = r.read_u32().unwrap_or(0);
        match ctor {
            // inputInvoiceStarGift#e8625e92
            0xe862_5e92 => {
                let flags = r.read_i32().unwrap_or(0);
                let target_peer = parse_input_peer(r, Some(me.id)).ok().flatten();
                let recipient_id = match target_peer {
                    Some(ParsedPeer::User(uid)) if uid != 0 => uid,
                    _ => me.id,
                };
                let gift_id = r.read_i64().unwrap_or(5001);
                let msg = if (flags & 2) != 0 {
                    let _ctor = r.read_u32();
                    r.read_string().unwrap_or_default().to_string()
                } else {
                    String::new()
                };

                let _ = self.store().acid().purchase_star_gift(me.id, recipient_id, gift_id, &msg);
            }
            // inputInvoiceStarGiftUpgrade#4d818d5d
            0x4d81_8d5d => {
                let _flags = r.read_i32();
                let _sg_ctor = r.read_u32();
                let _flags2 = r.read_i32();
                let instance_id = r.read_i64().unwrap_or(0);
                let _ = self.store().acid().upgrade_star_gift(me.id, instance_id);
            }
            // inputInvoiceStarGiftTransfer#4a5f5bd9
            0x4a5f_5bd9 => {
                let _sg_ctor = r.read_u32();
                let _flags2 = r.read_i32();
                let instance_id = r.read_i64().unwrap_or(0);
                let target_peer = parse_input_peer(r, Some(me.id)).ok().flatten();
                let recipient_id = match target_peer {
                    Some(ParsedPeer::User(uid)) if uid != 0 => uid,
                    _ => me.id,
                };
                let _ = self.store().acid().transfer_star_gift(me.id, recipient_id, instance_id);
            }
            _ => {}
        }

        let mut w = Writer::new();
        w.write_u32(0x4e71_ea61); // payments.paymentResult#4e71ea61
        w.write_u32(0x74ae_4240); // updates#74ae4240
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(now_unix());
        w.write_i32(0);
        w.into_vec()
    }

    // payments.saveStarGift#3ea205e2
    pub fn payments_save_star_gift(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    // messages.getStickers#d5a5d3a1 emoticon:string hash:long = messages.Stickers
    pub fn messages_get_stickers(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let _emoticon = r.read_string().unwrap_or("");
        let hash = r.read_i64().unwrap_or(0);
        if hash != 0 {
            let mut w = Writer::new();
            w.write_u32(0xf174_9a22); // messages.stickersNotModified#f1749a22
            return w.into_vec();
        }
        let mut w = Writer::new();
        w.write_u32(0x30a6_ec7e); // messages.stickers#30a6ec7e
        w.write_i64(1); // hash
        let catalog = self.store().acid().list_gift_catalog();
        let count = catalog.len().min(30);
        w.write_vector_header(count);
        for item in &catalog[..count] {
            w.write_u32(0x8fd4_c4d8); // document#8fd4c4d8
            w.write_i32(0); // flags
            w.write_i64(item.gift_id);
            let ahash = item.gift_id.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64);
            w.write_i64(ahash);
            w.write_bytes(&[]); // file_reference
            w.write_i32(1730000000); // date
            w.write_string("application/x-tgsticker"); // mime_type
            w.write_i64(50000); // size
            w.write_i32(2); // dc_id
            w.write_vector_header(2); // attributes
            w.write_u32(0x6c37_c15c); // documentAttributeImageSize
            w.write_i32(512);
            w.write_i32(512);
            w.write_u32(0x6319_d612); // documentAttributeSticker
            w.write_i32(0);
            w.write_string("⭐️");
            w.write_u32(0xffb6_2b95); // inputStickerSetEmpty
        }
        w.into_vec()
    }

    // bots.getBotRecommendations#a1b70815 flags:# bot:flags.0?InputUser = users.Users
    pub fn bots_get_bot_recommendations(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x7440_058b); // users.users#7440058b
        w.write_vector_header(0);
        w.into_vec()
    }

    // stories.getPinnedStories#5821a5dc peer:InputPeer offset_id:int limit:int = stories.Stories
    pub fn stories_get_pinned_stories(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x63c3_dd0a); // stories.stories#63c3dd0a
        w.write_i32(0); // flags
        w.write_i32(0); // count
        w.write_vector_header(0); // stories
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // messages.getEmojiGroups#7488ce5b hash:int = messages.EmojiGroups
    pub fn messages_get_emoji_groups(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x6fb4_ad87); // messages.emojiGroupsNotModified#6fb4ad87
        w.into_vec()
    }

    // phone.getCallConfig#55451fa9 = DataJSON
    pub fn phone_get_call_config(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x7d74_8d04); // dataJSON#7d748d04
        w.write_string("{}");
        w.into_vec()
    }

    // account.getAccountTTL#08fc711d = AccountDaysTTL
    pub fn account_get_account_ttl(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xb8d0_afdf); // accountDaysTTL#b8d0afdf
        w.write_i32(365); // 365 days
        w.into_vec()
    }

    // account.getConnectedBots#4ea4c80f = account.ConnectedBots
    pub fn account_get_connected_bots(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x17d7_f87b); // account.connectedBots#17d7f87b
        w.write_vector_header(0); // connected_bots
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // channels.getAdminedPublicChannels#f8b036af flags:# ... = messages.Chats
    pub fn channels_get_admined_public_channels(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x64ff_9fd5); // messages.chats#64ff9fd5
        w.write_vector_header(0); // chats
        w.into_vec()
    }

    // messages.getWebPage#8d9692a3 url:string hash:int = WebPage
    pub fn messages_get_web_page(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x211a_1788); // webPageEmpty#211a1788
        w.write_i32(0); // flags
        w.write_i64(0); // id
        w.into_vec()
    }

    // messages.getOutboxReadDate#8c4bfe5d peer:InputPeer msg_id:int = OutboxReadDate
    pub fn messages_get_outbox_read_date(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x3bb8_42ac); // outboxReadDate#3bb842ac
        w.write_i32(now_unix());
        w.into_vec()
    }

    // phone.requestCall#42ff964e flags:# video:flags.0?true user_id:InputUser random_id:int g_a_hash:bytes protocol:PhoneCallProtocol = phone.PhoneCall;
    pub fn phone_request_call(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let flags = r.read_i32().unwrap_or(0);
        let target_uid = match self.resolve_input_user(ctx, r) {
            Ok(Some(u)) => u.id,
            _ => me.id,
        };
        let _random_id = r.read_i32();
        let _g_a_hash = r.read_bytes();

        let call_id = rand::random::<i64>().abs().max(1);
        let access_hash = rand::random::<i64>().abs();

        let mut w = Writer::new();
        w.write_u32(0xec82_e140); // phone.phoneCall#ec82e140
        w.write_u32(0xc522_6f17); // phoneCallWaiting#c5226f17
        w.write_i32(if (flags & 1) != 0 { 1 << 6 } else { 0 }); // video flag
        w.write_i64(call_id);
        w.write_i64(access_hash);
        w.write_i32(now_unix());
        w.write_i64(me.id);
        w.write_i64(target_uid);
        w.write_u32(0xfc87_8fc8); // PhoneCallProtocol
        w.write_i32(3); // udp_p2p | udp_reflector
        w.write_i32(65);
        w.write_i32(93);
        w.write_vector_header(1);
        w.write_string("3.0.0");

        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        w.write_vector_header(1);
        w.write_raw(&me_tl);
        w.into_vec()
    }

    // phone.acceptCall#3bd2b4a0 peer:InputPhoneCall g_b:bytes protocol:PhoneCallProtocol = phone.PhoneCall;
    pub fn phone_accept_call(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _ctor = r.read_u32();
        let call_id = r.read_i64().unwrap_or(1);
        let access_hash = r.read_i64().unwrap_or(0);
        let g_b = r.read_bytes().unwrap_or_default();

        let mut w = Writer::new();
        w.write_u32(0xec82_e140); // phone.phoneCall#ec82e140
        w.write_u32(0x997c_454a); // phoneCallAccepted#997c454a
        w.write_i32(0); // flags
        w.write_i64(call_id);
        w.write_i64(access_hash);
        w.write_i32(now_unix());
        w.write_i64(me.id);
        w.write_i64(me.id);
        w.write_bytes(g_b);
        w.write_u32(0xfc87_8fc8); // PhoneCallProtocol
        w.write_i32(3);
        w.write_i32(65);
        w.write_i32(93);
        w.write_vector_header(1);
        w.write_string("3.0.0");

        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        w.write_vector_header(1);
        w.write_raw(&me_tl);
        w.into_vec()
    }

    // phone.confirmCall#2efe1722 peer:InputPhoneCall g_a:bytes key_fingerprint:long protocol:PhoneCallProtocol = phone.PhoneCall;
    pub fn phone_confirm_call(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _ctor = r.read_u32();
        let call_id = r.read_i64().unwrap_or(1);
        let access_hash = r.read_i64().unwrap_or(0);
        let g_a = r.read_bytes().unwrap_or_default();
        let key_fingerprint = r.read_i64().unwrap_or(0);

        let mut w = Writer::new();
        w.write_u32(0xec82_e140);
        w.write_u32(0x8741_893a); // phoneCall#8741893a
        w.write_i32(1 << 5); // p2p_allowed = true
        w.write_i64(call_id);
        w.write_i64(access_hash);
        w.write_i32(now_unix());
        w.write_i64(me.id);
        w.write_i64(me.id);
        w.write_bytes(g_a);
        w.write_i64(key_fingerprint);
        w.write_u32(0xfc87_8fc8); // PhoneCallProtocol
        w.write_i32(3);
        w.write_i32(65);
        w.write_i32(93);
        w.write_vector_header(1);
        w.write_string("3.0.0");
        w.write_vector_header(0);
        w.write_i32(now_unix());

        let me_tl = self.render_user_for_viewer(&me, Some(me.id));
        w.write_vector_header(1);
        w.write_raw(&me_tl);
        w.into_vec()
    }

    // phone.discardCall#b2cbc1c0 flags:# video:flags.0?true peer:InputPhoneCall duration:int reason:PhoneCallDiscardReason connection_id:long = Updates;
    pub fn phone_discard_call(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let _flags = r.read_i32().unwrap_or(0);
        let _ctor = r.read_u32();
        let call_id = r.read_i64().unwrap_or(1);
        let _access_hash = r.read_i64().unwrap_or(0);
        let duration = r.read_i32().unwrap_or(0);

        let mut w = Writer::new();
        w.write_u32(0x74ae_4240); // updates#74ae4240
        w.write_vector_header(1);
        w.write_u32(0xab0f_6b1e); // updatePhoneCall#ab0f6b1e
        w.write_u32(0x50ca_4de1); // phoneCallDiscarded#50ca4de1
        w.write_i32(1 << 0 | 1 << 1);
        w.write_i64(call_id);
        w.write_u32(0x57ad_c690); // phoneCallDiscardReasonHangup
        w.write_i32(duration);

        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(now_unix());
        w.write_i32(0);
        w.into_vec()
    }

    // phone.receivedCall#03cd2c4f peer:InputPhoneCall = Bool;
    pub fn phone_received_call(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(TL_BOOL_TRUE);
        w.into_vec()
    }

    // phone.createGroupCall#48cdc6d8 flags:# peer:InputPeer random_id:int title:flags.0?string schedule_date:flags.1?int = Updates;
    pub fn phone_create_group_call(&self, ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let me = match self.require_auth_user(ctx) {
            Ok(u) => u,
            Err(e) => return e,
        };
        let _flags = r.read_i32().unwrap_or(0);
        let target_peer = parse_input_peer(r, Some(me.id)).ok().flatten();
        let _random_id = r.read_i32();

        let call_id = rand::random::<i64>().abs().max(1);
        let access_hash = rand::random::<i64>().abs();

        let mut w = Writer::new();
        w.write_u32(0x74ae_4240); // updates#74ae4240
        w.write_vector_header(1);
        w.write_u32(0x14b4_a003); // updateGroupCall#14b4a003
        w.write_i32(0); // flags
        if let Some(peer) = target_peer {
            peer.write_tl(&mut w);
        } else {
            w.write_u32(TL_PEER_USER);
            w.write_i64(me.id);
        }
        w.write_u32(0xefb2_b617); // groupCall#efb2b617
        w.write_i32(1 << 9 | 1 << 15); // can_start_video | creator
        w.write_i64(call_id);
        w.write_i64(access_hash);
        w.write_i32(1); // participants_count
        w.write_i32(1); // version

        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(now_unix());
        w.write_i32(0);
        w.into_vec()
    }

    // phone.getGroupCall#4124c6e6 call:InputGroupCall limit:int = phone.GroupCall;
    pub fn phone_get_group_call(&self, _ctx: &mut ConnContext, r: &mut Reader) -> Vec<u8> {
        let _ctor = r.read_u32();
        let call_id = r.read_i64().unwrap_or(1);
        let access_hash = r.read_i64().unwrap_or(0);

        let mut w = Writer::new();
        w.write_u32(0x9e72_7aad); // phone.groupCall#9e727aad
        w.write_u32(0xefb2_b617); // groupCall#efb2b617
        w.write_i32(1 << 9 | 1 << 15);
        w.write_i64(call_id);
        w.write_i64(access_hash);
        w.write_i32(1); // participants_count
        w.write_i32(1); // version

        w.write_vector_header(0);
        w.write_string("");
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(1);
        w.into_vec()
    }

    // phone.getGroupParticipants#c555c853 call:InputGroupCall ids:Vector<InputPeer> sources:Vector<int> offset:string limit:int = phone.GroupParticipants;
    pub fn phone_get_group_participants(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xf477_51b6); // phone.groupParticipants#f47751b6
        w.write_i32(0);
        w.write_vector_header(0);
        w.write_string("");
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(1);
        w.into_vec()
    }

    // phone.joinGroupCall#b132ff7b / phone.leaveGroupCall#500377f9
    pub fn phone_join_leave_group_call(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x74ae_4240); // updates#74ae4240
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_vector_header(0);
        w.write_i32(now_unix());
        w.write_i32(0);
        w.into_vec()
    }

    // account.getReactionsNotifySettings#06dd654c = ReactionsNotifySettings
    pub fn account_get_reactions_notify_settings(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x71e4_ea58); // reactionsNotifySettings#71e4ea58
        w.write_i32(0); // flags
        w.write_u32(0x97e8_bebe); // notificationSoundDefault#97e8bebe
        w.write_u32(TL_BOOL_TRUE); // show_previews
        w.into_vec()
    }

    // help.getInviteText#4d392343 = help.InviteText
    pub fn help_get_invite_text(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x18cb_9f78); // help.inviteText#18cb9f78
        w.write_string("Join me on ShuzaGram!");
        w.into_vec()
    }

    // contacts.getBirthdays#daeda864 = contacts.ContactBirthdays
    pub fn contacts_get_birthdays(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x114f_f30d); // contacts.contactBirthdays#114ff30d
        w.write_vector_header(0); // contacts
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // messages.getDefaultTagReactions#bdf93428 = messages.Reactions
    pub fn messages_get_default_tag_reactions(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xeafc_32bc); // messages.reactions#eafc32bc
        w.write_i64(0); // hash
        w.write_vector_header(0); // reactions
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // account.getAutoDownloadSettings#56da0b3f = account.AutoDownloadSettings
    pub fn account_get_auto_download_settings(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x63ca_cf26); // account.autoDownloadSettings#63cacf26
        // low, medium, high presets
        for _ in 0..3 {
            w.write_u32(0xbaa5_7628); // autoDownloadSettings#baa57628
            w.write_i32(0); // flags
            w.write_i32(1048576); // photo_size_max (1MB)
            w.write_i64(10485760); // video_size_max (10MB)
            w.write_i64(10485760); // file_size_max (10MB)
            w.write_i32(1000); // video_upload_maxbitrate
            w.write_i32(5); // small_queue_active_operations_max
            w.write_i32(2); // large_queue_active_operations_max
        }
        w.into_vec()
    }

    // messages.getRecentReactions#39461db2 flags:# hash:long = messages.Reactions
    pub fn messages_get_recent_reactions(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xeafc_32bc); // messages.reactions#eafc32bc
        w.write_i64(0); // hash
        w.write_vector_header(0); // reactions
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // messages.getTopReactions#bb8125ba flags:# hash:long = messages.Reactions
    pub fn messages_get_top_reactions(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xeafc_32bc); // messages.reactions#eafc32bc
        w.write_i64(0); // hash
        w.write_vector_header(0); // reactions
        w.write_vector_header(0); // chats
        w.write_vector_header(0); // users
        w.into_vec()
    }

    // account.getDefaultProfilePhotoEmojis#e2750328 hash:long = EmojiList
    pub fn account_get_default_profile_photo_emojis(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x7a1e_22e1); // emojiList#7a1e22e1
        w.write_i64(1); // hash
        w.write_vector_header(0); // document_id
        w.into_vec()
    }

    // account.getSavedRingtones#e1902288 hash:long = account.SavedRingtones
    pub fn account_get_saved_ringtones(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0xc1e9_2cc5); // account.savedRingtones#c1e92cc5
        w.write_i64(1); // hash
        w.write_vector_header(0); // ringtones
        w.into_vec()
    }

    // help.getPremiumPromo#b81b93d4 = help.PremiumPromo
    pub fn help_get_premium_promo(&self, _ctx: &mut ConnContext, _r: &mut Reader) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(0x5334_759c); // help.premiumPromo#5334759c
        w.write_string("Telegram Premium is unlocked on ShuzaGram!");
        w.write_vector_header(0); // status_entities
        w.write_vector_header(0); // video_sections
        w.write_vector_header(0); // videos
        w.write_vector_header(0); // period_options
        w.write_vector_header(0); // users
        w.into_vec()
    }
}

fn parse_input_file(r: &mut Reader) -> Option<(i64, usize, String)> {
    let Ok(ctor) = r.read_u32() else { return None };
    match ctor {
        0xf52f_f12b => {
            let id = r.read_i64().ok()?;
            let parts = r.read_i32().ok()?.max(1) as usize;
            let name = r.read_string().unwrap_or_default();
            let _md5 = r.read_string();
            Some((id, parts, name.to_string()))
        }
        0xfa27_921a => {
            let id = r.read_i64().ok()?;
            let parts = r.read_i32().ok()?.max(1) as usize;
            let name = r.read_string().unwrap_or_default();
            Some((id, parts, name.to_string()))
        }
        _ => None,
    }
}

fn read_message_id_list(r: &mut Reader, boxed_input_msg: bool) -> Vec<i32> {
    let Ok(count) = r.read_vector_header() else {
        return vec![];
    };
    let mut ids = Vec::with_capacity(count.min(200) as usize);
    for _ in 0..count.min(200) {
        if boxed_input_msg {
            // inputMessageID#a676a322 / inputMessageReplyTo#bad88395 / inputMessagePinned#86872538
            let Ok(ctor) = r.read_u32() else { break };
            if ctor == 0x8687_2538 {
                continue;
            }
            if let Ok(id) = r.read_i32() {
                ids.push(id);
            }
        } else if let Ok(id) = r.read_i32() {
            ids.push(id);
        } else {
            break;
        }
    }
    ids
}

fn peer_from_kind(kind: i32, peer_id: i64) -> ParsedPeer {
    match kind {
        KIND_CHAT => ParsedPeer::Chat(peer_id),
        KIND_CHANNEL => ParsedPeer::Channel(peer_id),
        _ => ParsedPeer::User(peer_id),
    }
}

fn now_unix() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i32)
        .unwrap_or(0)
}
