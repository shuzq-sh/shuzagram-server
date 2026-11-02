//! MTProto 2.0 `msg_id` 128-slot sliding replay window & 3-slot `server_salt` window.

/// Outcome of validating a client `msg_id` against MTProto 2.0 parity, clock-skew,
/// and 128-slot anti-replay invariants (`MASTER_PLAN.md` §2.4).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MsgIdVerdict {
    /// Fresh, valid client `msg_id` accepted into the window.
    Accept,
    /// Duplicate `msg_id` (already processed) — drop silently per MTProto spec.
    DuplicateReplay,
    /// Invalid client parity (`msg_id & 3 != 0`) -> `bad_msg_notification` code 18.
    BadParity,
    /// `msg_id` too old (`< unix_now - 300s` or behind the 128-slot window) -> code 16.
    TooLow,
    /// `msg_id` too far in the future (`> unix_now + 60s`) -> code 17.
    TooHigh,
}

impl MsgIdVerdict {
    pub const fn bad_msg_error_code(self) -> Option<i32> {
        match self {
            Self::Accept | Self::DuplicateReplay => None,
            Self::TooLow => Some(16),
            Self::TooHigh => Some(17),
            Self::BadParity => Some(18),
        }
    }
}

/// Zero-allocation 128-slot sliding bitmap tracking recent client `msg_id`s
/// within an MTProto `(auth_key_id, session_id)` session.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest_idx: Option<i64>,
    bitmap_128: u128,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest_idx: None,
            bitmap_128: 0,
        }
    }

    /// Reset replay tracking when the client switches `session_id`.
    pub fn reset(&mut self) {
        self.highest_idx = None;
        self.bitmap_128 = 0;
    }

    /// Validate `msg_id` against parity, optional clock window (`max_past_secs = 300`,
    /// `max_future_secs = 60`), and the 128-slot replay bitmap.
    pub fn check_and_record(&mut self, msg_id: i64, now_unix_sec: Option<i64>) -> MsgIdVerdict {
        if msg_id <= 0 || (msg_id & 3) != 0 {
            return MsgIdVerdict::BadParity;
        }
        if let Some(now) = now_unix_sec {
            let msg_ts = msg_id >> 32;
            if msg_ts < now - 300 {
                return MsgIdVerdict::TooLow;
            }
            if msg_ts > now + 60 {
                return MsgIdVerdict::TooHigh;
            }
        }

        // Since client msg_ids step in multiples of >= 4, compress the LSB parity
        // while keeping exact uniqueness for arbitrary monotonic client msg_ids.
        let idx = msg_id >> 2;
        match self.highest_idx {
            None => {
                self.highest_idx = Some(idx);
                self.bitmap_128 = 1;
                MsgIdVerdict::Accept
            }
            Some(hi) if idx > hi => {
                let shift = (idx - hi) as u64;
                if shift >= 128 {
                    self.bitmap_128 = 1;
                } else {
                    self.bitmap_128 = (self.bitmap_128 << shift) | 1;
                }
                self.highest_idx = Some(idx);
                MsgIdVerdict::Accept
            }
            Some(hi) => {
                let diff = (hi - idx) as u64;
                if diff >= 128 {
                    return MsgIdVerdict::TooLow;
                }
                let mask = 1u128 << diff;
                if (self.bitmap_128 & mask) != 0 {
                    MsgIdVerdict::DuplicateReplay
                } else {
                    self.bitmap_128 |= mask;
                    MsgIdVerdict::Accept
                }
            }
        }
    }
}

/// 3-slot rolling `server_salt` validator (`[prev_salt, curr_salt, next_salt]`).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SaltWindow {
    pub prev_salt: i64,
    pub curr_salt: i64,
    pub next_salt: i64,
}

impl SaltWindow {
    pub fn from_primary(salt: i64) -> Self {
        let next = salt.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(1);
        Self {
            prev_salt: salt,
            curr_salt: salt,
            next_salt: next,
        }
    }

    pub const fn accepts(&self, candidate: i64) -> bool {
        candidate == self.curr_salt || candidate == self.prev_salt || candidate == self.next_salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_out_of_order_and_rejects_duplicates() {
        let mut win = ReplayWindow::new();
        let now = 1_760_000_000i64;
        let base = now << 32;

        assert_eq!(win.check_and_record(base + 1, Some(now)), MsgIdVerdict::BadParity);
        assert_eq!(win.check_and_record(base, Some(now)), MsgIdVerdict::Accept);
        assert_eq!(win.check_and_record(base + 8, Some(now)), MsgIdVerdict::Accept);
        assert_eq!(win.check_and_record(base + 4, Some(now)), MsgIdVerdict::Accept);
        // Duplicate replay!
        assert_eq!(
            win.check_and_record(base + 4, Some(now)),
            MsgIdVerdict::DuplicateReplay
        );
        // Clock skew checks
        assert_eq!(
            win.check_and_record((now - 400) << 32, Some(now)),
            MsgIdVerdict::TooLow
        );
        assert_eq!(
            win.check_and_record((now + 120) << 32, Some(now)),
            MsgIdVerdict::TooHigh
        );
    }
}
