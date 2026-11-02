//! ShuzaGram core: the authenticated MTProto session layer, request routing,
//! and the auth RPCs that let a phone number log in.

pub mod dispatch;
pub mod session;
pub mod store;

pub use dispatch::Dispatcher;
pub use session::{Incoming, Session};
pub use store::{Store, User};
