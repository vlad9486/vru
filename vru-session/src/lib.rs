// TODO: error handling, recover, replay

#![forbid(unsafe_code)]
#![feature(never_type)]
#![cfg_attr(not(feature = "std"), no_std)]

use rac::generic_array::{GenericArray, typenum::U0};

pub type EmptyLine = GenericArray<u8, U0>;

mod session;
mod channel;

pub use self::session::{Choose, Choose0, Choose1, Choose2, Choose3, Session};
pub use self::channel::{HierarchicError, ChannelError, Channel};
