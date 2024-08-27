#![cfg_attr(feature = "no_std", no_std)]

#[macro_use]
extern crate alloc;

mod data_types;
mod error_message;
mod get_shares;
mod get_window;
mod new_block_found;
mod new_txs;
mod share_ok;

pub use data_types::{Hash256, Share, Slice};
pub use share_ok::ShareOk;
pub use new_block_found::NewBlockFound;
pub use get_window::{GetWindow, GetWindowBusy, GetWindowSuccess};
pub use get_shares::{GetShares, GetSharesSuccess};
pub use new_txs::NewTxs;
pub use error_message::ErrorMessage;

pub const EXTENSION_TYPE: u16 = 32;

pub const MESSAGE_TYPE_SHARE_OK: u8 = 0x00;
pub const MESSAGE_TYPE_NEW_BLOCK_FOUND: u8 = 0x01;
pub const MESSAGE_TYPE_GET_WINDOW: u8 = 0x02;
pub const MESSAGE_TYPE_GET_WINDOW_SUCCESS: u8 = 0x03;
pub const MESSAGE_TYPE_GET_WINDOW_BUSY: u8 = 0x04;
pub const MESSAGE_TYPE_GET_SHARES: u8 = 0x05;
pub const MESSAGE_TYPE_GET_SHARES_SUCCESS: u8 = 0x06;
pub const MESSAGE_TYPE_NEW_TXS: u8 = 0x07;
pub const MESSAGE_TYPE_ERROR_MESSAGE: u8 = 0x08;

pub const CHANNEL_BIT_SHARE_OK: bool = false;
pub const CHANNEL_BIT_NEW_BLOCK_FOUND: bool = false;
pub const CHANNEL_BIT_GET_WINDOW: bool = false;
pub const CHANNEL_BIT_GET_WINDOW_SUCCESS: bool = false;
pub const CHANNEL_BIT_GET_WINDOW_BUSY: bool = false;
pub const CHANNEL_BIT_GET_SHARES: bool = false;
pub const CHANNEL_BIT_GET_SHARES_SUCCESS: bool = false;
pub const CHANNEL_BIT_NEW_TXS: bool = false;
pub const CHANNEL_BIT_ERROR_MESSAGE: bool = false;
