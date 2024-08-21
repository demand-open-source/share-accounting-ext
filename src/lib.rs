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
pub use error_message::ErrorMessage;
pub use get_shares::{GetShares, GetSharesSuccess};
pub use get_window::{GetWindow, GetWindowBusy, GetWindowSuccess};
pub use new_block_found::NewBlockFound;
pub use new_txs::NewTxs;
pub use share_ok::ShareOk;
