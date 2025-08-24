#![cfg_attr(feature = "no_std", no_std)]

#[macro_use]
extern crate alloc;

mod r#const;
mod data_types;
pub mod parser;
mod messages;

pub use crate::r#const::*;
pub use messages::activate_ext::{Activate, ActivateSuccess};
pub use data_types::{Hash256, PHash, Share, Slice};
pub use messages::error_message::ErrorMessage;
pub use messages::get_shares::{GetShares, GetSharesSuccess};
pub use messages::get_window::{GetWindow, GetWindowBusy, GetWindowSuccess};
pub use messages::error_message;
pub use messages::new_block_found::NewBlockFound;
pub use messages::new_txs::NewTxs;
pub use messages::share_ok::ShareOk;
pub use messages::verify_fees::{
    GetTransationsInJob, GetTransationsInJobSuccess, IdentifyTransations,
    IdentifyTransationsSuccess, ProvideMissinTransactions, ProvideMissinTransactionsSuccess,
};
