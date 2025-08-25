#[cfg(not(feature = "with_serde"))]
use alloc::vec::Vec;
#[cfg(not(feature = "with_serde"))]
use binary_sv2::binary_codec_sv2;
#[cfg(feature = "with_serde")]
use binary_sv2::GetSize;
use binary_sv2::{Deserialize, Seq064K, Serialize};
#[cfg(not(feature = "with_serde"))]
use core::convert::TryInto;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RequestExtensions<'decoder> {
    pub request_id: u16,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    pub requested_extensions: Seq064K<'decoder, u16>,
}

/// Successful response to extension negotiation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RequestExtensionsSuccess<'decoder> {
    pub request_id: u16,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    pub supported_extensions: Seq064K<'decoder, u16>,
}

/// Error response to extension negotiation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RequestExtensionsError<'decoder> {
    pub request_id: u16,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    pub requested_extensions: Seq064K<'decoder, u16>,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    pub unsupported_extensions: Seq064K<'decoder, u16>,
}

#[cfg(feature = "with_serde")]
impl<'d> GetSize for RequestExtensions<'d> {
    fn get_size(&self) -> usize {
        self.request_id.get_size() + self.requested_extensions.get_size()
    }
}

#[cfg(feature = "with_serde")]
impl<'d> GetSize for RequestExtensionsSuccess<'d> {
    fn get_size(&self) -> usize {
        self.request_id.get_size() + self.supported_extensions.get_size()
    }
}

#[cfg(feature = "with_serde")]
impl<'d> GetSize for RequestExtensionsError<'d> {
    fn get_size(&self) -> usize {
        self.request_id.get_size()
            + self.requested_extensions.get_size()
            + self.unsupported_extensions.get_size()
    }
}
