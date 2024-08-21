use binary_sv2::{
    decodable::FieldMarker,
    encodable::{EncodableField, EncodablePrimitive},
    Error, Fixed, GetMarker, GetSize, Seq064K, Sv2DataType, B032, B064K,
};

use alloc::vec::Vec;
#[cfg(not(feature = "with_serde"))]
use binary_sv2::binary_codec_sv2;
#[cfg(feature = "with_serde")]
use binary_sv2::GetSize;
use binary_sv2::{Deserialize, Serialize, U256};
#[cfg(not(feature = "with_serde"))]
use core::convert::TryInto;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[already_sized]
#[repr(C)]
pub struct Hash256 {
    first: u64,
    second: u64,
    third: u64,
    forth: u64,
}

impl From<[u8; 32]> for Hash256 {
    fn from(data: [u8; 32]) -> Self {
        Self {
            first: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            second: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            third: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            forth: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        }
    }
}

impl From<Hash256> for [u8; 32] {
    fn from(data: Hash256) -> Self {
        let first = data.first.to_le_bytes();
        let second = data.second.to_le_bytes();
        let third = data.third.to_le_bytes();
        let forth = data.forth.to_le_bytes();
        [
            first[0], first[1], first[2], first[3], first[4], first[5], first[6], first[7],
            second[0], second[1], second[2], second[3], second[4], second[5], second[6], second[7],
            third[0], third[1], third[2], third[3], third[4], third[5], third[6], third[7],
            forth[0], forth[1], forth[2], forth[3], forth[4], forth[5], forth[6], forth[7],
        ]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[already_sized]
#[repr(C)]
pub struct Slice {
    // How many shares are in the slice
    pub number_of_shares: u32,
    // Below 2 values ara cached for performance
    // sum of all the difficulties of the shares that compose the slice
    pub difficulty: u64,
    // fees of the ref job for this slice
    pub fees: u64,
    // merkle root of the tree composed by all the shares in the slice
    pub root: Hash256,
    // id of the ref job for this slice
    pub job_id: u64,
}

impl<'a> Slice {
    pub fn seq_into_encodable_field(v: Seq064K<'a, Slice>) -> EncodableField<'a> {
        let inner = v.into_inner();
        let inner_len = inner.len() as u16;
        let mut as_encodable: Vec<EncodableField> = Vec::with_capacity((inner_len + 2) as usize);
        as_encodable.push(EncodableField::Primitive(EncodablePrimitive::OwnedU8(
            inner_len.to_le_bytes()[0],
        )));
        as_encodable.push(EncodableField::Primitive(EncodablePrimitive::OwnedU8(
            inner_len.to_le_bytes()[1],
        )));
        for element in inner {
            as_encodable.push(element.into());
        }
        EncodableField::Struct(as_encodable)
    }
}

impl TryInto<FieldMarker> for Slice {
    type Error = ();
    fn try_into(self) -> Result<FieldMarker, Self::Error> {
        Ok(Slice::get_marker())
    }
}

impl Fixed for Slice {
    const SIZE: usize = 60;
}

impl GetMarker for Slice {
    fn get_marker() -> FieldMarker {
        let markers = vec![
            u32::get_marker(),
            u64::get_marker(),
            u64::get_marker(),
            U256::get_marker(),
            u64::get_marker(),
        ];
        FieldMarker::Struct(markers)
    }
}

impl<'d> Sv2DataType<'d> for Slice {
    fn from_bytes_unchecked(data: &'d mut [u8]) -> Self {
        debug_assert!(data.len() == 60);
        let number_of_shares = u32::from_bytes_unchecked(&mut data[0..4]);
        let difficulty = u64::from_bytes_unchecked(&mut data[4..12]);
        let fees = u64::from_bytes_unchecked(&mut data[12..20]);
        let root_1 = u64::from_bytes_unchecked(&mut data[20..28]);
        let root_2 = u64::from_bytes_unchecked(&mut data[28..36]);
        let root_3 = u64::from_bytes_unchecked(&mut data[36..44]);
        let root_4 = u64::from_bytes_unchecked(&mut data[44..52]);
        let root = Hash256 {
            first: root_1,
            second: root_2,
            third: root_3,
            forth: root_4,
        };
        let job_id = u64::from_bytes_unchecked(&mut data[52..60]);
        Self {
            number_of_shares,
            difficulty,
            fees,
            root,
            job_id,
        }
    }

    fn from_vec_(mut data: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes_(&mut data)
    }

    fn from_vec_unchecked(mut data: Vec<u8>) -> Self {
        Self::from_bytes_unchecked(&mut data)
    }

    fn to_slice_unchecked(&'d self, dst: &mut [u8]) {
        debug_assert!(dst.len() == 60);
        self.number_of_shares.to_slice_unchecked(&mut dst[0..4]);
        self.difficulty.to_slice_unchecked(&mut dst[4..12]);
        self.fees.to_slice_unchecked(&mut dst[12..20]);
        self.root.first.to_slice_unchecked(&mut dst[20..52]);
        self.root.second.to_slice_unchecked(&mut dst[20..52]);
        self.root.third.to_slice_unchecked(&mut dst[20..52]);
        self.root.forth.to_slice_unchecked(&mut dst[20..52]);
        self.job_id.to_slice_unchecked(&mut dst[52..60]);
    }
}

#[cfg(feature = "with_serde")]
impl GetSize for Slice {
    fn get_size(&self) -> usize {
        60
    }
}
#[cfg(feature = "with_serde")]
impl GetSize for Hash256 {
    fn get_size(&self) -> usize {
        32
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[already_sized]
#[repr(C)]
pub struct Share<'decoder> {
    nonce: u32,
    ntime: u32,
    version: u32,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    extranonce: B032<'decoder>,
    job_id: u64,
    reference_job_id: u64,
    #[cfg_attr(feature = "with_serde", serde(borrow))]
    merkle_path: B064K<'decoder>,
}

impl<'a> Share<'a> {
    pub fn seq_into_encodable_field(v: Seq064K<'a, Share<'a>>) -> EncodableField<'a> {
        let inner = v.into_inner();
        let inner_len = inner.len() as u16;
        let mut as_encodable: Vec<EncodableField> = Vec::with_capacity((inner_len + 2) as usize);
        as_encodable.push(EncodableField::Primitive(EncodablePrimitive::OwnedU8(
            inner_len.to_le_bytes()[0],
        )));
        as_encodable.push(EncodableField::Primitive(EncodablePrimitive::OwnedU8(
            inner_len.to_le_bytes()[1],
        )));
        for element in inner {
            as_encodable.push(element.into());
        }
        EncodableField::Struct(as_encodable)
    }
}

impl<'d> GetMarker for Share<'d> {
    fn get_marker() -> FieldMarker {
        let markers = vec![
            u32::get_marker(),
            u32::get_marker(),
            u32::get_marker(),
            B032::get_marker(),
            u64::get_marker(),
            u64::get_marker(),
            B064K::get_marker(),
        ];
        FieldMarker::Struct(markers)
    }
}

impl<'d> GetSize for Share<'d> {
    fn get_size(&self) -> usize {
        self.nonce.get_size()
            + self.ntime.get_size()
            + self.version.get_size()
            + self.extranonce.get_size()
            + self.job_id.get_size()
            + self.reference_job_id.get_size()
            + self.merkle_path.get_size()
    }
}

impl<'d> binary_sv2::SizeHint for Share<'d> {
    // This is not needed
    fn size_hint(_: &[u8], _: usize) -> Result<usize, binary_sv2::Error> {
        todo!()
    }
    fn size_hint_(&self, _: &[u8], _: usize) -> Result<usize, binary_sv2::Error> {
        Ok(self.get_size())
    }
}

impl<'d> TryInto<binary_sv2::decodable::FieldMarker> for Share<'d> {
    type Error = ();
    fn try_into(self) -> Result<binary_sv2::decodable::FieldMarker, Self::Error> {
        Ok(Share::get_marker())
    }
}
impl<'d> Sv2DataType<'d> for Share<'d> {
    fn from_bytes_unchecked(data: &'d mut [u8]) -> Self {
        let nonce = u32::from_bytes_unchecked(&mut data[0..4]);
        let ntime = u32::from_bytes_unchecked(&mut data[4..8]);
        let version = u32::from_bytes_unchecked(&mut data[8..12]);
        let extranonce = B032::from_bytes_unchecked(&mut data[12..]);
        let extranonce = extranonce.into_static();
        let index = extranonce.len() + 12;
        let job_id = u64::from_bytes_unchecked(&mut data[index..index + 8]);
        let reference_job_id = u64::from_bytes_unchecked(&mut data[index + 8..index + 16]);
        let merkle_path = B064K::from_bytes_unchecked(&mut data[index + 16..]);
        Self {
            nonce,
            ntime,
            version,
            extranonce,
            job_id,
            reference_job_id,
            merkle_path,
        }
    }

    fn from_vec_(_data: Vec<u8>) -> Result<Self, Error> {
        unreachable!()
    }

    fn from_vec_unchecked(_data: Vec<u8>) -> Self {
        unreachable!()
    }

    fn to_slice_unchecked(&'d self, dst: &mut [u8]) {
        debug_assert!(dst.len() == 60);
        self.nonce.to_slice_unchecked(&mut dst[0..4]);
        self.ntime.to_slice_unchecked(&mut dst[4..12]);
        self.version.to_slice_unchecked(&mut dst[8..12]);
        self.extranonce.to_slice_unchecked(&mut dst[12..]);
        let index = 12 + self.extranonce.get_size();
        self.job_id.to_slice_unchecked(&mut dst[index..index + 8]);
        self.reference_job_id
            .to_slice_unchecked(&mut dst[index + 8..index + 16]);
        self.merkle_path.to_slice_unchecked(&mut dst[index + 16..]);
    }
}
