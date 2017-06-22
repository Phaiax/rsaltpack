use std;
use SBNonce;

//use errors::*;







/// This trait provides the consume() method.
pub trait Consumable {
    fn consume(&mut self, amt: usize);
}


impl<'a> Consumable for &'a mut [u8] {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, &mut []);
        *self = &mut this[amt..];
    }
}


impl<'a> Consumable for &'a [u8] {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, &[]);
        *self = &this[amt..];
    }
}

impl<'a> Consumable for &'a str {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, "");
        *self = &this[amt..];
    }
}

/// The nonce is `saltpack_ploadsbNNNNNNNN` where `NNNNNNNN` is the packet numer
///  as an 8-byte big-endian unsigned integer. The first payload packet is number 0.
pub fn make_payloadpacket_nonce(packetnumber: u64) -> SBNonce {
    let mut nonce: [u8; 24] = *b"saltpack_ploadsbNNNNNNNN";
    let packetnumber_big_endian = packetnumber.to_be();
    let packetnumber_bytes =
        unsafe { std::slice::from_raw_parts(&packetnumber_big_endian as *const _ as *const u8, 8) };
    for (pn, n) in packetnumber_bytes.iter().zip(nonce.iter_mut().skip(16)) {
        *n = *pn;
    }
    SBNonce(nonce)
}

pub trait TryFrom<T>: Sized {
    type Error;
    fn try_from(value: T) -> ::std::result::Result<Self, Self::Error>;
}

pub trait TryInto<T>: Sized {
    type Error;

    fn try_into(self) -> ::std::result::Result<T, Self::Error>;
}

impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn try_into(self) -> ::std::result::Result<U, U::Error> {
        U::try_from(self)
    }
}
