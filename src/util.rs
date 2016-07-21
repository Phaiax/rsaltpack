use std;
use ::SBNonce;



pub fn bytes_to_hex(bin : &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bin.len() * 2);
    for b in bin.iter() {
        write!(out, "{:02x}", b).ok();
    }
    out
}

pub fn hex_to_bytes(hex : &str) -> Result<Vec<u8>, String> {
    use std::error::Error;
    let mut bin = Vec::with_capacity(hex.len() / 2 + 1);
    for b in hex.as_bytes().chunks(2) {
        let c = try!(std::str::from_utf8(&b).map_err(|e| e.description().to_string()));
        bin.push(try!(u8::from_str_radix(&c, 16).map_err(|e| e.description().to_string())));
    }
    Ok(bin)
}



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
        let this = std::mem::replace(self, & []);
        *self = & this[amt..];
    }
}

impl<'a> Consumable for &'a str {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, & "");
        *self = & this[amt..];
    }
}

/// The nonce is saltpack_ploadsbNNNNNNNN where NNNNNNNN is the packet numer
///  as an 8-byte big-endian unsigned integer. The first payload packet is number 0.
pub fn make_payloadpacket_nonce(packetnumber : u64) -> SBNonce {
    let mut nonce : [u8; 24] = *b"saltpack_ploadsbNNNNNNNN";
    let packetnumber_big_endian = packetnumber.to_be();
    let packetnumber_bytes = unsafe {
        std::slice::from_raw_parts(&packetnumber_big_endian as *const _ as *const u8, 8)
    };
    for (pn, n) in packetnumber_bytes.iter().zip(nonce.iter_mut().skip(16)) { *n = *pn; }
    SBNonce(nonce)
}