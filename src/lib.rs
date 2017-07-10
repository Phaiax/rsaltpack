
#![recursion_limit="128"]

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_bytes;
extern crate rmp; // message pack
extern crate rmp_serde;
extern crate rmpv;

extern crate base64;

#[cfg(feature = "fast_math")]
extern crate ramp;
extern crate byteorder;
//extern crate alloc;
extern crate regex;
extern crate sodiumoxide;
extern crate ring_pwhash;

#[cfg(feature = "num-bigint")]
extern crate num_bigint;
#[cfg(feature = "num-bigint")]
extern crate num_traits;

#[macro_use]
extern crate error_chain;

#[macro_use]
pub mod errors;
pub mod encrypt;
pub mod parse;
pub mod armor;
pub mod dearmor;
pub mod util;
pub mod key;

#[cfg(feature = "num-bigint")]
#[path = "base62_num.rs"]
pub mod base62;

#[cfg(feature = "fast_math")]
#[path = "base62_ramp.rs"]
pub mod base62;

pub use sodiumoxide::crypto::box_::Nonce as CBNonce;

pub use sodiumoxide::crypto::secretbox::Nonce as SBNonce;

use std::string::ToString;
// use std::convert::TryFrom;

use util::TryFrom;


#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SaltpackMessageType {
    ENCRYPTEDMESSAGE,
    SIGNEDMESSAGE,
    DETACHEDSIGNATURE,
}

impl SaltpackMessageType {
    pub fn to_int(&self) -> u32 {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => 0,
            SaltpackMessageType::SIGNEDMESSAGE => 1,
            SaltpackMessageType::DETACHEDSIGNATURE => 2,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => "ENCRYPTED MESSAGE",
            SaltpackMessageType::SIGNEDMESSAGE => "SIGNED MESSAGE",
            SaltpackMessageType::DETACHEDSIGNATURE => "DETACHED SIGNATURE",
        }
    }

    pub fn to_condensed_str(&self) -> &'static str {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => "ENCRYPTEDMESSAGE",
            SaltpackMessageType::SIGNEDMESSAGE => "SIGNEDMESSAGE",
            SaltpackMessageType::DETACHEDSIGNATURE => "DETACHEDSIGNATURE",
        }
    }
}

impl ToString for SaltpackMessageType {
    fn to_string(&self) -> String {
        self.to_str().to_string()
    }
}



impl<'a> TryFrom<&'a str> for SaltpackMessageType {
    type Error = String;
    fn try_from(ascii: &str) -> Result<Self, Self::Error> {
        match ascii {
            "ENCRYPTEDMESSAGE" |
            "ENCRYPTED MESSAGE" => Ok(SaltpackMessageType::ENCRYPTEDMESSAGE),
            "SIGNEDMESSAGE" | "SIGNED MESSAGE" => Ok(SaltpackMessageType::SIGNEDMESSAGE),
            "DETACHEDSIGNATURE" |
            "DETACHED SIGNATURE" => Ok(SaltpackMessageType::DETACHEDSIGNATURE),
            e => Err(format!("No valid saltpack type: {}", e)),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for SaltpackMessageType {
    type Error = String;
    fn try_from(ascii: &[u8]) -> Result<Self, Self::Error> {
        match ascii {
            b"ENCRYPTEDMESSAGE" |
            b"ENCRYPTED MESSAGE" => Ok(SaltpackMessageType::ENCRYPTEDMESSAGE),
            b"SIGNEDMESSAGE" |
            b"SIGNED MESSAGE" => Ok(SaltpackMessageType::SIGNEDMESSAGE),
            b"DETACHEDSIGNATURE" |
            b"DETACHED SIGNATURE" => Ok(SaltpackMessageType::DETACHEDSIGNATURE),
            e => Err(format!(
                "No valid saltpack type: {}",
                String::from_utf8_lossy(e)
            )),
        }
    }
}


#[cfg(test)]
mod tests {}
