
#![feature(custom_derive, plugin, alloc, test, try_from)]
#![plugin(serde_macros)]
#![plugin(regex_macros)]

extern crate serde;
extern crate ramp;
extern crate byteorder;
extern crate alloc;
extern crate regex;
extern crate rmp;
extern crate sodiumoxide;
extern crate rmp_serde;
extern crate rmp_serialize;
extern crate rustc_serialize;
extern crate test;

pub mod compose;
pub mod parse;
pub mod armor;
pub mod dearmor;
pub mod util;

pub use sodiumoxide::crypto::box_::PublicKey;
pub use sodiumoxide::crypto::box_::SecretKey;
pub use sodiumoxide::crypto::box_::Nonce as CBNonce;

pub use sodiumoxide::crypto::secretbox::Key;
pub use sodiumoxide::crypto::secretbox::Nonce as SBNonce;

use sodiumoxide::crypto::box_;
use std::string::ToString;
use std::convert::TryFrom;

pub struct KeyPair{ pub p : PublicKey, pub s : SecretKey }

impl KeyPair {
    pub fn gen() -> KeyPair {
        let (p, s) = box_::gen_keypair();
        KeyPair { p : p, s : s }
    }
    // sodiumoxide has implemented Drop for Secretkey -> wipe
}



#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SaltpackMessageType {
    ENCRYPTEDMESSAGE,
    SIGNEDMESSAGE,
    DETACHEDSIGNATURE
}

impl SaltpackMessageType {
    pub fn to_int(&self) -> u32 {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => 0,
            SaltpackMessageType::SIGNEDMESSAGE => 1,
            SaltpackMessageType::DETACHEDSIGNATURE => 2
        }
    }

    pub fn to_str(&self) -> &'static str {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => "ENCRYPTEDMESSAGE",
            SaltpackMessageType::SIGNEDMESSAGE => "SIGNEDMESSAGE",
            SaltpackMessageType::DETACHEDSIGNATURE => "DETACHEDSIGNATURE"
        }
    }
}

impl ToString for SaltpackMessageType {
    fn to_string(&self) -> String {
        self.to_str().to_string()
    }
}


impl<'a> TryFrom<&'a str> for SaltpackMessageType {
    type Err = String;
    fn try_from(ascii : &str) -> Result<Self, Self::Err> {
        match ascii {
            "ENCRYPTEDMESSAGE" => Ok(SaltpackMessageType::ENCRYPTEDMESSAGE),
            "SIGNEDMESSAGE" => Ok(SaltpackMessageType::SIGNEDMESSAGE),
            "DETACHEDSIGNATURE" => Ok(SaltpackMessageType::DETACHEDSIGNATURE),
            e @ _ => Err(format!("No valid saltpack type: {}", e).to_string())
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for SaltpackMessageType {
    type Err = String;
    fn try_from(ascii : &[u8]) -> Result<Self, Self::Err> {
        match ascii {
            b"ENCRYPTEDMESSAGE" => Ok(SaltpackMessageType::ENCRYPTEDMESSAGE),
            b"SIGNEDMESSAGE" => Ok(SaltpackMessageType::SIGNEDMESSAGE),
            b"DETACHEDSIGNATURE" => Ok(SaltpackMessageType::DETACHEDSIGNATURE),
            e @ _ => Err(format!("No valid saltpack type: {}", String::from_utf8_lossy(e)).to_string())
        }
    }
}


#[cfg(test)]
mod tests {

}
