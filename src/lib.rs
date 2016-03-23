
#![feature(custom_derive, plugin, alloc, test)]
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

pub struct KeyPair{ pub p : PublicKey, pub s : SecretKey }

impl KeyPair {
    pub fn gen() -> KeyPair {
        let (p, s) = box_::gen_keypair();
        KeyPair { p : p, s : s }
    }
    // sodiumoxide has implemented Drop for Secretkey -> wipe
}



#[derive(Debug, PartialEq)]
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
}

use std::string::ToString;
impl ToString for SaltpackMessageType {
    fn to_string(&self) -> String {
        match *self {
            SaltpackMessageType::ENCRYPTEDMESSAGE => "ENCRYPTEDMESSAGE".to_string(),
            SaltpackMessageType::SIGNEDMESSAGE => "SIGNEDMESSAGE".to_string(),
            SaltpackMessageType::DETACHEDSIGNATURE => "DETACHEDSIGNATURE".to_string()
        }
    }
}


#[cfg(test)]
mod tests {

}
