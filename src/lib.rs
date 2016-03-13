
#![feature(custom_derive, plugin, alloc)]
#![plugin(serde_macros)]
#![plugin(regex_macros)]

extern crate serde;
extern crate serde_json;
extern crate ramp;
extern crate byteorder;
extern crate alloc;
extern crate regex;
extern crate rmp;
extern crate sodiumoxide;
extern crate rmp_serialize;
extern crate rustc_serialize;

pub mod headerpacket;
pub mod armor;

#[derive(Debug, PartialEq)]
pub enum SaltpackMessageType {
    ENCRYPTEDMESSAGE,
    SIGNEDMESSAGE,
    DETACHEDSIGNATURE
}

pub use sodiumoxide::crypto::box_::PublicKey;
pub use sodiumoxide::crypto::box_::SecretKey;
pub use sodiumoxide::crypto::box_::Nonce as CBNonce;
pub struct KeyPair{ p : PublicKey, s : SecretKey }

pub use sodiumoxide::crypto::secretbox::Key;
pub use sodiumoxide::crypto::secretbox::Nonce as SBNonce;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;

impl KeyPair {
    pub fn gen() -> KeyPair {
        let (p, s) = box_::gen_keypair();
        KeyPair { p : p, s : s }
    }
}

impl Key {
    pub fn gen() -> Key {
        Key(secretbox::gen());
    }
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


#[cfg(test)]
mod test {

    use super::*;

}
