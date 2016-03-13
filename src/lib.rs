
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

impl KeyPair {
    fn gen() -> KeyPair {
        let (p, s) = box_::gen_keypair();
        KeyPair { p : p, s : s }
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

use rustc_serialize::Encodable;
use rmp_serialize::Encoder;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct RecipSerializable(Vec<u8>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderSerializable(String, (u32, u32), u32, Vec<u8>, Vec<u8>, Vec<RecipSerializable>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderOuterSerializable(Vec<u8>);

#[cfg(test)]
mod test {

    use super::*;
    use sodiumoxide::crypto::box_;
    use sodiumoxide::crypto::secretbox;
    use sodiumoxide::crypto::hash::hash;
    use rustc_serialize::{Encodable, Decodable};
    use rmp_serialize::{Encoder, Decoder};
    use std::mem::size_of;

    #[test]
    fn make_saltpack() {
        let mut sender = KeyPair::gen();
        let mut recipients = Vec::<KeyPair>::new();
        recipients.push(KeyPair::gen());
        recipients.push(KeyPair::gen());
        recipients.push(KeyPair::gen());
        let anonymous = true;

        // 1 Generate a random 32-byte payload key.
        let payload_key : Key = secretbox::gen_key();

        // 2 Generate a random ephemeral keypair, using crypto_box_keypair.
        let eph_key = KeyPair::gen();

        if anonymous {
            sender.p = eph_key.p;
        }

        // 3 Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce `saltpack_sender_key_sbox`, to create the sender secretbox.
        let secretbox_sender_p = secretbox::seal(/*msg*/&sender.p.0,
                                                 /*nonce*/&SBNonce(*b"saltpack_sender_key_sbox"),
                                                 /*key*/&payload_key);

        // 4 For each recipient, encrypt the payload key using crypto_box with the recipient's public key, the ephemeral private key, and the nonce saltpack_payload_key_box. Pair these with the recipients' public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
        let mut recipients_list = Vec::<_>::with_capacity(recipients.len());
        let mut bufsize_for_recipients = 0usize;
        for recip_key in recipients.iter() {
            let cryptobox_payloadkey_for_recipient = box_::seal(/*msg*/&payload_key.0,
                                                 /*nonce*/&CBNonce(*b"saltpack_payload_key_box"),
                                                 /*p key*/&recip_key.p,
                                                 /*s key*/&eph_key.s);
            let recip_pair = RecipSerializable(cryptobox_payloadkey_for_recipient,
                                               Vec::from(&recip_key.p.0[..]));
            bufsize_for_recipients += recip_pair.0.len() + recip_pair.1.len();
            recipients_list.push(recip_pair);
        }

        // 5 Collect the format name, version, and mode into a list, followed by the ephemeral public key, the sender secretbox, and the nested recipients list.
        let mode = SaltpackMessageType::ENCRYPTEDMESSAGE;
        let header = HeaderSerializable ( "saltpack".to_string(),
                                          (1, 0),
                                          mode.to_int(),
                                          Vec::from(&eph_key.p.0[..]),
                                          secretbox_sender_p,
                                          recipients_list);
        println!("{:?}", header);
        // 6 Serialize the list from #5 into a MessagePack array object.
        // estimate buf size
        let mut bufsize = size_of::<HeaderSerializable>()
                        + header.0.len()
                        + header.3.len()
                        + header.4.len()
                        + header.5.len() * (size_of::<RecipSerializable>() + 2)
                        + bufsize_for_recipients
                        + 10; // backup;
        let mut header_inner_mp = Vec::<u8>::with_capacity(bufsize);

        header.encode(&mut Encoder::new(&mut header_inner_mp)).unwrap();

        // 7 Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.
        let headerhash = hash(&header_inner_mp[..]);

        // 8 Serialize the bytes from #6 again into a MessagePack bin object. These twice-encoded bytes are the header packet.

        let mut header_outer_mp = Vec::<u8>::with_capacity(header_inner_mp.len() + 10);
        headerpacket::print_debug_as_str(&header_inner_mp[..]);
        let header_outer = HeaderOuterSerializable( header_inner_mp );
        header_outer.encode(&mut Encoder::new(&mut header_outer_mp)).unwrap();

        // After generating the header, the sender computes the MAC keys, which will be used below to authenticate the payload:
        // 9 For each recipient, encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term private key, and the first 24 bytes of the header hash from #8 as a nonce. Take the last 32 bytes of each box. These are the MAC keys.
        let zeros = [0u8; 32]; // 32 zeros
        let mut nonce = [0; 24];
        for (hh, n) in headerhash.0.iter().zip(nonce.iter_mut()) {*n = *hh; }
        let nonce = CBNonce(nonce);
        let mut mac_keys = Vec::with_capacity(recipients.len());
        for recip_key in recipients.iter() {
            let mut mac_box = box_::seal(/*msg*/&zeros,
                                     /*nonce*/&nonce,
                                     /*p key*/&recip_key.p,
                                     /*s key*/&sender.s);
            mac_box.resize(32, 0);
            mac_keys.push(mac_box);
        }


        panic!("");

    }

    #[test]
    fn gen_key() {
        let key : Key = secretbox::gen_key();
        panic!("{:?}", key);
    }

    #[test]
    fn generate_keypair() {
        let (ourpk, oursk) : ( PublicKey, SecretKey) = box_::gen_keypair();
        assert_eq!(ourpk.0, oursk.0);
    }
}
