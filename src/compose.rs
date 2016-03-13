
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::hash;
use rustc_serialize::Encodable;
use rmp_serialize::Encoder;
use std::mem::size_of;
use std;


#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct RecipSerializable(Vec<u8>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderSerializable(String, (u32, u32), u32, Vec<u8>, Vec<u8>, Vec<RecipSerializable>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderOuterSerializable(Vec<u8>);

use ::{Key, KeyPair, SaltpackMessageType, CBNonce, SBNonce};

pub struct Saltpack {
    payload_key : Key,
    header_hash : Option<Vec<u8>>,
    header_messagepacked : Option<Vec<u8>>,
    macs : Option<Vec<Vec<u8>>>,
    payload_packets : Option<Vec<PayloadPacket>>,
}

pub struct PayloadPacket {
    authenticators : Vec<Vec<u8>>,
    secretbox_payload : Vec<u8>,
}

impl Saltpack {

    pub fn encrypt(sender : Option<&KeyPair>,
                   recipients : &Vec<KeyPair>,
                   payload : &[u8]) -> Saltpack
    {
        // 1 Generate a random 32-byte payload key.
        let payload_key : Key = secretbox::gen_key();

        // 2 Generate a random ephemeral keypair, using crypto_box_keypair.
        let eph_key = KeyPair::gen();

        // Anonymous senders reuse ephemeral keypair
        let sender = if sender.is_none() { &eph_key } else { sender.unwrap() };

        let mut new_saltpack = Saltpack {
            payload_key : payload_key,
            header_hash : None,
            header_messagepacked : None,
            macs : None,
            payload_packets : Some(Vec::new()),
        };

        new_saltpack.compose_saltpack_header(&sender, &eph_key, &recipients);

        new_saltpack.add_payload(&sender, payload, 0);

        new_saltpack
    }

    /// returns payload key and macs
    fn compose_saltpack_header(&mut self,
                               sender : &KeyPair,
                               eph_key : &KeyPair,
                               recipients : &Vec<KeyPair>)
    {

        // 3 Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce `saltpack_sender_key_sbox`, to create the sender secretbox.
        let secretbox_sender_p = secretbox::seal(/*msg*/&sender.p.0,
                                                 /*nonce*/&SBNonce(*b"saltpack_sender_key_sbox"),
                                                 /*key*/&self.payload_key);

        // 4 For each recipient, encrypt the payload key using crypto_box with the recipient's public key, the ephemeral private key, and the nonce saltpack_payload_key_box. Pair these with the recipients' public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
        let mut recipients_list = Vec::<_>::with_capacity(recipients.len());
        let mut bufsize_for_recipients = 0usize;
        for recip_key in recipients.iter() {
            let cryptobox_payloadkey_for_recipient = box_::seal(/*msg*/&self.payload_key.0,
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
        self.header_hash = Some(Vec::from(&headerhash.0[..]));

        // 8 Serialize the bytes from #6 again into a MessagePack bin object. These twice-encoded bytes are the header packet.

        let mut header_outer_mp = Vec::<u8>::with_capacity(header_inner_mp.len() + 10);
        let header_outer = HeaderOuterSerializable( header_inner_mp );
        header_outer.encode(&mut Encoder::new(&mut header_outer_mp)).unwrap();
        self.header_messagepacked = Some(header_outer_mp);

        // After generating the header, the sender computes the MAC keys, which will be used below to authenticate the payload:
        // 9 For each recipient, encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term private key, and the first 24 bytes of the header hash from #8 as a nonce. Take the last 32 bytes of each box. These are the MAC keys.
        let zeros = [0u8; 32]; // 32 zeros
        let mut nonce = [0; 24];
        for (hh, n) in headerhash.0.iter().zip(nonce.iter_mut()) { *n = *hh; }
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
        self.macs = Some(mac_keys);

    }

    pub fn add_payload(&mut self, sender : &KeyPair, payload : &[u8], packetnumber : u64) {

        let authenticators = Vec::<Vec<u8>>::new();
        let secretbox_payload = Vec::<u8>::new();

        // The nonce is saltpack_ploadsbNNNNNNNN where NNNNNNNN is the packet numer as an 8-byte big-endian unsigned integer. The first payload packet is number 0.
        let mut nonce : [u8; 24] = *b"saltpack_ploadsbNNNNNNNN";
        let packetnumber_big_endian = packetnumber.to_be();
        let packetnumber_bytes = unsafe {
            std::slice::from_raw_parts(&packetnumber_big_endian as *const _ as *const u8, 8)
        };
        for (pn, n) in packetnumber_bytes.iter().zip(nonce.iter_mut()) { *n = *pn; }
        let nonce = CBNonce(nonce);

        // 1 Concatenate the header hash, the nonce for the payload secretbox, and the payload secretbox itself.

        let mut cat = Vec::with_capacity(nonce.0.len() + self.header_hash.unwrap().as_ref().len() + secretbox_payload.len());
        cat.extend_from_slice(&self.header_hash.unwrap().as_ref().[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&secretbox_payload[..]);

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1.

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash from #2, using that recipient's MAC key.


        let packet = PayloadPacket {
            authenticators : authenticators,
            secretbox_payload : secretbox_payload,
        };
        let mut packets = self.payload_packets.as_mut().unwrap();
        packets.push(packet);
    }
}
#[cfg(test)]
mod test {

    use super::*;
    use super::super::*;

    #[test]
    fn make_saltpack() {
        let mut sender = KeyPair::gen();
        let mut recipients = Vec::<KeyPair>::new();
        let mut payload = [10u8; 100];
        recipients.push(KeyPair::gen());
        recipients.push(KeyPair::gen());
        recipients.push(KeyPair::gen());
        Saltpack::encrypt(Some(&sender), &recipients, &payload);
        Saltpack::encrypt(None, &recipients, &payload);
    }
}
