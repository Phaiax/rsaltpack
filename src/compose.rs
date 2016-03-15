
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::hash;
use sodiumoxide::crypto::auth;
use rustc_serialize::Encodable;
use rmp_serialize::Encoder;
use std::mem::size_of;
use std::io::{Read, Chain};
use std;


#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct RecipSerializable(Vec<u8>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderSerializable(String, (u32, u32), u32, Vec<u8>, Vec<u8>, Vec<RecipSerializable>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct HeaderOuterSerializable(Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct PayloadPacketSerializable (Vec<Authenticator>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct Authenticator(Vec<u8>);

use ::{Key, PublicKey, KeyPair, SaltpackMessageType, CBNonce, SBNonce};

pub struct Saltpack {
    header_hash : Option<Vec<u8>>,
    header_messagepacked : Option<Vec<u8>>,
    payload_packets : Vec<Vec<u8>>,
    reader : ReaderState,
}

#[derive(PartialEq, Debug)]
pub enum ReaderState {
    HeaderPacket{ptr : usize},
    PayloadPacket{packet : usize, ptr : usize},
    Finished
}



impl Saltpack {


    pub fn encrypt(sender : Option<&KeyPair>,
                   recipients : &Vec<PublicKey>,
                   payload : &[u8]) -> Saltpack
    {
        // 1 Generate a random 32-byte payload key.
        let payload_key : Key = secretbox::gen_key();

        // 2 Generate a random ephemeral keypair, using crypto_box_keypair.
        let eph_key = KeyPair::gen();

        // Anonymous senders reuse ephemeral keypair
        let sender = if sender.is_none() { &eph_key } else { sender.unwrap() };

        let mut new_saltpack = Saltpack {
            header_hash : None,
            header_messagepacked : None,
            payload_packets : Vec::new(),
            reader : ReaderState::HeaderPacket{ptr:0}
        };

        let macs = new_saltpack.compose_saltpack_header(&sender, &recipients, &eph_key, &payload_key);

        for chunk in payload.chunks(1000*1000) {
            new_saltpack.add_payload(&chunk, 0, &payload_key, &macs);
        }

        // finalize
        new_saltpack.add_payload(&[], 0, &payload_key, &macs);

        // wipe keys
        // libodium takes care of that via Drop

        new_saltpack
    }

    /// returns macs
    fn compose_saltpack_header(&mut self,
                               sender : &KeyPair,
                               recipients : &Vec<PublicKey>,
                               eph_key : &KeyPair,
                               payload_key : &Key) -> Vec<auth::Key>
    {

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
                                                 /*p key*/&recip_key,
                                                 /*s key*/&eph_key.s);
            let recip_pair = RecipSerializable(cryptobox_payloadkey_for_recipient,
                                               Vec::from(&recip_key.0[..]));
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
        let bufsize = size_of::<HeaderSerializable>()
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
        let mut macs = Vec::with_capacity(recipients.len());
        for recip_key in recipients.iter() {
            let mut mac_box = box_::seal(/*msg*/&zeros,
                                     /*nonce*/&nonce,
                                     /*p key*/&recip_key,
                                     /*s key*/&sender.s);
            let mac = auth::Key::from_slice(&mac_box[0..32]).unwrap();
            // wipe mac_box
            for b in mac_box.iter_mut() { *b = 0; }

            macs.push(mac);
        }
        macs
    }

    fn add_payload(&mut self,
                   payload : &[u8],
                   packetnumber : u64,
                   payload_key : &Key,
                   macs : &Vec<auth::Key>) {


        // The nonce is saltpack_ploadsbNNNNNNNN where NNNNNNNN is the packet numer as an 8-byte big-endian unsigned integer. The first payload packet is number 0.
        let mut nonce : [u8; 24] = *b"saltpack_ploadsbNNNNNNNN";
        let packetnumber_big_endian = packetnumber.to_be();
        let packetnumber_bytes = unsafe {
            std::slice::from_raw_parts(&packetnumber_big_endian as *const _ as *const u8, 8)
        };
        for (pn, n) in packetnumber_bytes.iter().zip(nonce.iter_mut()) { *n = *pn; }
        let nonce = SBNonce(nonce);

        // The payload secretbox is a NaCl secretbox containing a chunk of the plaintext bytes, max size 1 MB. It's encrypted with the payload key.
        let secretbox_payload = secretbox::seal(/*msg*/&payload[..],
                                                 /*nonce*/&nonce,
                                                 /*key*/&payload_key);



        // 1 Concatenate the header hash, the nonce for the payload secretbox, and the payload secretbox itself.

        let mut cat = Vec::with_capacity(nonce.0.len()
                                        + self.header_hash.as_ref().unwrap().len()
                                        + secretbox_payload.len());
        cat.extend_from_slice(&self.header_hash.as_ref().unwrap()[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&secretbox_payload[..]);

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1.
        let headerhash = hash(&cat[..]);

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash from #2, using that recipient's MAC key.
        let mut authenticators = Vec::new();
        let mut bufsize = secretbox_payload.len() + 12;
        for mac in macs.iter() {
            let tag = auth::authenticate(&headerhash.0, &mac);
            bufsize += tag.0.len() + 2;
            authenticators.push(Authenticator(Vec::from(&tag.0[..])));
        }

        // Compose Packet
        let packet = PayloadPacketSerializable (
            authenticators,
            secretbox_payload,
        );
        let mut packet_messagepacked = Vec::<u8>::with_capacity(bufsize);
        packet.encode(&mut Encoder::new(&mut packet_messagepacked)).unwrap();

        self.payload_packets.push(packet_messagepacked);

    }

    pub fn armor() -> String {
        "".to_string()
    }

}

impl Read for Saltpack {

    /// Recursive. May be a problem for large payloads?
    /// Recursion deph will be buf size in mb
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0;

        if let ReaderState::HeaderPacket{ptr} = self.reader {
            if let Some(ref hp) = self.header_messagepacked {
                let bytes_just_written = try!((&hp[ptr..]).read(&mut buf[bytes_written..]));
                bytes_written += bytes_just_written;
                if ptr == hp.len() {
                    // header finished, continue with first packet
                    self.reader = ReaderState::PayloadPacket{ packet : 0,
                                                              ptr : 0 };
                } else {
                    // buffer full, wait for next read() call
                    self.reader = ReaderState::HeaderPacket { ptr : ptr + bytes_just_written };
                    return Ok(bytes_written);
                }
            } else {
                // No header data found.
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ""));
            }
        }
        while let ReaderState::PayloadPacket{packet, ptr} = self.reader {
            if let Some(ref pp) = self.payload_packets.get(packet) {
                let bytes_just_written = try!((&pp[ptr..]).read(&mut buf[bytes_written..]));
                bytes_written += bytes_just_written;
                if ptr == pp.len() {
                    // packet finished, next packet
                    self.reader = ReaderState::PayloadPacket{ packet : packet + 1,
                                                              ptr : 0 };
                    continue;
                } else {
                    // buffer full, wait for next read() call
                    self.reader = ReaderState::PayloadPacket{ packet : packet,
                                                              ptr : ptr + bytes_just_written };
                    return Ok(bytes_written)
                }
            } else {
                // payload not found or no more payload
                self.reader = ReaderState::Finished;
            }
        }
        if self.reader == ReaderState::Finished {
            Ok(bytes_written)
        } else {
            panic!("should not happen");
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use super::super::*;
    use test::{self, Bencher};

    #[test]
    fn make_saltpack() {
        let sender = KeyPair::gen();
        let mut recipients = Vec::<PublicKey>::new();
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);
        let payload = [10u8; 100];
        Saltpack::encrypt(Some(&sender), &recipients, &payload);
        Saltpack::encrypt(None, &recipients, &payload);
    }

    #[test]
    fn giant_saltpack() {
        let mut recipients = Vec::<PublicKey>::new();
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);

        // todo: make encrypt take either a reference or a writer via some enum
        // let the struct Saltpack store that reference or writer
        // do generate the payload packets on the fly when read() is called
        let payload = vec![10u8; 1000*1000*1000]; // 500mb
        let mut saltpack = Saltpack::encrypt(None, &recipients, &payload);
        let mut buff = Vec::with_capacity(1000*5); // 5mb chunks
        buff.resize(1000*5, 0);
        use std::io::Read;
        while saltpack.read(&mut buff[..]).unwrap() > 0 {
            buff.resize(0, 0);
        }
    }

    #[bench]
    fn bench_encrypt_2mb_100recip(b: &mut Bencher) {
        let sender = KeyPair::gen();
        let mut recipients = Vec::<PublicKey>::new();
        for _ in 0..100 {
            recipients.push(KeyPair::gen().p);
        }
        let payload = [10u8; 2*1000*1000 + 100];

        b.iter(|| {
            let saltpack = Saltpack::encrypt(Some(&sender), &recipients, &payload);
            test::black_box(saltpack.payload_packets);
        });
    }
}
