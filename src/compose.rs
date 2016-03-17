//! Asymmetrically encrypt or sign data for multiple recipients using the saltpack format.
//!
//! # Usage
//! ```
//! let mut recipients = vec![KeyPair::gen().p];
//!
//! let data : [u8] = b"If I put a usb stick into my ass, \
//!                     does it make me a cyborg already?"
//!
//! // using None as first parameter for anonymous sender
//! let mut saltpack = Saltpack::encrypt(None, &recipients);
//!
//! use std::io::Write;
//! saltpack.write_all(&data[..]).unwrap();
//! saltpack.flush().unwrap();
//!
//! use std::io::Read;
//! let encrypted = vec![u8; 0]; // totally binary data
//! saltpack.read_to_end(encrypted).unwrap();
//!
//! # assert!(saltpack.all_written()); // optional
//! assert!(encrypted.len() > 100);
//! ```
//!
//! You can use Saltpack as a buffer. Saltpack encrypts in chunks
//! of 1 MB (1000000 bytes). Flush after end of write, otherwise a panic
//! will occur. Also read all data, otherwise a panic will occur.
//!
//! ```
//! # let mut recipients = vec![KeyPair::gen().p];
//! # let data : [u8] = [12; 1000000]
//! # // using None as first parameter for anonymous sender
//! # let mut saltpack = Saltpack::encrypt(None, &recipients);
//! use std::io::Write;
//! use std::io::Read;
//! let encrypted = vec![u8; 0];
//!
//! saltpack.write_all(&data[0..500_000]).unwrap(); // only half chunk
//! saltpack.read_to_end(encrypted).unwrap();
//! assert_eq!(encrypted.len() < 1000); // only header written
//!
//! saltpack.write_all(&data[0..1_000_000]).unwrap();
//! saltpack.read_to_end(encrypted).unwrap();
//! assert!(1_000_000 < encrypted.len() < 1_001_000); // 1 chunk written
//!
//! saltpack.flush().unwrap();
//! saltpack.read_to_end(encrypted).unwrap();
//! assert!(1_500_000 < encrypted.len() < 1_501_000); // 1.5 chunks written
//! # assert!(saltpack.all_written()); // optional
//! ```
//!
//! # ASCII armor (only a-z A-Z 0-9 and .)
//!
//! ```
//! let mut saltpack = Saltpack::encrypt(None, & vec![KeyPair::gen().p]);
//! use std::io::Write;
//! saltpack.write_all(&b"secretData").unwrap();
//! saltpack.flush();
//! let mut armored = saltpack.armor("");
//! println!("{}", armored.to_string()); // read all
//! // or use std::io::Read on armored to get ascii character as binary string.
//! ```
//!
//! Take a look at the [`Saltpack`][Saltpack] struct.
//!
//! [Saltpack]: struct.Saltpack.html

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::hash;
use sodiumoxide::crypto::auth;
use rustc_serialize::Encodable;
use rmp_serialize::Encoder;
use std::mem::size_of;
use std::io::{Read, Write};
use std::collections::VecDeque;
use std::string::ToString;
use std;
use std::io;


#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
struct RecipSerializable(Vec<u8>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
struct HeaderSerializable(String, (u32, u32), u32, Vec<u8>, Vec<u8>, Vec<RecipSerializable>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
struct HeaderOuterSerializable(Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
struct PayloadPacketSerializable (Vec<Authenticator>, Vec<u8>);
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
struct Authenticator(Vec<u8>);

use ::{Key, PublicKey, KeyPair, SaltpackMessageType, CBNonce, SBNonce};

pub struct Saltpack {
    header_hash : Option<Vec<u8>>,
    payload_key : Option<Key>,
    macs : Vec<auth::Key>,

    next_packet_number : u64,
    input_buffer : VecDeque<Vec<u8>>,
    flushed : bool,

    bytes_read_from_first : usize,
    output_buffer : VecDeque<Vec<u8>>,
}

pub fn encrypt_to_binary(sender : Option<&KeyPair>,
                      recipients : &Vec<PublicKey>,
                      payload : &[u8]) -> Vec<u8> {
    let mut saltpack = Saltpack::encrypt(sender, recipients);
    saltpack.write_all(payload).unwrap();
    saltpack.flush().unwrap();
    let mut encrypted = Vec::with_capacity((payload.len() as f64 * 1.2) as usize);
    saltpack.read_to_end(&mut encrypted).unwrap();
    encrypted
}

impl Saltpack {

    /// Use this constructor if you want to encrypt data.
    ///
    /// For anonymous sending, set `sender` to `None`.
    pub fn encrypt(sender : Option<&KeyPair>,
                   recipients : &Vec<PublicKey>) -> Saltpack
    {
        // 1 Generate a random 32-byte payload key.
        let payload_key : Key = secretbox::gen_key();

        // 2 Generate a random ephemeral keypair, using crypto_box_keypair.
        let eph_key = KeyPair::gen();

        // Anonymous senders reuse ephemeral keypair
        let sender = if sender.is_none() { &eph_key } else { sender.unwrap() };

        let mut new_saltpack = Saltpack {
            header_hash : None,
            payload_key : Some(payload_key),
            macs : Vec::new(),

            next_packet_number : 0,
            input_buffer : VecDeque::with_capacity(10),
            flushed : false,

            output_buffer : VecDeque::with_capacity(10),
            bytes_read_from_first : 0,
        };

        new_saltpack.compose_saltpack_header(&sender, &recipients, &eph_key);
        new_saltpack
    }

    /// Prevents panic on drop if not all data as been read.
    pub fn cancel(&mut self) {
        self.flushed = true;
        self.payload_key = None;
        self.output_buffer.clear();
        self.input_buffer.clear();
    }

    /// Returns true, if all data has been read from this Saltpack.
    pub fn is_done(&self) -> bool {
        self.flushed && self.input_buffer.is_empty() && self.output_buffer.is_empty()
    }

    /// Consumes self and returns an `ArmoredSaltpack` that outputs the armored
    /// version of the encrypted data.
    ///
    /// ```ignore
    /// BEGIN vendor SALTPACK SIGNED MESSAGE.
    /// kg3sg3u8.
    /// END vendor SALTPACK SIGNED MESSAGE.
    /// ```
    ///
    /// Returns Err if vendor contains chars other than `[a-zA-Z0-9]`.
    pub fn armor(self, vendor : &str) -> Result<ArmoredSaltpack, String> {
        fn in_(c : char, first : char, last : char) -> bool {
            first <= c && c <= last
        }
        for c in vendor.chars() {
            if ! (in_(c, 'a', 'z') || in_(c, 'A', 'Z') || in_(c, '0', '9')) {
                return Err(format!("Invalid char {} in vendor string {}.", c, vendor));
            }
        }
        Ok(ArmoredSaltpack {
            saltpack : self,
            vendor : vendor.to_string()
        })
    }

    /// returns macs
    fn compose_saltpack_header(&mut self,
                               sender : &KeyPair,
                               recipients : &Vec<PublicKey>,
                               eph_key : &KeyPair)
    {

        // 3 Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce `saltpack_sender_key_sbox`, to create the sender secretbox.
        let secretbox_sender_p = secretbox::seal(/*msg*/&sender.p.0,
                                                 /*nonce*/&SBNonce(*b"saltpack_sender_key_sbox"),
                                                 /*key*/&self.payload_key.as_ref().unwrap());

        // 4 For each recipient, encrypt the payload key using crypto_box with the recipient's public key, the ephemeral private key, and the nonce saltpack_payload_key_box. Pair these with the recipients' public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
        let mut recipients_list = Vec::<_>::with_capacity(recipients.len());
        let mut bufsize_for_recipients = 0usize;
        for recip_key in recipients.iter() {
            let cryptobox_payloadkey_for_recipient = box_::seal(/*msg*/&self.payload_key.as_ref().unwrap().0,
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
        self.output_buffer.push_back(header_outer_mp);

        // After generating the header, the sender computes the MAC keys, which will be used below to authenticate the payload:
        // 9 For each recipient, encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term private key, and the first 24 bytes of the header hash from #8 as a nonce. Take the last 32 bytes of each box. These are the MAC keys.
        let zeros = [0u8; 32]; // 32 zeros
        let mut nonce = [0; 24];
        for (hh, n) in headerhash.0.iter().zip(nonce.iter_mut()) { *n = *hh; }
        let nonce = CBNonce(nonce);
        self.macs.reserve_exact(recipients.len());
        for recip_key in recipients.iter() {
            let mut mac_box = box_::seal(/*msg*/&zeros,
                                     /*nonce*/&nonce,
                                     /*p key*/&recip_key,
                                     /*s key*/&sender.s);
            let mac = auth::Key::from_slice(&mac_box[0..32]).unwrap();
            // wipe mac_box
            for b in mac_box.iter_mut() { *b = 0; }

            self.macs.push(mac);
        }
    }

    fn encrypt_next_packet(&mut self) -> bool {
        // only write last package if flushed.
        if self.input_buffer.len() == 1 && ! self.flushed {
            return false;
        }

        // no data
        if self.input_buffer.len() == 0 {
            return false;
        }
        //$ println!("Encr START");

        let next = self.input_buffer.pop_front().unwrap();
        let payload = &next[..];

        let nonce = Self::make_nonce(self.next_packet_number);
        self.next_packet_number += 1;

        // The payload secretbox is a NaCl secretbox containing a chunk of the plaintext bytes, max size 1 MB. It's encrypted with the payload key.
        //$ println!("   Secretbox BEGIN");
        let secretbox_payload = secretbox::seal(/*msg*/&payload[..],
                                                 /*nonce*/&nonce,
                                                 /*key*/&self.payload_key.as_ref().unwrap());
        //$ println!("   Secretbox END");



        // 1 Concatenate the header hash, the nonce for the payload secretbox, and the payload secretbox itself.

        let mut cat = Vec::with_capacity(nonce.0.len()
                                        + self.header_hash.as_ref().unwrap().len()
                                        + secretbox_payload.len());
        cat.extend_from_slice(&self.header_hash.as_ref().unwrap()[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&secretbox_payload[..]);

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1.
        //$ println!("     Hash BEGIN");
        let headerhash = hash(&cat[..]);
        //$ println!("     Hash END");

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash from #2, using that recipient's MAC key.
        let mut authenticators = Vec::new();
        let mut bufsize = secretbox_payload.len() + 12;
        //$ println!("       Auth BEGIN");
        for mac in self.macs.iter() {
            let tag = auth::authenticate(&headerhash.0, &mac);
            bufsize += tag.0.len() + 2;
            authenticators.push(Authenticator(Vec::from(&tag.0[..])));
        }
        //$ println!("       Auth END");

        // Compose Packet
        let packet = PayloadPacketSerializable (
            authenticators,
            secretbox_payload,
        );
        //$ println!("          Encode BEGIN");
        let mut packet_messagepacked = Vec::<u8>::with_capacity(bufsize);
        packet.encode(&mut Encoder::new(&mut packet_messagepacked)).unwrap();
        //$ println!("          Encode END");

        self.output_buffer.push_back(packet_messagepacked);
        //$ println!("              Encr END");
        true
    }

    /// The nonce is saltpack_ploadsbNNNNNNNN where NNNNNNNN is the packet numer
    ///  as an 8-byte big-endian unsigned integer. The first payload packet is number 0.
    fn make_nonce(packetnumber : u64) -> SBNonce {
        let mut nonce : [u8; 24] = *b"saltpack_ploadsbNNNNNNNN";
        let packetnumber_big_endian = packetnumber.to_be();
        let packetnumber_bytes = unsafe {
            std::slice::from_raw_parts(&packetnumber_big_endian as *const _ as *const u8, 8)
        };
        for (pn, n) in packetnumber_bytes.iter().zip(nonce.iter_mut()) { *n = *pn; }
        SBNonce(nonce)
    }


}

/// Will panic if not flushed or not all data read.
impl Drop for Saltpack {
    fn drop(&mut self) {
        if ! self.is_done() {
            panic!("Saltpack not flushed or not read to end.");
        }
    }
}

/// Accepts the unencrypted raw data.
/// Flushing is required after writing all data.
impl Write for Saltpack {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let total_input_len = buf.len();
        let buf = match self.input_buffer.back_mut() {
            Some(ref mut maybe_unfinished) => {
                let missing = 1_000_000 - maybe_unfinished.len();
                maybe_unfinished.extend_from_slice(&buf[0..missing]);
                &buf[missing..]
            },
            None => buf
        };
        for chunk in buf.chunks(1_000_000) {
            let mut b = Vec::with_capacity(1_000_000);
            b.extend_from_slice(chunk);
            self.input_buffer.push_back(b);
        }
        Ok(total_input_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if ! self.flushed {
            self.flushed = true;
            self.input_buffer.push_back(Vec::new()); // finish with empty packet
        }

        Ok(())
    }
}

/// Yields the encrypted data in chunks of 1MB. (or less if `flush()` has been called.)
impl Read for Saltpack {
    fn read(&mut self, mut buffer: &mut [u8]) -> std::io::Result<usize> {
        io::stdout().flush().ok().expect("Could not flush stdout");

        let mut bytes_read = 0;
        while buffer.len() > 0 { // still place to write
            if self.output_buffer.len() > 0 {
                // write already encrypted to output
                let br = self.bytes_read_from_first;
                let written = {
                    let front = self.output_buffer.front().unwrap();
                    try!(buffer.write(&front[br..]))
                };
                bytes_read += written;
                self.bytes_read_from_first += written;

                if self.output_buffer.front().unwrap().len() == self.bytes_read_from_first {
                    self.bytes_read_from_first = 0;
                    self.output_buffer.pop_front();
                }
                continue; // write again from output buffer if not empty yet.
            } else if ! self.encrypt_next_packet() { // encrypt new data, since more data is needed
                break; // no new encrypted data, so nothing to write
            }
        }
        Ok(bytes_read)
    }
}



pub struct ArmoredSaltpack {
    saltpack : Saltpack,
    vendor : String
}


impl Read for ArmoredSaltpack {

    /// Writes the armored saltpack (ascii only characters) as binary data (u8)
    /// into `buffer`.
    fn read(&mut self, mut buffer : &mut [u8]) -> std::io::Result<usize> {

        self.saltpack.read(&mut buffer)
    }
}

impl ArmoredSaltpack {

    /// Outputs all
    fn to_string(&mut self) -> String {
        "".to_string()
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
        encrypt_to_binary(Some(&sender), &recipients, &payload);
        encrypt_to_binary(None, &recipients, &payload);
    }

    #[test]
    fn giant_saltpack() {
        return;
        let mut recipients = Vec::<PublicKey>::new();
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);
        recipients.push(KeyPair::gen().p);

        // todo: make encrypt take either a reference or a writer via some enum
        // let the struct Saltpack store that reference or writer
        // do generate the payload packets on the fly when read() is called
        let payload = vec![10u8; 10_000_000]; // 10 MB
        let mut saltpack = Saltpack::encrypt(None, &recipients);
        let mut buff = Vec::with_capacity(1000*5); // 5mb chunks
        use std::io::{Read, Write};
        for _ in 0..100 {
            saltpack.write(&payload[..]).unwrap();
            buff.clear();
            saltpack.read_to_end(&mut buff).unwrap();
        }
        saltpack.flush().unwrap();
        saltpack.read_to_end(&mut buff).unwrap();
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
            let encr = encrypt_to_binary(Some(&sender), &recipients, &payload);
            test::black_box(encr);
        });
    }
}
