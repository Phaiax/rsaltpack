//! Asymmetrically encrypt or sign data for multiple recipients using the saltpack format.
//!
//! Take a look at the [`Saltpack`][Saltpack] struct.
//!
//! [Saltpack]: struct.Saltpack.html
//!
//! # Usage
//!
//! ## Encrypt and armor (result only contains a-z A-Z 0-9 space and .)
//!
//! ```
//! # use rsaltpack::key::EncryptionKeyPair;
//! # use rsaltpack::compose::{Saltpack, ArmoredSaltpack};
//! let mut saltpack = Saltpack::encrypt(None, & vec![EncryptionKeyPair::gen().p]);
//! use std::io::Write;
//! saltpack.write_all(b"I love you").unwrap();
//! saltpack.flush().unwrap();
//!
//! let mut armored : ArmoredSaltpack = saltpack.armor("").unwrap();
//! println!("{}", armored.to_string()); // read all
//! // or use std::io::Read on armored to get ascii character as binary string.
//! ```
//!
//! ## Binary data via stream interface
//!
//! Stream interface means to use `std::io::Write` to insert the plain text
//! into the [Saltpack struct](struct.Saltpack.html) and to use `std::io::Reader`
//! to read the encrypted data.
//!
//! ```
//! use rsaltpack::key::EncryptionKeyPair;
//! use rsaltpack::compose::Saltpack;
//! let recipients = vec![EncryptionKeyPair::gen().p];
//!
//! let data = b" The moment when, after many years
//!               of hard work and a long voyage
//!               you stand in the centre of your room,
//!               house, half-acre, square mile, island, country,
//!               knowing at last how you got there,
//!               and say, I own this,
//!
//!               is the same moment when the trees unloose
//!               their soft arms from around you,
//!               the birds take back their language,
//!               the cliffs fissure and collapse,
//!               the air moves back from you like a wave
//!               and you can't breathe.
//!
//!
//!               No, they whisper.
//!                You own nothing.
//!
//!               You were a visitor, time after time
//!               climbing the hill, planting the flag, proclaiming.
//!
//!               We never belonged to you.
//!
//!               You never found us.
//!
//!               It was always the other way round.
//!
//!               by Margaret Atwood";
//!
//! // using None as first parameter for anonymous sender
//! let mut saltpack = Saltpack::encrypt(None, &recipients);
//!
//! use std::io::Write;
//! saltpack.write_all(&data[..]).unwrap();
//! saltpack.flush().unwrap();
//!
//! use std::io::Read;
//! let mut encrypted = vec![0u8; 0]; // totally binary data
//! saltpack.read_to_end(&mut encrypted).unwrap();
//!
//! # assert!(saltpack.is_done()); // optional
//! assert!(encrypted.len() > 100);
//! ```
//!
//! You can use Saltpack as a buffer. Saltpack encrypts in chunks
//! of 1 MB (1000000 bytes). Flush after end of write, otherwise a panic
//! will occur. Also read all data, otherwise a panic will occur.
//!
//! ```
//! # use rsaltpack::key::EncryptionKeyPair;
//! # use rsaltpack::compose::Saltpack;
//! # let recipients = vec![EncryptionKeyPair::gen().p];
//! # let data = [12u8; 1000000];
//! # // using None as first parameter for anonymous sender
//! # let mut saltpack = Saltpack::encrypt(None, &recipients);
//! use std::io::Write;
//! use std::io::Read;
//! let mut encrypted = vec![0u8; 0];
//!
//! saltpack.write_all(&data[0..500_000]).unwrap(); // only half chunk
//! saltpack.read_to_end(&mut encrypted).unwrap();
//! assert!(encrypted.len() < 1000); // only header written
//!
//! saltpack.write_all(&data[0..1_000_000]).unwrap();
//! saltpack.read_to_end(&mut encrypted).unwrap();
//! assert!(1_000_000 < encrypted.len() && encrypted.len() < 1_005_000); // 1 chunk written
//!
//! saltpack.flush().unwrap();
//! saltpack.read_to_end(&mut encrypted).unwrap();
//! assert!(1_500_000 < encrypted.len() && encrypted.len() < 1_501_000); // 1.5 chunks written
//! # assert!(saltpack.is_done()); // optional
//! ```
//!

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::hash;
use sodiumoxide::crypto::auth;

use serde::Serialize;
use serde::bytes::ByteBuf;
use rmp_serde::Serializer;

use ::armor;
use ::util;

use std::mem::size_of;
use std::io::{Read, Write};
use std::collections::VecDeque;
use std::string::ToString;
use std::cmp;
use std;


/// A recipient pair is a two-element list: [recipient public key, payload key box]
#[derive(Serialize, PartialEq, Debug)]
struct RecipSerializable(ByteBuf, ByteBuf);
#[derive(Serialize, PartialEq, Debug)]
struct HeaderSerializable(String, (u32, u32), u32, ByteBuf, ByteBuf, Vec<RecipSerializable>);
#[derive(Serialize, PartialEq, Debug)]
struct PayloadPacketSerializable (Vec<ByteBuf>, ByteBuf);

use ::{SaltpackMessageType, CBNonce, SBNonce};
use ::key::{EncryptionPublicKey, EncryptionKeyPair, Key};

pub const CHUNK_SIZE_UNENCRYPTED : usize = 1_000_000;


/// Main interface to create new saltpacks.
pub struct Saltpack {
    header_hash : Option<Vec<u8>>,
    payload_key : Option<Key>,
    macs : Vec<auth::Key>,

    next_packet_number : u64,
    input_buffer : VecDeque<Vec<u8>>,
    flushed : bool,

    bytes_read_from_first_output_buffer_element : usize,
    output_buffer : VecDeque<Vec<u8>>,
}

pub fn encrypt_to_binary(sender : Option<&EncryptionKeyPair>,
                      recipients : &Vec<EncryptionPublicKey>,
                      payload : &[u8]) -> Vec<u8> {
    let mut saltpack = Saltpack::encrypt(sender, recipients);
    saltpack.write_all(payload).unwrap();
    saltpack.flush().unwrap();
    let mut encrypted = Vec::with_capacity((payload.len() as f64 * 1.2) as usize);
    saltpack.read_to_end(&mut encrypted).unwrap();
    encrypted
}


pub fn encrypt_and_armor(sender : Option<&EncryptionKeyPair>,
                      recipients : &Vec<EncryptionPublicKey>,
                      payload : &[u8],
                      vendor : &str) -> Result<String, String> {
    let mut saltpack = Saltpack::encrypt(sender, recipients);
    saltpack.write_all(payload).unwrap();
    saltpack.flush().unwrap();
    let encrypted = try!(saltpack.armor(&vendor)).to_string();
    Ok(encrypted)
}

impl Saltpack {

    /// Use this constructor if you want to encrypt data.
    ///
    /// For anonymous sending, set `sender` to `None`.
    pub fn encrypt(sender : Option<&EncryptionKeyPair>,
                   recipients : &Vec<EncryptionPublicKey>) -> Saltpack
    {
        // 1 Generate a random 32-byte payload key.
        let payload_key : Key = secretbox::gen_key();

        // 2 Generate a random ephemeral keypair, using crypto_box_keypair.
        let eph_key = EncryptionKeyPair::gen();

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
            bytes_read_from_first_output_buffer_element : 0,
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

    fn last_bytes(&self) -> bool {
        self.flushed && self.output_buffer.len() <= 1 && self.input_buffer.is_empty()
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
        ArmoredSaltpack::new(self, vendor)
    }

    fn compose_saltpack_header(&mut self,
                               sender : &EncryptionKeyPair,
                               recipients : &Vec<EncryptionPublicKey>,
                               eph_key : &EncryptionKeyPair)
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
            // A recipient pair is a two-element list: [recipient public key, payload key box]
            let recip_pair = RecipSerializable( ByteBuf::from(Vec::from(&recip_key.0[..])),
                                                ByteBuf::from(cryptobox_payloadkey_for_recipient));
            bufsize_for_recipients += recip_pair.0.len() + recip_pair.1.len();
            recipients_list.push(recip_pair);
        }

        // 5 Collect the format name, version, and mode into a list, followed by the ephemeral public key, the sender secretbox, and the nested recipients list.
        let mode = SaltpackMessageType::ENCRYPTEDMESSAGE;
        let header = HeaderSerializable ( "saltpack".to_string(),
                                          (1, 0),
                                          mode.to_int(),
                                          ByteBuf::from(Vec::from(&eph_key.p.0[..])),
                                          ByteBuf::from(secretbox_sender_p),
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
        let mut header_inner_messagepack = Vec::<u8>::with_capacity(bufsize);

        header.serialize(&mut Serializer::new(&mut header_inner_messagepack)).unwrap();
        //header.encode(&mut Encoder::new(&mut header_inner_messagepack)).unwrap();

        // 7 Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.
        let headerhash = hash(&header_inner_messagepack[..]);
        self.header_hash = Some(Vec::from(&headerhash.0[..]));

        // 8 Serialize the bytes from #6 again into a MessagePack bin object. These twice-encoded bytes are the header packet.

        let mut header_outer_messagepack = Vec::with_capacity(header_inner_messagepack.len() + 10);
        ByteBuf::from(header_inner_messagepack).serialize(&mut Serializer::new(&mut header_outer_messagepack)).unwrap();
        //header_outer.encode(&mut Encoder::new(&mut header_outer_messagepack)).unwrap();
        self.output_buffer.push_back(header_outer_messagepack);

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
            let mac_box_len = mac_box.len();
            let mac = auth::Key::from_slice(&mac_box[(mac_box_len-32)..]).unwrap();

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

        let nonce = util::make_payloadpacket_nonce(self.next_packet_number);
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
        let packethash = hash(&cat[..]);
        //$ println!("     Hash END");

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash from #2, using that recipient's MAC key.
        let mut authenticators = Vec::with_capacity(self.macs.len());
        let mut bufsize = secretbox_payload.len() + 12;
        //$ println!("       Auth BEGIN");
        for mac in self.macs.iter() {
            let tag = auth::authenticate(&packethash.0, &mac);
            bufsize += tag.0.len() + 2;
            authenticators.push(ByteBuf::from(Vec::from(&tag.0[..])));
        }

        //$ println!("       Auth END");

        // Compose Packet
        let packet = PayloadPacketSerializable (
            authenticators,
            ByteBuf::from(secretbox_payload),
        );

        //$ println!("          Encode BEGIN");
        let mut packet_messagepacked = Vec::<u8>::with_capacity(bufsize);
        packet.serialize(&mut Serializer::new(&mut packet_messagepacked)).unwrap();
        //$ println!("          Encode END");

        self.output_buffer.push_back(packet_messagepacked);
        //$ println!("              Encr END");
        true
    }

    /// Tries to predict the length of all unwritten data.
    pub fn predict_len(&self) -> usize {
        let mut len = 0;
        let secretbox_add = secretbox::MACBYTES;
        for i in &self.input_buffer {
            len += (auth::TAGBYTES + 2) * self.macs.len(); // incl 2 msgpack marker bytes
            len += i.len() + secretbox_add + 5; // incl max 5 msgpack marker bytes
            len += 20; // for PayloadPacketSerializable struct, with security margin
        }
        for i in &self.output_buffer { // btw: header is already in output_buffer
            len += i.len();
        }
        len
    }



    /// Get the encrypted data in packets of max approximately 1MB (some packets may be significantly less).
    /// Returns None, if no more data is currently available.
    /// More data can be available at later times (after calls to `write()` or `flush()`)
    ///
    /// The `Read` trait (implemented for `Saltpack`) can be used alternatively to this method.
    /// This method may have the advantage of avoiding copies.
    pub fn get_next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.output_buffer.is_empty() {
            self.encrypt_next_packet();
        }
        self.output_buffer.pop_front()
    }
}

/// Will panic if not flushed or not all data read.
impl Drop for Saltpack {
    fn drop(&mut self) {
        use std::thread::panicking;
        if panicking() {
            println!("Saltpack not flushed or not read to end. Thread has paniced elsewhere.");
            return;
        }
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
        // save input data in chunks of 1MB
        // (input buffer is VecDeque<Vec<u8>>)

        // fill last Vec in input_buffer until it has 1MB of data
        let buf = match self.input_buffer.back_mut() {
            Some(ref mut maybe_unfinished) => {
                let missing = CHUNK_SIZE_UNENCRYPTED - maybe_unfinished.len();
                let take = cmp::min(missing, total_input_len);
                maybe_unfinished.extend_from_slice(&buf[0..take]);
                &buf[take..]
            },
            None => buf
        };

        // then create new Vecs in input_buffer, each 1MB
        for chunk in buf.chunks(CHUNK_SIZE_UNENCRYPTED) {
            let mut b = Vec::with_capacity(CHUNK_SIZE_UNENCRYPTED);
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
        let mut bytes_read = 0;
        while buffer.len() > 0 { // still place to write
            if self.output_buffer.len() > 0 {
                // write already encrypted to output
                let written = {
                    let br = self.bytes_read_from_first_output_buffer_element;
                    let front = self.output_buffer.front().unwrap();
                    // This `write()` will modify the range `buffer` is pointing to
                    try!(buffer.write(&front[br..]))
                };
                bytes_read += written;
                self.bytes_read_from_first_output_buffer_element += written;

                // chunk finished?
                if self.output_buffer.front().unwrap().len() == self.bytes_read_from_first_output_buffer_element {
                    self.bytes_read_from_first_output_buffer_element = 0;
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
    armoring_stream : armor::ArmoringStream,
}


impl Write for ArmoredSaltpack {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.saltpack.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.saltpack.flush()
    }
}

impl Read for ArmoredSaltpack {

    /// Writes the armored saltpack (ascii only characters) as binary data (u8)
    /// into `buffer`.
    fn read(&mut self, mut buffer : &mut [u8]) -> std::io::Result<usize> {
        use util::Consumable;
        let mut bytes_read = 0;
        while buffer.len() > 0 { // still place to write
            if self.saltpack.output_buffer.len() > 0 {
                // pipe already encrypted through armoring and let armor() directly write to buffer
                let (read_from_front, written_into_buffer) = {
                    let br = self.saltpack.bytes_read_from_first_output_buffer_element;
                    let front = self.saltpack.output_buffer.front().unwrap();
                    match self.armoring_stream.armor(&front[br..], self.saltpack.last_bytes(), &mut buffer) {
                        Ok(a) => a,
                        Err(msg) => { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)); }
                    }
                };
                bytes_read += written_into_buffer;
                buffer.consume(written_into_buffer);
                self.saltpack.bytes_read_from_first_output_buffer_element += read_from_front;

                if self.saltpack.output_buffer.front().unwrap().len()
                  == self.saltpack.bytes_read_from_first_output_buffer_element {
                    self.saltpack.bytes_read_from_first_output_buffer_element = 0;
                    self.saltpack.output_buffer.pop_front();
                }

                continue; // write again from output buffer if not empty yet.
            } else if self.is_done() {
                break; // finished completely
            } else if self.saltpack.is_done() && !self.armoring_stream.is_done() {
                // last bytes have been armored, but still data in armor buffer
                let (_, written_into_buffer) = {
                    match self.armoring_stream.armor(&[], true, &mut buffer) {
                        Ok(a) => a,
                        Err(msg) => { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)); }
                    }
                };
                buffer.consume(written_into_buffer);
            } else if ! self.saltpack.encrypt_next_packet() { // encrypt new data, since more data is needed
                break; // no new encrypted data, so nothing to write
            }
        }
        Ok(bytes_read)
    }
}

impl ArmoredSaltpack {

    pub fn new(saltpack : Saltpack, vendor : &str) -> Result<ArmoredSaltpack, String> {
        Ok(ArmoredSaltpack {
            saltpack : saltpack,
            armoring_stream : try!(armor::ArmoringStream::new(vendor, SaltpackMessageType::ENCRYPTEDMESSAGE)),
        })
    }

    /// Outputs all
    pub fn to_string(&mut self) -> String {
        self.flush().unwrap();
        let bin_len = self.saltpack.predict_len();
        let armored_len = self.armoring_stream.predict_armored_len(bin_len);
        let mut str_u8 = Vec::with_capacity(armored_len);
        self.read_to_end(&mut str_u8).unwrap();
        assert!(self.is_done());
        unsafe { String::from_utf8_unchecked(str_u8) }
    }

    pub fn is_done(&self) -> bool {
        self.saltpack.is_done() && self.armoring_stream.is_done()
    }

    pub fn cancel(&mut self) {
        self.saltpack.cancel();
        self.armoring_stream.cancel();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use super::super::key::*;
    use test::{self, Bencher};

    #[test]
    fn make_saltpack() {
        let sender = EncryptionKeyPair::gen();
        let mut recipients = Vec::<EncryptionPublicKey>::new();
        recipients.push(EncryptionKeyPair::gen().p);
        recipients.push(EncryptionKeyPair::gen().p);
        recipients.push(EncryptionKeyPair::gen().p);
        let payload = [10u8; 100];
        encrypt_to_binary(Some(&sender), &recipients, &payload);
        encrypt_to_binary(None, &recipients, &payload);
    }

    #[test]
    #[allow(unreachable_code)]
    fn giant_saltpack() {
        return;
        let mut recipients = Vec::<EncryptionPublicKey>::new();
        recipients.push(EncryptionKeyPair::gen().p);
        recipients.push(EncryptionKeyPair::gen().p);
        recipients.push(EncryptionKeyPair::gen().p);

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

    #[test]
    fn to_string() {

        let mut saltpack = Saltpack::encrypt(None, & vec![EncryptionKeyPair::gen().p]);
        use std::io::Write;
        saltpack.write_all(b"I love you").unwrap();
        saltpack.flush().unwrap();
        let mut armored = saltpack.armor("").unwrap();
        println!("{}", armored.to_string()); // read all
    }

    #[bench]
    fn bench_encrypt_2mb_100recip(b: &mut Bencher) {
        let sender = EncryptionKeyPair::gen();
        let mut recipients = Vec::<EncryptionPublicKey>::new();
        for _ in 0..100 {
            recipients.push(EncryptionKeyPair::gen().p);
        }
        let payload = [10u8; 2*1000*1000 + 100];

        b.iter(|| {
            let encr = encrypt_to_binary(Some(&sender), &recipients, &payload);
            test::black_box(encr);
        });
    }
}
