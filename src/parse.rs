//! Decrypt Saltpacks.
//!
//!
//!
//! # Usage
//!
//! ```
//! // Stakeholders
//! use rsaltpack::key::EncryptionKeyPair;
//! let sender = EncryptionKeyPair::gen();
//! let recipient = EncryptionKeyPair::gen();
//! let data = b"The secret passage is behind shelf 13";
//!
//! // Compose
//! use rsaltpack::compose;
//! let email = compose::encrypt_to_binary(
//!                 Some(&sender),
//!                 &vec![recipient.p], // sender only knows public key
//!                 data);
//!
//! // Parse
//! use rsaltpack::parse;
//! let mut read_email = &email[..];
//! let mut header = parse::SaltpackHeader::read_header(&mut read_email).unwrap();
//! if header.is_mode_encryption() {
//!     let mut decryptor = header.verify(&recipient.s).unwrap(); // recipient knows its secret key
//!     let data_2 = decryptor.read_payload(&mut read_email).map(parse::concat).unwrap();
//!     assert_eq!(&data[..], &data_2[..]);
//! }
//! ```
//!
//!
//!
//!
//!
//!
//!
//!
//!

use ::util;

use std::io::Read;
use std::io::Write;
use rmp::decode;
use rmp::value::{Value, Integer};
use std::char::from_u32;

use sodiumoxide::crypto::hash::sha512::{hash, Digest};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::auth;
use ::{CBNonce, SBNonce, SaltpackMessageType};
use ::key::{EncryptionSecretKey, EncryptionPublicKey, Key};






// #############################################################################
// #######             VERSIONLESS INTERFACE            ########################
// #############################################################################

/// Starting point for future proof implementations. Detects Version automatically.
///
/// Start by calling `let header = SaltpackHeader::read_header(&buffer[..])`
/// Then test the mode.
///
/// ## Encryption mode
///
/// ```ign
/// if header.is_mode_encryption() {
///     header.verify(&recipient_priv_key)
/// ```
///
///
pub enum SaltpackHeader {
    Version10(SaltpackHeader10),
}

#[derive(Debug)]
/// Possible errors of `read_header()`
pub enum ParseError{
    WrongSaltpackVersion(String, u64, u64),
    UnknownMode(String, u64),
    NotWellFormed(String),
}



impl SaltpackHeader {

    /// Entry point for decrypting saltpacks.
    pub fn read_header<R>(mut raw: &mut R) -> Result<SaltpackHeader, ParseError>
      where R: Read {
        // try version 1.0
        let mut try = (1, 0);

        // log to prevent deadlocks
        let mut tried = vec![];

        loop {
            let header = match try {
                (1, _) => SaltpackHeader10::read_header(&mut raw)
                          .map(|h| SaltpackHeader::Version10(h) ),

                (a, b) => Err(ParseError::WrongSaltpackVersion("".into(), a, b)) ,
            };

            match header {
                Err(ParseError::WrongSaltpackVersion(_, a, b)) => {
                    tried.push(try);
                    try = (a, b);
                    if (&tried[..]).contains(&try) {
                        return Err(ParseError::WrongSaltpackVersion(
                                       format!("Parser for version {}.{} not implemented.",
                                               a, b),
                                       a, b));
                    }
                },
                Ok(h) => { return Ok(h); },
                Err(e) => { return Err(e); },
            }

        }
    }

    /// Returns true if `mode == SaltpackMessageType::ENCRYPTEDMESSAGE`
    /// Call `verify()` if this function returns true.
    pub fn is_mode_encryption(&self) -> bool {
        match self {
            &SaltpackHeader::Version10(SaltpackHeader10::Encryption(..)) => true,
            //_ => false,
        }
    }

    /// Verifys header for an encrypted saltpack.
    /// Panics if `!self.is_mode_encryption()`.
    pub fn verify(&mut self, recipient_priv_key : &EncryptionSecretKey) -> Result<SaltpackDecrypter, EncryptionHeaderVerifyError> {
        match *self {
            SaltpackHeader::Version10(SaltpackHeader10::Encryption(ref mut e))
                => e.verify(&recipient_priv_key)
                    .map(|d| SaltpackDecrypter::Version10(d)),
            //_ => panic!("Called verify() but !is_mode_encryption()"),
        }
    }

}

/// Future proof interface for decrypting (mode=encryption, version=all)
pub enum SaltpackDecrypter {
    Version10(SaltpackDecrypter10),
}

impl SaltpackDecrypter {
    /// Decrypt all payload packets at once. The output must be concated to retrieve
    /// the original input. You can do this via `.map(parse::concat)`.
    pub fn read_payload<R>(&mut self, mut raw: &mut R) -> Result<Vec<Vec<u8>>, DecryptionError>
      where R : Read {
        match *self {
            SaltpackDecrypter::Version10(ref mut d) => d.read_payload(&mut raw)
        }
    }

}

// #############################################################################
// #######             COMMON FUNCTIONS                 ########################
// #############################################################################


fn peel_outer_messagepack_encoding<R>(mut raw: &mut R) -> Result<Vec<u8>, ParseError>
  where R: Read {
    match decode::read_value(&mut raw) {
        Ok(Value::Binary(bin)) => Ok(bin),
        Err(s) => Err(ParseError::NotWellFormed(format!("Not a messagepack stream. {}", s))),
        e @ _ => Err(ParseError::NotWellFormed(format!("No nested messagepack found. {:?}", e)))
    }
}

fn get_header_array(reader : &mut &[u8], min_len : usize) -> Result<Vec<Value>, ParseError> {
    let arr = match decode::read_value(&mut *reader) {
        Ok(Value::Array(arr)) => arr,
        Err(s) => return Err(ParseError::NotWellFormed(format!("Nested binary is not a messagepack stream. {}", s))),
        _ => return Err(ParseError::NotWellFormed("Nested header messagepack is not of type array.".to_string()))
    };

    if arr.len() < min_len {
        return Err(ParseError::NotWellFormed(format!("Header messagepack array to short. ({}<2)", arr.len())));
    }

    Ok(arr)
}

fn check_header_format_and_version(arr: &Vec<Value>,
                                   expected_version_major : u64,
                                   expected_version_minor : u64) -> Result<(), ParseError> {

    // 4.1 check first array element to be the string "saltpack"
    let saltpack_str = match arr.get(0).unwrap().clone() {
        Value::String(e) => e,
        _ => return Err(ParseError::NotWellFormed("First header array element is not of type string.".to_string()))
    };

    if saltpack_str != "saltpack" {
        return Err(ParseError::NotWellFormed(format!("Header magic string should be 'saltpack' but is {}", saltpack_str)));
    }

    // 4.2.1 check second array element to be version number
    let version_arr = match arr.get(1).unwrap().clone() {
        Value::Array(arr) => arr,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header version field is not of type array")))
    };

    if version_arr.len() != 2 {
        return Err(ParseError::NotWellFormed("Header version field is not of type array[2]".to_string()));
    }

    let version_major = match version_arr.get(0).unwrap().clone() {
        Value::Integer(Integer::U64(i)) => i,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header version field[0] is not of type integer"))),
    };

    let version_minor = match version_arr.get(1).unwrap().clone() {
        Value::Integer(Integer::U64(i)) => i,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header version field[1] is not of type integer"))),
    };

    // 4.2.2 check version number to be [1 0]
    if version_major != expected_version_major || version_minor != expected_version_minor {
        return Err(ParseError::WrongSaltpackVersion(
                    format!("Saltpack version {}.{} found. This is the decoder for Version {}.{}",
                            version_major,
                            version_minor,
                            expected_version_major,
                            expected_version_minor),
                    version_major, version_minor));
    }

    Ok(())
}

fn check_header_len(arr: &Vec<Value>, min_len: usize) -> Result<(), ParseError> {
    if arr.len() < min_len {
        return Err(ParseError::NotWellFormed(
            format!("Header messagepack array to short. ({}<{})", arr.len(), min_len)
            ));
    }
    Ok(())
}

fn check_mode(arr: &Vec<Value>) -> Result<SaltpackMessageType, ParseError> {
    match arr.get(2).unwrap().clone() {
        Value::Integer(Integer::U64(i)) if i == 0 => Ok(SaltpackMessageType::ENCRYPTEDMESSAGE),
        Value::Integer(Integer::U64(i)) if i == 1 => Ok(SaltpackMessageType::SIGNEDMESSAGE),
        Value::Integer(Integer::U64(i)) if i == 2 => Ok(SaltpackMessageType::DETACHEDSIGNATURE),
        Value::Integer(Integer::U64(i)) => Err(ParseError::UnknownMode(format!("Unknown saltpack mode. {}", i), i)),
        _ => Err(ParseError::NotWellFormed(format!("Header mode field[2] is not of type integer")))
    }
}

fn read_ephemeral_public_key(arr: &Vec<Value>) -> Result<EncryptionPublicKey, ParseError> {
    let eph_pub = match arr.get(3).unwrap().clone() {
        Value::Binary(bin) => bin,
        _ =>  return Err(ParseError::NotWellFormed(
                          format!("Header ephemeral public key field[3] is not of type binary"))),
    };

    let eph_pub_ = EncryptionPublicKey::from_slice(&eph_pub[..]);

    if eph_pub_.is_none() {
        return Err(ParseError::NotWellFormed(
            format!("Header ephemeral public key has wrong size. (has {}, expected {})",
                    eph_pub.len(), box_::PUBLICKEYBYTES)));
    }

    Ok(eph_pub_.unwrap())
}

fn read_sender_secretbox(arr: &Vec<Value>) -> Result<Vec<u8>, ParseError> {
    match arr.get(4).unwrap().clone() {
        Value::Binary(bin) => Ok(bin),
        _ =>  Err(ParseError::NotWellFormed(format!("Header sender secretbox field[4] is not of type binary"))),
    }
}

fn get_recipients_messagepackarray(arr: &Vec<Value>) -> Result<Option<Vec<Value>>, ParseError> {
    let has_recipients = arr.len() >= 6;

    if has_recipients {
        match arr.get(5).unwrap().clone() {
            Value::Array(arr) => Ok(Some(arr)),
            _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient field is not of type array")))
        }
    } else {
        Ok(None)
    }
}

fn get_recipient(recipient: &Value) -> Result<Recipient, ParseError> {
    let recipient = match recipient.clone() {
        Value::Array(arr) => arr,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient entry is not of type array")))
    };

    if recipient.len() < 2 {
        return Err(ParseError::NotWellFormed(
            format!("Header recipient entry has less then two fields: {}", recipient.len())));
    }

    let recipient_pub_key = match recipient.get(0).unwrap().clone() {
        Value::Binary(bin) => bin,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient public key is not of type binary."))),
    };

    let recipient_pub_key_ = EncryptionPublicKey::from_slice(&recipient_pub_key[..]);

    if recipient_pub_key_.is_none() {
        return Err(ParseError::NotWellFormed(
                    format!("Header recipient public key has wrong size. (has {}, expected {})",
                            recipient_pub_key.len(), box_::PUBLICKEYBYTES)));

    }

    let payloadkey_cryptobox = match recipient.get(1).unwrap().clone() {
        Value::Binary(bin) => bin,
        _ =>  return Err(ParseError::NotWellFormed(format!("Header payload crypto box is not of type binary."))),
    };

    Ok(Recipient {
        recipient_pub : recipient_pub_key_.unwrap(),
        payloadkey_cryptobox : payloadkey_cryptobox
    })
}

// #############################################################################
// #######             VERSION 1.0                      ########################
// #############################################################################

/// Information from saltpack header (mode=all, version=1.0)
#[derive(Debug)]
pub enum SaltpackHeader10 {
    Encryption(SaltpackEncryptionHeader10),
}

impl SaltpackHeader10 {

    pub fn read_header<R>(mut raw: &mut R) -> Result<SaltpackHeader10, ParseError>
      where R: Read {
        // 1 Deserialize the header bytes from the message stream using MessagePack. (What's on the wire is twice-encoded, so the result of unpacking will be once-encoded bytes.)
        let nested_binary : Vec<u8> = try!(peel_outer_messagepack_encoding(&mut raw));

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1 to give the header hash.
        let headerhash = hash(&nested_binary[..]);

        // 3 Deserialize the bytes from #1 again using MessagePack to give the header list.
        let mut reader : &[u8] = nested_binary.as_slice();

        // 3.1 retrieve array as `arr`
        let arr : Vec<Value> = try!(get_header_array(&mut reader, 2));

        // 4 Sanity check the format name, version, and mode.
        try!(check_header_format_and_version(&arr, 1, 0));

        // We got the correct version, so we can assume more header fields
        try!(check_header_len(&arr, 3));

        // 4.2.3 Check mode
        let mode = try!(check_mode(&arr));

        // From now on, the header packet format depends on `mode`
        // This function will only read the data, parsing must be done later
        let parsed_header = match mode {
            SaltpackMessageType::ENCRYPTEDMESSAGE => {
                let eph_pub = try!(read_ephemeral_public_key(&arr));
                let sender_secretbox = try!(read_sender_secretbox(&arr));
                let recipients_arr = try!(get_recipients_messagepackarray(&arr)).unwrap_or(vec![]);
                let mut parsed_recipients = Vec::with_capacity(recipients_arr.len());
                for recipient in recipients_arr.iter() {
                    parsed_recipients.push(try!(get_recipient(recipient)));
                }
                SaltpackHeader10::Encryption(SaltpackEncryptionHeader10 {
                    eph_pub : eph_pub,
                    sender_secretbox : sender_secretbox,
                    recipients : parsed_recipients,
                    header_hash : headerhash,
                })
            },
            _ => unimplemented!(),
        };

        Ok(parsed_header)
    }

}

// #############################################################################
// #######             VERSION 1.0  => ENCRYPTION       ########################
// #############################################################################

#[derive(Debug)]
/// Information from saltpack header (mode=encryption, version=1.0)
pub struct SaltpackEncryptionHeader10 {
    eph_pub : EncryptionPublicKey,
    sender_secretbox : Vec<u8>,
    recipients : Vec<Recipient>,
    header_hash : Digest,
}

#[derive(Debug)]
/// Recipient information from saltpack header (mode=encryption)
struct Recipient {
    recipient_pub: EncryptionPublicKey,
    payloadkey_cryptobox : Vec<u8>
}

#[derive(Debug)]
/// Possible errors of `verify()` (mode=encryption)
pub enum EncryptionHeaderVerifyError {
    YouAreNotOneOfTheRecipients,
    NotWellFormed(String),
}

impl SaltpackEncryptionHeader10 {

    /// Searches the recipients for the current recipient
    /// If found, decrypt the sender public key.
    /// Prepare for decrypting of payload packets.
    pub fn verify(&self, recipient_priv_key : &EncryptionSecretKey) -> Result<SaltpackDecrypter10, EncryptionHeaderVerifyError> {
        // 5 Precompute the ephemeral shared secret using crypto_box_beforenm with the ephemeral public key and the recipient's private key.
        let precomputed_key = box_::precompute(&self.eph_pub, &recipient_priv_key);

        // 6 Try to open each of the payload key boxes in the recipients list using crypto_box_open_afternm, the precomputed secret from #5, and the nonce saltpack_payload_key_box. Successfully opening one gives the payload key, and the index of the box that worked is the recipient index.
        let mut recipient_index = None;
        let mut payload_key = None;
        for (i, recipient) in self.recipients.iter().enumerate() {
            match box_::open_precomputed(&recipient.payloadkey_cryptobox[..],
                                         &CBNonce(*b"saltpack_payload_key_box"),
                                         &precomputed_key) {
                Ok(payload_key__) => {
                    let payload_key_ = Key::from_slice(&payload_key__[..]);
                    if payload_key_.is_none() {
                        return Err(EncryptionHeaderVerifyError::NotWellFormed(
                                    format!("Decrypted payload key has wrong format. (has {} bytes, expected {})",
                                            payload_key__.len(), secretbox::KEYBYTES)
                                    ));
                    }
                    payload_key = Some(payload_key_.unwrap());
                    recipient_index = Some(i);
                    break;
                },
                Err(_) => {}
            };
        }

        if payload_key.is_none() {
            return Err(EncryptionHeaderVerifyError::YouAreNotOneOfTheRecipients);
        }
        let payload_key = payload_key.unwrap();

        // 7 Open the sender secretbox using crypto_secretbox_open with the payload key from #6 and the nonce saltpack_sender_key_sbox
        let sender_pub_key_ = secretbox::open(&self.sender_secretbox[..],
                                             &SBNonce(*b"saltpack_sender_key_sbox"),
                                             &payload_key);
        if sender_pub_key_.is_err() {
            return Err(EncryptionHeaderVerifyError::NotWellFormed("Could not decrypt sender public key.".to_string()));
        }
        let sender_pub_key_ = sender_pub_key_.unwrap();

        let sender_pub_key = EncryptionPublicKey::from_slice(&sender_pub_key_[..]);
        if sender_pub_key.is_none() {
            return Err(EncryptionHeaderVerifyError::NotWellFormed(
                        format!("Sender public key has wrong format. (has {} bytes, expected {})",
                                sender_pub_key_.len(), box_::PUBLICKEYBYTES)
                        ));
        }
        let sender_pub_key = sender_pub_key.unwrap();

        // 8 Compute the recipient's MAC key by encrypting 32 zero bytes using crypto_box with the recipient's private key, the sender's public key from #7, and the first 24 bytes of the header hash from #2 as a nonce. The MAC key is the last 32 bytes of the resulting box.
        let mut nonce = [0; 24];
        for (hh, n) in self.header_hash.0.iter().zip(nonce.iter_mut()) { *n = *hh; }
        let mut mac_box = box_::seal(/*msg*/&[0u8; 32],
                                   /*nonce*/&CBNonce(nonce),
                                   /*p key*/&sender_pub_key,
                                   /*s key*/&recipient_priv_key);
        let mac_box_len = mac_box.len();
        let mac = auth::Key::from_slice(&mac_box[(mac_box_len-32)..]).unwrap();

        // wipe mac_box
        for b in mac_box.iter_mut() { *b = 0; }



        Ok(SaltpackDecrypter10 {
            sender : if sender_pub_key != self.eph_pub { Some(sender_pub_key) } else { None },
            header_hash : self.header_hash,
            mac : mac,
            packet_number : 0,
            recipient_index : recipient_index.unwrap(),
            payload_key : payload_key,
        })
    }

}

/// Decrypting of payload packets. (mode=encryption, version=1.0)
///
/// Get an instance by calling [`verify()`]
///
/// Use method [`read_payload()`] to decrypt all packets at once.
/// Combine with [`concat()`] to restore the whole payload.
///
/// Alternatively use method [`read_next_payload_packet()`] to read
/// the 1MB packets one by one (During encryption, the saltpack format has
/// splitted the raw data into chunks of 1MB for internal reasons).
/// If you do, you have to assert that the last recieved packet is empty.
/// If it is not empty, an attacker may have truncated the data.
/// See source code of [`read_payload()`] for an example.
///
/// [`verify()`]: struct.SaltpackEncryptionHeader10.html#method.verify
/// [`read_payload()`]: struct.SaltpackDecrypter10.html#method.read_payload
/// [`read_next_payload_packet()`]: struct.SaltpackDecrypter10.html#method.read_next_payload_packet
/// [`concat()`]: fn.concat.html
pub struct SaltpackDecrypter10 {
    pub sender : Option<EncryptionPublicKey>,
    header_hash : Digest,
    mac : auth::Key,
    packet_number : u64,
    recipient_index : usize,
    payload_key : Key,
}


#[derive(Debug)]
/// Possible errors of `read_payload()`
pub enum DecryptionError {
    PayloadPacketVerificationError,
    PayloadDecryptionError,
    MessageTruncatedError,
    EOFOccured,
    NotWellFormed(String),
}



impl SaltpackDecrypter10 {

    /// Decrypt all payload packets at once. The output must be concated to retrieve
    /// the original input. You can do this via `.map(parse::concat)`.
    pub fn read_payload<R>(&mut self, mut raw: &mut R) -> Result<Vec<Vec<u8>>, DecryptionError>
      where R: Read {
        let mut payload = Vec::with_capacity(10);

        loop {
            let payload_packet = match self.read_next_payload_packet(&mut raw) {
                Ok(pp) => pp,
                Err(DecryptionError::EOFOccured) => {
                    // empty packet missing
                    return Err(DecryptionError::MessageTruncatedError);
                },
                Err(x) => { return Err(x); },
            };
            if payload_packet.len() == 0 {
                // last packet
                return Ok(payload);
            }
            payload.push(payload_packet);
        }
    }

    /// See [`SaltpackDecrypter10`] for more information.
    /// [`SaltpackDecrypter10`]: struct.SaltpackDecrypter10.html
    pub fn read_next_payload_packet<R>(&mut self, mut raw: &mut R) -> Result<Vec<u8>, DecryptionError>
      where R: Read {
        let arr = try!(SaltpackDecrypter10::get_next_array(&mut raw));
        let payload_secretbox = try!(SaltpackDecrypter10::get_payload_secretbox(&arr));
        let authenticator = try!(SaltpackDecrypter10::get_authenticator(&arr, self.recipient_index));

        // 0 Make nonce for payload secretbox
        let nonce = util::make_payloadpacket_nonce(self.packet_number);
        self.packet_number += 1;

        // 1 Concatenate the header hash, the nonce for the payload secretbox, and the payload secretbox itself.
        let mut cat = Vec::with_capacity(nonce.0.len()
                                        + self.header_hash.0.len()
                                        + payload_secretbox.len());
        cat.extend_from_slice(&self.header_hash.0[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&payload_secretbox[..]);

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1.
        //$ println!("     Hash BEGIN");
        let packethash = hash(&cat[..]);
        //$ println!("     Hash END");

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash from #2, using that recipient's MAC key.
        let authenticated = auth::verify(&authenticator,
                                         &packethash.0[..],
                                         &self.mac);

        if ! authenticated {
            return Err(DecryptionError::PayloadPacketVerificationError);
        }

        // 4 Decrypt
        secretbox::open(/* chiphertext */ &payload_secretbox[..],
                        &nonce,
                        &self.payload_key)
            .map_err(|_| DecryptionError::PayloadDecryptionError )
    }

    fn get_next_array<R>(mut raw: &mut R) -> Result<Vec<Value>, DecryptionError>
      where R: Read {
        match decode::read_value(&mut raw) {
            Ok(Value::Array(arr)) => Ok(arr),
            Err(decode::value::Error::InvalidMarkerRead(decode::ReadError::UnexpectedEOF))
                => Err(DecryptionError::EOFOccured),
            Err(s) => Err(DecryptionError::NotWellFormed(format!("Not a messagepack stream. {}", s))),
            _ => Err(DecryptionError::NotWellFormed("Payload packet is no messagepack array.".to_string()))
        }
    }

    fn get_payload_secretbox(arr: &Vec<Value>) -> Result<Vec<u8>, DecryptionError> {
        if arr.len() < 2 {
            return Err(DecryptionError::NotWellFormed(format!("Payload array has only {} elements, 2 needed", arr.len())));
        }
        match arr.get(1).unwrap().clone() {
            Value::Binary(bin) => Ok(bin),
            _ =>  Err(DecryptionError::NotWellFormed(format!("Payload secretbox field[1] is not of type binary"))),
        }
    }

    fn get_authenticator(arr: &Vec<Value>, id : usize) -> Result<auth::Tag, DecryptionError> {
        if arr.len() < 1 {
            return Err(DecryptionError::NotWellFormed(format!("Payload array has only {} elements, 1 needed", arr.len())));
        }
        let authenticatorlist = match arr.get(0).unwrap().clone() {
            Value::Array(arr) => arr,
            _ =>  return Err(DecryptionError::NotWellFormed(format!("Payload secretbox field[0] is not of type array"))),
        };
        if authenticatorlist.len() < id {
            return Err(DecryptionError::NotWellFormed(format!("Only {} payload authenticators available, but recipient id is {}.", authenticatorlist.len(), id)));
        }
        let authenticator_ = match authenticatorlist.get(id).unwrap().clone() {
            Value::Binary(bin) => bin,
            _ =>  return Err(DecryptionError::NotWellFormed(format!("Payload authenticator is not of type binary"))),
        };
        let authenticator = auth::Tag::from_slice(&authenticator_[..]);
        if authenticator.is_none() {
            return Err(DecryptionError::NotWellFormed(
                          format!("Payload authenticator has wrong length. (has {}, expected {})",
                                  authenticator_.len(),
                                  auth::TAGBYTES) ));
        }
        Ok(authenticator.unwrap())
    }

}

/// Removes the outer vector by concating the inner vectors.
/// Zeros out the old plaintext data before dropping the input
pub fn concat(mut chunks : Vec<Vec<u8>>) -> Vec<u8> {
    let len = chunks.iter().fold(0, |l, inner| l + inner.len());
    let mut ret = Vec::with_capacity(len);
    for mut  inner in chunks.iter_mut() {
        ret.write_all(&inner[..]).unwrap();
        for c in inner.iter_mut() {
            *c = 0;
        }
    }
    ret
}

// #############################################################################
// #######             TESTING                          ########################
// #############################################################################


#[allow(dead_code)]
pub fn print_debug_as_str(reader : &[u8]) {
    for b in reader.iter() {
        let c : u8 = *b;
        let i : u32 = c as u32;
        let c = from_u32(i);
        if let Some(c) = c {
            print!("{}", c);
        }
    }
    println!("" );
}


#[cfg(test)]
mod tests {

    static ARMORED_2 : &'static str = "BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiOUtMhcc4NXXRb XMxIdgQyljueFUr j9Glci9VK9gs0FD SAI1ChjLXBNvLG9 KzKYjJpeQYdhPeE 132M0VyYiPVRKkc xfxsSUuTNvDtLV8 XJEZlLNM9AEMoJ4 4cQ9dhRpULgINBK CMjxIe0olHF05oC BFiS4JEd9YfzKfB kppV8R4RZeEoU2E StUW1n6563Nynco OAZjT8O8dy3wspR KRIYp2lGwO4jhxN 7Pr1ROg89nrQbTs jIe5kKk0OcNk2nr nFwpZ2T5FflPK6A OAfEWB1ff1o0dG7 3ZSD1GzzH3LbCgj IUg0xnpclpHi37r sXoVzt731JucYGh ihnM9jHK5hhiCmx hnnZ3SyXuW443wU WxTFOzeTJ37kNsG ZNIWxfKIu5rcL8Q PwFd2Sn4Azpcdmy qzlJMvKphjTdkEC EVg0JwaSwwMbhDl OuytEL90Qlf8g9O S8S6qY4Ssw80J5V Avqz3CiiCuSUWzr ry6HdhLWWpguBQi a74pdDYBlzbjsXM lLLKaF5t46nnfB0 7APzXL7wfvRHZVF kJH1SP9WVxULDH2 gocmmy8E2XHfHri nVZU27A3EQ0d0EY IrXpllP8BkCbIc1 GuQGRaAsYH4keTR FuH0h4RoJ6J6mYh TXRceNTDqYAtzm0 Fuop8MaJedh8Pzs HtXcxYsJgPvwqsh H6R3It9Atnpjh1U u0o0uNY0lhcTB4g GHNse3LigrLbMvd oq6UkokAowoWwy2 mk4QdKuWAXrTTSH viB7AMcs5HC96mG 4pTjaXRNBT7Zrs6 fc1GCa4lMJPzSWC XM2pIvu70NCHXYB 8xW11pz1Yy3K2Cw Wz. END KEYBASE SALTPACK ENCRYPTED MESSAGE.";

    use super::*;
    use dearmor::dearmor;
    use dearmor::Stripped;
    use ::SaltpackMessageType;

    #[test]
    fn test_v10() {
        let raw_saltpacks = dearmor(Stripped::from_utf8(&ARMORED_2), 1).unwrap();
        let pack1 = raw_saltpacks.get(0).unwrap();
        let mut reader : &[u8] = pack1.raw_bytes.as_slice();
        let header = SaltpackHeader10::read_header(&mut reader).unwrap();
        //assert_eq!(header.mode, SaltpackMessageType::ENCRYPTEDMESSAGE);
        //assert_eq!(header.recipients.len(), 3);
        //if let SaltpackHeader10::Encryption(enc_header) = header {
            //enc_header.verify()
        //}

    }

    #[test]
    fn test_real_keybase_msg() {

    }

    #[test]
    fn concat_does_zeroing() {
        let test_ptr;
        {
            let data1 = vec![1u8,2,3,4,5,6];
            let data2 = vec![1  ,2,3,4,5,6];
            test_ptr = data1.as_ptr();
            let multi = vec![data1, data2];
            assert_eq!(3, unsafe { *(test_ptr.offset(2)) });
            let cat = concat(multi);
            assert_eq!(*&cat[8], 3);
            // drop everything
        }
        assert_eq!(0, unsafe { *(test_ptr.offset(2)) });
        assert_eq!(0, unsafe { *(test_ptr.offset(4)) });
    }

}
