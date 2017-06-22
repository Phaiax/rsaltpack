
use std::io::Read;
use std::io::ErrorKind;

use util;

use parse::errors::*;
use parse::common::Recipient;

use key::{EncryptionSecretKey, EncryptionPublicKey, Key};
use {CBNonce, SBNonce};

use sodiumoxide::crypto::hash::sha512::{hash, Digest};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::auth;

use rmpv::decode;
use rmpv::Value;

#[derive(Debug)]
/// Information from saltpack header (mode=encryption, version=1.0)
pub struct Encrypted10 {
    pub(super) eph_pub: EncryptionPublicKey,
    pub(super) sender_secretbox: Vec<u8>,
    pub(super) recipients: Vec<Recipient>,
    pub(super) header_hash: Digest,
}



impl Encrypted10 {
    /// Searches the recipients for the current recipient.
    /// If found, decrypt the sender public key.
    /// Prepare for decrypting of payload packets.
    pub fn verify(&self, recipient_priv_key: &EncryptionSecretKey) -> ParseResult<Decrypter10> {
        // 5 Precompute the ephemeral shared secret using crypto_box_beforenm
        // with the ephemeral public key and the recipient's private key.
        let precomputed_key = box_::precompute(&self.eph_pub, recipient_priv_key);

        // 6 Try to open each of the payload key boxes in the recipients list
        // using crypto_box_open_afternm, the precomputed secret from #5, and
        // the nonce saltpack_payload_key_box. Successfully opening one gives
        // the payload key, and the index of the box that worked is the
        // recipient index.
        let mut recipient_index = None;
        let mut payload_key = None;
        for (i, recipient) in self.recipients.iter().enumerate() {
            if let Ok(payload_key__) =
                box_::open_precomputed(
                    &recipient.payloadkey_cryptobox[..],
                    &CBNonce(*b"saltpack_payload_key_box"),
                    &precomputed_key,
                )
            {
                let payload_key_ = Key::from_slice(&payload_key__[..]);
                if payload_key_.is_none() {
                    return not_well_formed!(
                        "Decrypted payload key has wrong format. (has {} bytes, expected {})",
                        payload_key__.len(),
                        secretbox::KEYBYTES
                    );
                }
                payload_key = Some(payload_key_.unwrap());
                recipient_index = Some(i);
                break;
            }
        }

        if payload_key.is_none() {
            bail!(ParseErrorKind::YouAreNotOneOfTheRecipients);
        }
        let payload_key = payload_key.unwrap();

        // 7 Open the sender secretbox using crypto_secretbox_open with the
        // payload key from #6 and the nonce saltpack_sender_key_sbox
        let sender_pub_key_ = secretbox::open(
            &self.sender_secretbox[..],
            &SBNonce(*b"saltpack_sender_key_sbox"),
            &payload_key,
        );
        if sender_pub_key_.is_err() {
            return not_well_formed!("Could not decrypt sender public key.");
        }
        let sender_pub_key_ = sender_pub_key_.unwrap();

        let sender_pub_key = EncryptionPublicKey::from_slice(&sender_pub_key_[..]);
        if sender_pub_key.is_none() {
            return not_well_formed!(
                "Sender public key has wrong format. (has {} bytes, expected {})",
                sender_pub_key_.len(),
                box_::PUBLICKEYBYTES
            );
        }
        let sender_pub_key = sender_pub_key.unwrap();

        // 8 Compute the recipient's MAC key by encrypting 32 zero bytes
        // using crypto_box with the recipient's private key, the sender's
        // public key from #7, and the first 24 bytes of the header hash from
        // #2 as a nonce. The MAC key is the last 32 bytes of the resulting
        // box.
        let mut nonce = [0; 24];
        for (hh, n) in self.header_hash.0.iter().zip(nonce.iter_mut()) {
            *n = *hh;
        }
        let mut mac_box = box_::seal(
            /*msg*/
            &[0u8; 32],
            /*nonce*/
            &CBNonce(nonce),
            /*p key*/
            &sender_pub_key,
            /*s key*/
            recipient_priv_key,
        );
        let mac_box_len = mac_box.len();
        let mac = auth::Key::from_slice(&mac_box[(mac_box_len - 32)..]).unwrap();

        // wipe mac_box
        for b in &mut mac_box {
            *b = 0;
        }



        Ok(Decrypter10 {
            sender: if sender_pub_key != self.eph_pub {
                Some(sender_pub_key)
            } else {
                None
            },
            header_hash: self.header_hash,
            mac: mac,
            packet_number: 0,
            recipient_index: recipient_index.unwrap(),
            payload_key: payload_key,
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
/// [`verify()`]: struct.EncryptionHeaderV1dot0.html#method.verify
/// [`read_payload()`]: struct.Decrypter10.html#method.read_payload
/// [`read_next_payload_packet()`]: struct.Decrypter10.html#method.read_next_payload_packet
/// [`concat()`]: fn.concat.html
pub struct Decrypter10 {
    pub sender: Option<EncryptionPublicKey>,
    header_hash: Digest,
    mac: auth::Key,
    packet_number: u64,
    recipient_index: usize,
    payload_key: Key,
}



impl Decrypter10 {
    /// Decrypt all payload packets at once. The output must be concated to
    /// retrieve the original input. You can do this via
    /// `.map(parse::concat)`.
    pub fn read_payload<R>(&mut self, mut raw: &mut R) -> ParseResult<Vec<Vec<u8>>>
    where
        R: Read,
    {
        let mut payload = Vec::with_capacity(10);

        loop {
            let payload_packet = match self.read_next_payload_packet(&mut raw) {
                Ok(pp) => pp,
                Err(ParseError(ParseErrorKind::EOFOccured, _)) => {
                    // empty packet missing
                    return Err(ParseErrorKind::MessageTruncatedError.into());
                }
                Err(x) => {
                    return Err(x);
                }
            };
            if payload_packet.is_empty() {
                // last packet
                return Ok(payload);
            }
            payload.push(payload_packet);
        }
    }

    /// See [`Decrypter10`] for more information.
    /// [`Decrypter10`]: struct.Decrypter10.html
    pub fn read_next_payload_packet<R>(&mut self, mut raw: &mut R) -> ParseResult<Vec<u8>>
    where
        R: Read,
    {
        let arr = Decrypter10::get_next_array(&mut raw)?;
        let payload_secretbox = Decrypter10::get_payload_secretbox(&arr)?;
        let authenticator = Decrypter10::get_authenticator(&arr, self.recipient_index)?;

        // 0 Make nonce for payload secretbox
        let nonce = util::make_payloadpacket_nonce(self.packet_number);
        self.packet_number += 1;

        // 1 Concatenate the header hash, the nonce for the payload
        // secretbox, and the payload secretbox itself.
        let mut cat = Vec::with_capacity(
            nonce.0.len() + self.header_hash.0.len() + payload_secretbox.len(),
        );
        cat.extend_from_slice(&self.header_hash.0[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&payload_secretbox[..]);

        // 2 Compute the crypto_hash (SHA512) of the bytes from #1.
        //$ println!("     Hash BEGIN");
        let packethash = hash(&cat[..]);
        //$ println!("     Hash END");

        // 3 For each recipient, compute the crypto_auth (HMAC-SHA512,
        // truncated to 32 bytes) of the hash from #2, using that recipient's
        // MAC key.
        let authenticated = auth::verify(&authenticator, &packethash.0[..], &self.mac);

        if !authenticated {
            bail!(ParseErrorKind::PayloadPacketVerificationError);
        }

        // 4 Decrypt
        secretbox::open(
            /* chiphertext */
            &payload_secretbox[..],
            &nonce,
            &self.payload_key,
        ).map_err(|_| ParseErrorKind::PayloadDecryptionError.into())
    }

    fn get_next_array<R>(mut raw: &mut R) -> ParseResult<Vec<Value>>
    where
        R: Read,
    {
        match decode::read_value(&mut raw) {
            Ok(Value::Array(arr)) => Ok(arr),
            Err(decode::Error::InvalidMarkerRead(ref inner))
                if inner.kind() == ErrorKind::UnexpectedEof => Err(
                ParseErrorKind::EOFOccured.into(),
            ),
            Err(s) => not_well_formed!("Not a messagepack stream. {}", s),
            _ => not_well_formed!("Payload packet is no messagepack array."),
        }
    }

    fn get_payload_secretbox(arr: &[Value]) -> ParseResult<Vec<u8>> {
        if arr.len() < 2 {
            return not_well_formed!("Payload array has only {} elements, 2 needed", arr.len());
        }
        match arr[1].clone() {
            Value::Binary(bin) => Ok(bin),
            _ => not_well_formed!("Payload secretbox field[1] is not of type binary"),
        }
    }

    fn get_authenticator(arr: &[Value], id: usize) -> ParseResult<auth::Tag> {
        if arr.len() < 1 {
            return not_well_formed!("Payload array has only {} elements, 1 needed", arr.len());
        }
        let authenticatorlist = match arr[0].clone() {
            Value::Array(arr) => arr,
            _ => {
                return not_well_formed!("Payload secretbox field[0] is not of type array");

            }
        };
        if authenticatorlist.len() < id {
            return not_well_formed!(
                "Only {} payload authenticators available, but recipient id is {}.",
                authenticatorlist.len(),
                id
            );
        }
        let authenticator_ = match authenticatorlist[id].clone() {
            Value::Binary(bin) => bin,
            _ => return not_well_formed!("Payload authenticator is not of type binary"),
        };
        let authenticator = auth::Tag::from_slice(&authenticator_[..]);
        if authenticator.is_none() {
            return not_well_formed!(
                "Payload authenticator has wrong length. (has {}, expected {})",
                authenticator_.len(),
                auth::TAGBYTES
            );
        }
        Ok(authenticator.unwrap())
    }
}
