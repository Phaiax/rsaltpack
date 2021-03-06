
use std::io::Read;

use SaltpackMessageType;
use super::Encrypted10;
use parse::errors::*;
use parse::common::header::{peel_outer_messagepack_encoding, get_header_array,
                            check_header_format_and_version, check_header_len, check_mode,
                            read_ephemeral_public_key, read_sender_secretbox,
                            get_recipients_messagepackarray, get_recipient};
use rmpv::Value;

use sodiumoxide::crypto::hash::sha512::hash;


/// Information from saltpack header (mode=all, version=1.0)
#[derive(Debug)]
pub enum Parser10 {
    Encrypted(Encrypted10),
}

impl Parser10 {
    pub fn read_header<R: Read>(mut raw: &mut R) -> ParseResult<Parser10> {
        // 1 Deserialize the header bytes from the message stream using MessagePack. (What's on
        // the wire is twice-encoded, so the result of unpacking will be once-encoded bytes.)
        let nested_messagepack: Vec<u8> = peel_outer_messagepack_encoding(&mut raw)?;

        Self::parse_nested_messagepack(nested_messagepack.as_slice())
    }

    // TODO: make priv again
    pub(in parse) fn parse_nested_messagepack(nested_messagepack: &[u8]) -> ParseResult<Parser10> {
        // 2 Compute the crypto_hash (SHA512) of the bytes from #1 to give the header hash.
        let headerhash = hash(&nested_messagepack[..]);

        // 3 Deserialize the bytes from #1 again using MessagePack to give the header list.
        let mut reader: &[u8] = &nested_messagepack[..];

        // 3.1 retrieve array as `arr`
        let arr: Vec<Value> = get_header_array(&mut reader)?;

        // 4 Sanity check the format name, version, and mode.
        check_header_format_and_version(&arr, 1, 0)?;

        // We got the correct version, so we can assume more header fields
        check_header_len(&arr, 3)?;

        // 4.2.3 Check mode
        let mode = check_mode(&arr)?;

        // From now on, the header packet format depends on `mode`.
        // This function will only read the data, parsing must be done later
        let parsed_header = match mode {
            SaltpackMessageType::ENCRYPTEDMESSAGE => {
                let eph_pub = read_ephemeral_public_key(&arr)?;
                let sender_secretbox = read_sender_secretbox(&arr)?;
                let recipients_arr = get_recipients_messagepackarray(&arr)?.unwrap_or_else(
                    || vec![],
                );
                let mut parsed_recipients = Vec::with_capacity(recipients_arr.len());
                for recipient in &recipients_arr {
                    parsed_recipients.push(get_recipient(recipient)?);
                }
                Parser10::Encrypted(Encrypted10 {
                    eph_pub: eph_pub,
                    sender_secretbox: sender_secretbox,
                    recipients: parsed_recipients,
                    header_hash: headerhash,
                })
            }
            _ => unimplemented!(),
        };

        Ok(parsed_header)
    }

    /// Returns Some(encryption_parser) if the parsed saltpack is in encryption mode.
    pub fn try_encrypted(&mut self) -> Option<&mut Encrypted10> {
        match *self {
            Parser10::Encrypted(ref mut e) => Some(e),
        }
    }
}
