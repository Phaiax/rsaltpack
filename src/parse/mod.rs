//! Decrypt and verify saltpacks.
//!
//! # Usage
//!
//! Usually you start with a binary stream of data, that implements `Read` and contains a binary
//! saltpack.
//!
//! The first step is to read the first few bytes of the saltpack (the header) and determine the
//! saltpack type (signed, encrypted) and the saltpack version. This is done by calling the API
//! entry point `parse::SaltpackHeader::read_header()`.
//!
//! Then you have to check if the saltpack type matches the type you expected or start handling
//! the different types. You can do this by calling `is_mode_xxx()` on the `SaltpackHeader`.
//! Currently only the encryption mode is supported.
//!
//! - When `is_mode_encryption()` returns true, you can start decrypting. By calling `verify()`
//! with the private key of the receiver, you get a `Decrypter` that does the decryption.
//! Call `read_payload()` and you'll get a `Vec<Vec<u8>>` out of performance reasons.
//!
//! ## Notes
//!
//! - A mutable slice implements `Read`. - If you got an armored saltpack you need to remove the
//! armor first by using the dearmor module. - Use `.map(parse::concat)` to create a single
//! `Vec<>` from the nested `Vec<Vec<u8>>`.
//!
//! # Example
//!
//! ```
//! // Stakeholders
//! use rsaltpack::key::EncryptionKeyPair;
//! let sender = EncryptionKeyPair::gen();
//! let recipient = EncryptionKeyPair::gen();
//! let data = b"The secret passage is behind shelf 13";
//!
//! // Compose
//! use rsaltpack::encrypt;
//! let email = encrypt::encrypt_to_binary(
//!                 Some(&sender),
//!                 &vec![recipient.p], // sender only knows public key
//!                 data);
//!
//! // Parse
//! use rsaltpack::parse;
//! let mut read_email = &email[..];
//! let header = parse::Parser::read_header(&mut read_email).unwrap();
//! match header {
//!     parse::Parser::Encrypted(mut e) => {
//!         // recipient knows its secret key
//!         let mut decryptor = e.verify(&recipient.s).unwrap();
//!         let data_2 = decryptor.read_payload(&mut read_email)
//!                               .map(parse::concat).unwrap();
//!         assert_eq!(&data[..], &data_2[..]);
//!     },
//!     _ => { panic!("Expected encrypted saltpack."); }
//! }
//! ```
//!
//! # Dealing with old saltpack Versions
//!
//! This library is backwards compatible to all saltpack versions.
//!
//! As a user of the library, that wants to support all versions, you should use the enums from
//! this module that do not have a version postfix. These enums relay the actual work to the
//! implementation that can read the received saltpack data. For example the `Decrypter`
//! uses the functionality implemented in the `Decrypter10` if it encounters a saltpack in
//! version 1.0. The specialised versions may offer additional methods that may not be compatible
//! with future versions of saltpack. You can use them, but you will have to `match` to support
//! all currently implemented versions.

#[macro_use]
pub mod errors;
mod common;
mod onedotzero;
mod twodotzero;

use std::io::Read;

use key::EncryptionSecretKey;

use parse::errors::*;

pub use self::common::concat;
pub use self::onedotzero::Parser10;
pub use self::onedotzero::Decrypter10;
pub use self::onedotzero::Encrypted10;

use self::common::header::peel_outer_messagepack_encoding;


/// API starting point. Reads saltpack header and detects saltpack version automatically.
///
/// Start by calling `let header = SaltpackHeader::read_header(&buffer)`. Then test the saltpack
/// mode.
///
/// ## Encryption mode
///
/// ```ign
/// if header.is_mode_encryption() {
///     header.verify(&recipient_priv_key)
/// ```
///
pub enum Parser {
    Encrypted(Encrypted),
    Signed(Signed),
}

pub enum Encrypted {
    Version10(Encrypted10),
}

/// Interface for decrypting (mode=encryption, version=all)
pub enum Decrypter {
    Version10(Decrypter10),
}

pub enum Signed {

}

impl Parser {
    /// API Entry point for parsing/decrypting saltpacks.
    pub fn read_header<R: Read>(mut raw: &mut R) -> Result<Parser, ParseError> {

        // The `Read` stream can only be read once, so we peel the outer message pack here and not
        // in the version specific parsers like `SaltpackHeader10`. The bytes are copied into an
        // Vec<u8> and can be read multiple times afterwards.

        // 1 Deserialize the header bytes from the message stream using MessagePack. (What's on
        // the wire is twice-encoded, so the result of unpacking will be once-encoded bytes.)
        let nested_messagepack: Vec<u8> = peel_outer_messagepack_encoding(&mut raw)?;


        // Find out version of saltpack. First try `try_version`. If it fails, use the version
        // info returned in the `Err` to select the right version. Try again.
        let mut try_version = (1, 0);

        // Do not try the same version twice.
        let mut tried = vec![];

        loop {
            // Try.
            let header = match try_version {
                (1, _) => {
                    Parser10::parse_nested_messagepack(nested_messagepack.as_slice())
                        .map(|h| h.into())
                }

                (a, b) => Err(ParseErrorKind::UnsupportedSaltpackVersion(a, b).into()),
            };
            tried.push(try_version);

            // Adjust `try_version` based on returned Err()
            match header {
                Err(ParseError(ParseErrorKind::UnsupportedSaltpackVersion(a, b), _)) => {
                    try_version = (a, b);
                    if (&tried[..]).contains(&try_version) {
                        bail!(ParseErrorKind::UnsupportedSaltpackVersion(a, b));
                    }
                }
                e => {
                    return e;
                }
            }

        }
    }

    /// Returns true if `mode == SaltpackMessageType::ENCRYPTEDMESSAGE`.
    pub fn try_encrypted(&mut self) -> Option<&mut Encrypted> {
        match *self {
            Parser::Encrypted(ref mut e) => Some(e),
            _ => None,
        }
    }
}

impl From<Parser10> for Parser {
    fn from(src: Parser10) -> Self {
        match src {
            Parser10::Encrypted(enc) => Parser::Encrypted(enc.into()),
        }
    }
}

impl Encrypted {
    /// Verifys header for an encrypted saltpack.
    pub fn verify(
        &mut self,
        recipient_priv_key: &EncryptionSecretKey,
    ) -> Result<Decrypter, ParseError> {
        match *self {
            Encrypted::Version10(ref mut e) => e.verify(recipient_priv_key).map(Into::into),
        }
    }
}

impl From<Encrypted10> for Encrypted {
    fn from(src: Encrypted10) -> Self {
        Encrypted::Version10(src)
    }
}

impl Decrypter {
    /// Decrypt all payload packets at once. The output must be concated to
    /// retrieve the original input. You can do this via
    /// `.map(parse::concat)`.
    pub fn read_payload<R>(&mut self, mut raw: &mut R) -> Result<Vec<Vec<u8>>, ParseError>
    where
        R: Read,
    {
        match *self {
            Decrypter::Version10(ref mut d) => d.read_payload(&mut raw),
        }
    }
}

impl From<Decrypter10> for Decrypter {
    fn from(src: Decrypter10) -> Self {
        Decrypter::Version10(src)
    }
}
