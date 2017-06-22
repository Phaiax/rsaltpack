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
//! with the private key of the receiver, you get a `SaltpackDecrypter` that does the decryption.
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
//! let mut header = parse::SaltpackHeader::read_header(&mut read_email).unwrap();
//! if header.is_mode_encryption() {
//!     // recipient knows its secret key
//!     let mut decryptor = header.verify(&recipient.s).unwrap();
//!     let data_2 = decryptor.read_payload(&mut read_email)
//!                           .map(parse::concat).unwrap();
//!     assert_eq!(&data[..], &data_2[..]);
//! }
//! ```
//!
//! # Dealing with old saltpack Versions
//!
//! This library is backwards compatible to all saltpack versions.
//!
//! As a user of the library, that wants to support all versions, you should use the enums from
//! this module that do not have a version postfix. These enums relay the actual work to the
//! implementation that can read the received saltpack data. For example the `SaltpackDecrypter`
//! uses the functionality implemented in the `SaltpackDecrypter10` if it encounters a saltpack in
//! version 1.0. The specialised versions may offer additional methods that may not be compatible
//! with future versions of saltpack. You can use them, but you will have to `match` to support
//! all currently implemented versions.

#[macro_use]
pub mod errors;
mod common;
mod onedotzero;
mod twodotzero;

use std::io::Read;

use key::{EncryptionSecretKey};

use parse::errors::*;

pub use self::common::concat;
pub use self::onedotzero::SaltpackHeader10;
pub use self::onedotzero::SaltpackDecrypter10;
pub use self::onedotzero::SaltpackEncryptionHeader10;

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
pub enum SaltpackHeader {
    Version10(SaltpackHeader10),
}


impl SaltpackHeader {
    /// API Entry point for parsing/decrypting saltpacks.
    pub fn read_header<R : Read>(mut raw: &mut R) -> Result<SaltpackHeader, ParseError> {

        // The `Read` stream can only be read once, so we peel the outer message pack here and not
        // in the version specific parsers like `SaltpackHeader10`. The bytes are copied into an
        // Vec<u8> and can be read multiple times afterwards.

        // 1 Deserialize the header bytes from the message stream using MessagePack. (What's on
        // the wire is twice-encoded, so the result of unpacking will be once-encoded bytes.)
        let nested_messagepack : Vec<u8> = try!(peel_outer_messagepack_encoding(&mut raw));


        // Find out version of saltpack. First try `try_version`. If it fails, use the version
        // info returned in the `Err` to select the right version. Try again.
        let mut try_version = (1, 0);

        // Do not try the same version twice.
        let mut tried = vec![];

        loop {
            // Try.
            let header = match try_version {
                (1, _) => SaltpackHeader10::parse_nested_messagepack(nested_messagepack.as_slice())
                          .map(|h| SaltpackHeader::Version10(h) ),

                (a, b) => Err(ParseErrorKind::UnsupportedSaltpackVersion(a, b).into()) ,
            };
            tried.push(try_version);

            // Adjust `try_version` based on returned Err()
            match header {
                Err(ParseError(ParseErrorKind::UnsupportedSaltpackVersion(a, b), _)) => {
                    try_version = (a, b);
                    if (&tried[..]).contains(&try_version) {
                        bail!(ParseErrorKind::UnsupportedSaltpackVersion(a, b));
                    }
                },
                e => { return e; },
            }

        }
    }

    /// Returns true if `mode == SaltpackMessageType::ENCRYPTEDMESSAGE`.
    ///
    /// Call `verify()` if this function returns true.
    pub fn is_mode_encryption(&self) -> bool {
        match self {
            &SaltpackHeader::Version10(SaltpackHeader10::Encryption(..)) => true,
            //_ => false,
        }
    }

    /// Verifys header for an encrypted saltpack.
    /// Panics if `!self.is_mode_encryption()`. TODO bad API
    pub fn verify(&mut self, recipient_priv_key : &EncryptionSecretKey) -> Result<SaltpackDecrypter, ParseError> {
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
    /// Decrypt all payload packets at once. The output must be concated to
    /// retrieve the original input. You can do this via
    /// `.map(parse::concat)`.
    pub fn read_payload<R>(&mut self, mut raw: &mut R) -> Result<Vec<Vec<u8>>, ParseError>
      where R : Read {
        match *self {
            SaltpackDecrypter::Version10(ref mut d) => d.read_payload(&mut raw)
        }
    }

}




#[cfg(test)]
mod tests {

    static ARMORED_2 : &'static str = "BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiOUtMhcc4NXXRb XMxIdgQyljueFUr j9Glci9VK9gs0FD SAI1ChjLXBNvLG9 KzKYjJpeQYdhPeE 132M0VyYiPVRKkc xfxsSUuTNvDtLV8 XJEZlLNM9AEMoJ4 4cQ9dhRpULgINBK CMjxIe0olHF05oC BFiS4JEd9YfzKfB kppV8R4RZeEoU2E StUW1n6563Nynco OAZjT8O8dy3wspR KRIYp2lGwO4jhxN 7Pr1ROg89nrQbTs jIe5kKk0OcNk2nr nFwpZ2T5FflPK6A OAfEWB1ff1o0dG7 3ZSD1GzzH3LbCgj IUg0xnpclpHi37r sXoVzt731JucYGh ihnM9jHK5hhiCmx hnnZ3SyXuW443wU WxTFOzeTJ37kNsG ZNIWxfKIu5rcL8Q PwFd2Sn4Azpcdmy qzlJMvKphjTdkEC EVg0JwaSwwMbhDl OuytEL90Qlf8g9O S8S6qY4Ssw80J5V Avqz3CiiCuSUWzr ry6HdhLWWpguBQi a74pdDYBlzbjsXM lLLKaF5t46nnfB0 7APzXL7wfvRHZVF kJH1SP9WVxULDH2 gocmmy8E2XHfHri nVZU27A3EQ0d0EY IrXpllP8BkCbIc1 GuQGRaAsYH4keTR FuH0h4RoJ6J6mYh TXRceNTDqYAtzm0 Fuop8MaJedh8Pzs HtXcxYsJgPvwqsh H6R3It9Atnpjh1U u0o0uNY0lhcTB4g GHNse3LigrLbMvd oq6UkokAowoWwy2 mk4QdKuWAXrTTSH viB7AMcs5HC96mG 4pTjaXRNBT7Zrs6 fc1GCa4lMJPzSWC XM2pIvu70NCHXYB 8xW11pz1Yy3K2Cw Wz. END KEYBASE SALTPACK ENCRYPTED MESSAGE.";

    use super::*;
    use dearmor::dearmor;
    use dearmor::Stripped;
    // use ::SaltpackMessageType;

    #[test]
    #[allow(unused_variables)]
    fn test_v10() {
        let raw_saltpacks = dearmor(Stripped::from_utf8(&ARMORED_2), 1).unwrap();
        let pack1 = raw_saltpacks.get(0).unwrap();
        let mut reader : &[u8] = pack1.raw_bytes.as_slice();
        let header = SaltpackHeader10::read_header(&mut reader).unwrap();
        // assert_eq!(header.mode, SaltpackMessageType::ENCRYPTEDMESSAGE);
        // assert_eq!(header.recipients.len(), 3);
        // if let SaltpackHeader10::Encryption(enc_header) = header {
        //     enc_header.verify()
        // }

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
