//! This modules provides methods to generate new keys for encryption and
//! signing or to decode those keys from hexadecimal encoding.
//!
//! [As with keybase](https://keybase.io/docs/api/1.0/kid), the encryption key does not equal the signing key.
//!
//!  * The signing key is an _EdDSA (Ed25519)_ key
//!  * The encryption key is a _DH over Curve25519_ key
//!
//! ## Usage
//!
//! ```
//! use rsaltpack::key::{EncryptionPublicKey, SigningPublicKey,
//!                      KeybaseKeyFormat, KeybaseKeyFormatVersion};
//!
//! // Encryption keys start with 0121
//! let chris_encr_key = "0121b6f70a8b79a28742a0a85e493f825e7\
//!                       9a15cddce080e59d671ccb1da9b50a07a0a";
//! let key = EncryptionPublicKey::from_keybaseformat(&chris_encr_key).unwrap();
//! println!("Chris public key for asymmetric authenticated encryption: {}",
//!          key.into_keybaseformat(KeybaseKeyFormatVersion::Version1));
//!
//! // Signing keys start with 0120
//! let chris_signing_key = "01203a5a45c545ef4f661b8b7573711aaec\
//!                          ee3fd5717053484a3a3e725cd68abaa5a0a";
//! assert!(SigningPublicKey::from_keybaseformat(&chris_signing_key).is_ok());
//! ```
//!
//!
//! ## Notes Regarding Keybase
//!
//! During key generation in keybase, the signing key signs the encryption key, see
//!
//! * client/go/engine/kex2_provisionee.go : cacheKeys(), HandleDidCounterSign()
//! * also see client/go/libkb/naclwrap.go : makeNaclSigningKeyPair(), makeNaclDHKeyPair()
//!   - makeNaclDHKeyPair() uses NaCls box.GenerateKey()
//!   - makeNaclSigningKeyPair() **uses ed25519.GenerateKey() but not NaCl!**
//!
//! Signing doesn't use [old NaCl signatures
//! (crypto_sign_edwards25519sha512batch)](http://nacl.cr.yp.to/sign.html) but the
//! [Ed25519](https://ed25519.cr.yp.to/).
//! I guess the NaCl lib of keybase did not
//! support Ed25519 at time of writing their code, so they used
//! [github:agl/ed25519](https://github.com/agl/ed25519)
//! instead of the NaCl primitives. But this has changed and
//! [now](../../sodiumoxide/crypto/sign/index.html)
//! we can simply use NaCl aka sodiumoxide.
//!
//!
//! # Security Note
//!
//! The library in the background, sodiumoxide, has implemented
//! Drop for SecretKey. During `drop()`, the secret key data is wiped
//! from memory.
//!

pub use sodiumoxide::crypto::box_::PublicKey as EncryptionPublicKey;
pub use sodiumoxide::crypto::box_::SecretKey as EncryptionSecretKey;

pub use sodiumoxide::crypto::sign::PublicKey as SigningPublicKey;
pub use sodiumoxide::crypto::sign::SecretKey as SigningSecretKey;

pub use sodiumoxide::crypto::secretbox::Key; // symmmetric encryption

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use std::str::from_utf8;
use errors::*;

/// Composition of a public key and a secret key for
/// asymmetric authenticated encryption.
///
/// A keypair typically belongs to one user.
pub struct EncryptionKeyPair {
    pub p : EncryptionPublicKey,
    pub s : EncryptionSecretKey
}

impl EncryptionKeyPair {
    /// Generates a new, random keypair.
    pub fn gen() -> EncryptionKeyPair {
        let (p, s) = box_::gen_keypair();
        EncryptionKeyPair { p : p, s : s }
    }
}

/// Composition of a public key and a secret key for signatures.
///
/// A keypair typically belongs to one user.
///

pub struct SigningKeyPair {
    pub p : SigningPublicKey,
    pub s : SigningSecretKey
}

impl SigningKeyPair {
    /// Generates a new, random keypair.
    pub fn gen() -> SigningKeyPair {
        let (p, s) = sign::gen_keypair();
        SigningKeyPair { p : p, s : s }
    }
}

/// Parses hex formatted data.
///
/// # Errors
/// This function can return the ErrorKinds
///
///  - `Utf8Error`
///  - `ParseIntError`
pub fn hex_to_bytes(hex : &str) -> Result<Vec<u8>> {
    let mut bin = Vec::with_capacity(hex.len() / 2 + 1);
    for b in hex.as_bytes().chunks(2) {
        let c = from_utf8(&b)?;
        bin.push(u8::from_str_radix(&c, 16)?);
    }
    Ok(bin)
}

/// Formats bytes as lowercase hexadecimal string.
pub fn bytes_to_hex(bin : &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bin.len() * 2);
    for b in bin.iter() {
        write!(out, "{:02x}", b).ok();
    }
    out
}

/// Checks the common traits of keybase formated keys and returns the type part.
///
/// # Errors
/// This function can return the ErrorKinds
///
///  - `KeybaseKeyNotAPublicKey`
///  - `KeybaseKeyUnsupportedVersion`
///  - `KeybaseKeyWrongLength`
fn check_keybase_format(hex : &str) -> Result<&str> {
    let len = hex.len();
    if &hex[len-2..len] != "0a" {
        bail!(ErrorKind::KeybaseKeyNotAPublicKey);
    }
    if &hex[0..2] != "01" {
        bail!(ErrorKind::KeybaseKeyUnsupportedVersion(hex[0..2].to_owned()));
    }
    if hex.len() != 35*2 {
        bail!(ErrorKind::KeybaseKeyWrongLength(hex.len()));
    }
    return Ok(&hex[2..4])
}

/// The possible versions for formating keybase KIDs.
///
/// Default is implemented and will always be the newest version.
pub enum KeybaseKeyFormatVersion {
    Version1
}

impl Default for KeybaseKeyFormatVersion {
    fn default() -> Self {
        KeybaseKeyFormatVersion::Version1
    }
}

/// Helper to convert `EncryptionPublicKey`s and `SigningPublicKey`s
/// from and to the [keybase KID format](https://keybase.io/docs/api/1.0/kid).
pub trait KeybaseKeyFormat : Sized {
    /// Parses a key given in keybases human readable KID style.
    ///
    /// # Errors
    /// This function can return the ErrorKinds
    ///
    ///  - `KeybaseKeyNotAPublicKey`
    ///  - `KeybaseKeyUnsupportedVersion`
    ///  - `KeybaseKeyWrongLength`
    ///  - `KeybaseKeyNotAnEncryptionKey` or `KeybaseKeyNotASigningKey`
    ///  - `CouldNotDecodeHex`
    fn from_keybaseformat(keybase_formatted_key : &str) -> Result<Self>;
    /// Formats the key data in keybases human readable KID style.
    fn into_keybaseformat(&self, v : KeybaseKeyFormatVersion) -> String;
}

impl KeybaseKeyFormat for EncryptionPublicKey {
    fn from_keybaseformat(keybase_formatted_key : &str) -> Result<Self> {
        if check_keybase_format(&keybase_formatted_key)? != "21" {
            bail!(ErrorKind::KeybaseKeyNotAnEncryptionKey);
        }
        let bytes = hex_to_bytes(&keybase_formatted_key[4..68])
            .chain_err(|| ErrorKind::CouldNotDecodeHex)?;
        Ok(Self::from_slice(bytes.as_slice()).unwrap())
    }
    fn into_keybaseformat(&self, v : KeybaseKeyFormatVersion) -> String {
        match v {
            KeybaseKeyFormatVersion::Version1 => {
                let mut s = String::with_capacity(70);
                s.push_str("0121"); // version 01, type 21=DH_over_Curve25519=encryption
                s.push_str(&bytes_to_hex(&self.0[..]));
                s.push_str("0a");
                s
            }
        }
    }
}


impl KeybaseKeyFormat for SigningPublicKey {
    fn from_keybaseformat(hex : &str) -> Result<Self> {
        if check_keybase_format(&hex)? != "20" {
            bail!(ErrorKind::KeybaseKeyNotASigningKey);
        }
        let bytes = hex_to_bytes(&hex[4..68])
            .chain_err(|| ErrorKind::CouldNotDecodeHex)?;
        Ok(Self::from_slice(bytes.as_slice()).unwrap())
    }
    fn into_keybaseformat(&self, v : KeybaseKeyFormatVersion) -> String {
        match v {
            KeybaseKeyFormatVersion::Version1 => {
                let mut s = String::with_capacity(70);
                s.push_str("0120"); // version 01, type 20=EdDSA=signing
                s.push_str(&bytes_to_hex(&self.0[..]));
                s.push_str("0a");
                s
            }
        }
    }
}

/// Helper to convert `EncryptionPublicKey` and `SigningPublicKey`
/// from and to a simple unstructured hex representation.
pub trait RawHexEncoding : Sized {
    /// Parses a hex string.
    ///
    /// # Errors
    /// This function can return the ErrorKinds
    ///
    ///  - `RawHexEncodedKeyWrongLength`
    ///  - `CouldNotDecodeHex`
    fn from_rawhex(hex : &str) -> Result<Self>;
    fn into_rawhex(&self) -> String;
    fn formatted_len() -> usize;
}

impl RawHexEncoding for EncryptionPublicKey {
    fn formatted_len() -> usize {
        use sodiumoxide::crypto::box_::PUBLICKEYBYTES;
        PUBLICKEYBYTES*2
    }
    fn from_rawhex(hex : &str) -> Result<Self> {
        if hex.len() != Self::formatted_len() {
            bail!(ErrorKind::RawHexEncodedKeyWrongLength(
                "public encryption".to_owned(), hex.len(), Self::formatted_len()));
        }
        let bytes = hex_to_bytes(&hex[..])
            .chain_err(|| ErrorKind::CouldNotDecodeHex)?;
        Ok(Self::from_slice(bytes.as_slice()).unwrap())
    }
    fn into_rawhex(&self) -> String {
        bytes_to_hex(&self.0[..])
    }
}

impl RawHexEncoding for SigningPublicKey {
    fn formatted_len() -> usize {
        use sodiumoxide::crypto::box_::PUBLICKEYBYTES;
        PUBLICKEYBYTES*2
    }
    fn from_rawhex(hex : &str) -> Result<Self> {
        if hex.len() != Self::formatted_len() {
            bail!(ErrorKind::RawHexEncodedKeyWrongLength(
                "public signing".to_owned(), hex.len(), Self::formatted_len()));
        }
        let bytes = hex_to_bytes(&hex[..])
            .chain_err(|| ErrorKind::CouldNotDecodeHex)?;
        Self::from_slice(bytes.as_slice()).ok_or("Some error that should not happen.".into())
    }
    fn into_rawhex(&self) -> String {
        bytes_to_hex(&self.0[..])
    }
}

#[test]
fn test_enc_public_key_to_string() {
    let key = EncryptionPublicKey::from_slice(
        vec![1,2,3,4,5,6,7,8,
             61,62,63,64,65,66,67,68,
             121,122,123,124,125,126,127,128,
             211,212,213,214,215,216,217,218,].as_slice()).unwrap();

    let kb = key.into_keybaseformat(KeybaseKeyFormatVersion::Version1);
    let hex = key.into_rawhex();
    assert_eq!("01020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da", hex);
    assert_eq!("012101020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da0a", kb);

    let bin1 = EncryptionPublicKey::from_rawhex(&hex).unwrap();
    let bin2 = EncryptionPublicKey::from_keybaseformat(&kb).unwrap();
    assert_eq!(&bin1.0, &key.0);
    assert_eq!(&bin2.0, &key.0);
}

#[test]
fn test_sign_public_key_to_string() {
    let key = SigningPublicKey::from_slice(
        vec![1,2,3,4,5,6,7,8,
             61,62,63,64,65,66,67,68,
             121,122,123,124,125,126,127,128,
             211,212,213,214,215,216,217,218,].as_slice()).unwrap();

    let kb = key.into_keybaseformat(Default::default());
    let hex = key.into_rawhex();
    assert_eq!("01020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da", hex);
    assert_eq!("012001020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da0a", kb);

    let bin1 = SigningPublicKey::from_rawhex(&hex).unwrap();
    let bin2 = SigningPublicKey::from_keybaseformat(&kb).unwrap();
    assert_eq!(&bin1.0, &key.0);
    assert_eq!(&bin2.0, &key.0);
}

#[test]
fn test_import_original_keybase_key() {
    let chris_ccpro_signing_key = "01203a5a45c545ef4f661b8b7573711aaecee3fd5717053484a3a3e725cd68abaa5a0a";
    let chris_ccpro_encr_key = "0121b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a0a";
    assert!(EncryptionPublicKey::from_keybaseformat(&chris_ccpro_encr_key).is_ok());
    assert!(EncryptionPublicKey::from_keybaseformat(&chris_ccpro_signing_key).is_err());
    assert!(SigningPublicKey::from_keybaseformat(&chris_ccpro_encr_key).is_err());
    assert!(SigningPublicKey::from_keybaseformat(&chris_ccpro_signing_key).is_ok());
}

#[test]
fn test_failures() {
    let wrong_size = "2342017019274";
    assert!(EncryptionPublicKey::from_keybaseformat(&wrong_size).is_err());
    assert!(EncryptionPublicKey::from_rawhex(&wrong_size).is_err());
    let other = "0121b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a01";
    assert!(EncryptionPublicKey::from_keybaseformat(&other).is_err()); // end != 0a
    let other_version = "0221b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a01";
    assert!(EncryptionPublicKey::from_keybaseformat(&other_version).is_err()); // version = 02
    let not_09af = "0121b6f70a8b79a28742a0ag5e493f825e79a15cddce080e59d671ccb1da9b50a07a0a";
    assert!(EncryptionPublicKey::from_keybaseformat(&not_09af).is_err()); // char g
    let unicode = "0121bÐ6f70a8b79a28742a0ae493f825e79a15cddce080e59d671ccb1da9b50a07a0a";
    assert!(EncryptionPublicKey::from_keybaseformat(&unicode).is_err()); // char Ð at boundary
    let unicode = "0Ð20304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da";
    assert!(EncryptionPublicKey::from_rawhex(&unicode).is_err()); // char Ð at boundary
}