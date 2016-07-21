//! This modules provides methods to generate new keys for encryption and
//! signing or to decode those keys from hexadecimal encoding.
//!
//! [As with keybase](https://keybase.io/docs/api/1.0/kid), the encryption key does not equal the signing key.
//!
//!  * The signing key is an _EdDSA (Ed25519)_ key
//!  * The encryption key is a _DH over Curve25519_ key
//!
//! ## Usage
//! ```
//!    use rsaltpack::key::{EncryptionPublicKey, KeybaseFormat};
//!    // Encryption keys start with 0121
//!    let chris_ccpro_encr_key = "0121b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a0a";
//!    let key = EncryptionPublicKey::from_keybaseformat(&chris_ccpro_encr_key).unwrap();
//!    println!("Chris public key for asymmetric authenticated encryption: {}", key.into_keybaseformat());
//!
//!    use rsaltpack::key::{SigningPublicKey};
//!    // Encryption keys start with 0120
//!    let chris_ccpro_signing_key = "01203a5a45c545ef4f661b8b7573711aaecee3fd5717053484a3a3e725cd68abaa5a0a";
//!    assert!(SigningPublicKey::from_keybaseformat(&chris_ccpro_signing_key).is_ok());
//! ```
//!
//! ## Notes regarding keybase
//! During key generation in keybase, the signing key signs the encryption key, see
//!
//! * client/go/engine/kex2_provisionee.go : cacheKeys(), HandleDidCounterSign())
//! * also see client/go/libkb/naclwrap.go : makeNaclSigningKeyPair(), makeNaclDHKeyPair()
//!   - makeNaclDHKeyPair() uses NaCls box.GenerateKey()
//!   - makeNaclSigningKeyPair() **uses ed25519.GenerateKey() but not NaCl!**
//!
//! Signing doesn't use [old NaCl signatures (crypto_sign_edwards25519sha512batch)](http://nacl.cr.yp.to/sign.html) but
//! the [Ed25519](https://ed25519.cr.yp.to/). I guess the NaCl lib of keybase did not
//! support Ed25519 at time of writing their code, so they used [github:agl/ed25519](https://github.com/agl/ed25519)
//! instead of the NaCl primitives. But this has changed and [now](../../sodiumoxide/crypto/sign/index.html)
//! we can simply use NaCl aka sodiumoxide.

pub use sodiumoxide::crypto::box_::PublicKey as EncryptionPublicKey;
pub use sodiumoxide::crypto::box_::SecretKey as EncryptionSecretKey;

pub use sodiumoxide::crypto::sign::PublicKey as SigningPublicKey;
pub use sodiumoxide::crypto::sign::SecretKey as SigningSecretKey;

pub use sodiumoxide::crypto::secretbox::Key; // symmmetric encryption
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use ::util::{bytes_to_hex, hex_to_bytes};

/// Combination of public and secret key for asymmetric authenticated encryption
pub struct EncryptionKeyPair{ pub p : EncryptionPublicKey, pub s : EncryptionSecretKey }

impl EncryptionKeyPair {
    pub fn gen() -> EncryptionKeyPair {
        let (p, s) = box_::gen_keypair();
        EncryptionKeyPair { p : p, s : s }
    }
    // sodiumoxide has implemented Drop for Secretkey -> wipe
}

/// Combination of public and secret key for signatures
pub struct SigningKeyPair{ pub p : SigningPublicKey, pub s : SigningSecretKey }

impl SigningKeyPair {
    pub fn gen() -> SigningKeyPair {
        let (p, s) = sign::gen_keypair();
        SigningKeyPair { p : p, s : s }
    }
    // sodiumoxide has implemented Drop for Secretkey -> wipe
}

/// Helper to convert between `Encryption..` or `SigningPublicKey`s and the [keybase format](https://keybase.io/docs/api/1.0/kid)
pub trait KeybaseFormat {
    fn from_keybaseformat(hex : &str) -> Result<Self, String>
        where Self: Sized;
    fn into_keybaseformat(&self) -> String;
}

/// Checks the common traits of keybase formated keys and returns the type part
fn check_keybase_format(hex : &str) -> Result<&str, String> {
    if hex.len() != 35*2 {
        return Err("Wrong length. Keybase formated keys have a length of 70 chars.".into())
    }
    if &hex[68..70] != "0a" {
        return Err("Not a keybase public key. Keybase formated keys end with '0a'.".into())
    }
    if &hex[0..2] != "01" {
        return Err("Unsupported version of a keybase key. Expected the key to start with '01'.".into())
    }
    return Ok(&hex[2..4])
}

impl KeybaseFormat for EncryptionPublicKey {
    fn from_keybaseformat(hex : &str) -> Result<Self, String> {
        if try!(check_keybase_format(&hex)) != "21" {
            return Err("Wrong key type. Expected an encryption key that starts with '0121'.".into())
        }
        let bytes = try!(hex_to_bytes(&hex[4..68]).map_err(|e| format!("Could not decode hex string. ({}).", e)));
        Self::from_slice(bytes.as_slice()).ok_or("Some error that should not happen.".into())
    }
    fn into_keybaseformat(&self) -> String {
        let mut s = String::with_capacity(70);
        s.push_str("0121"); // version 01, type 21=DH_over_Curve25519=encryption
        s.push_str(&bytes_to_hex(&self.0[..]));
        s.push_str("0a");
        s
    }
}


impl KeybaseFormat for SigningPublicKey {
    fn from_keybaseformat(hex : &str) -> Result<Self, String> {
        if try!(check_keybase_format(&hex)) != "20" {
            return Err("Wrong key type. Expected a signing key that starts with '0120'.".into())
        }
        let bytes = try!(hex_to_bytes(&hex[4..68]).map_err(|e| format!("Could not decode hex string. ({}).", e)));
        Self::from_slice(bytes.as_slice()).ok_or("Some error that should not happen.".into())
    }
    fn into_keybaseformat(&self) -> String {
        let mut s = String::with_capacity(70);
        s.push_str("0120"); // version 01, type 20=EdDSA=signing
        s.push_str(&bytes_to_hex(&self.0[..]));
        s.push_str("0a");
        s
    }
}

/// Helper to convert between `Encryption..` or `SigningPublicKey`s and simple unstructured hex representation
pub trait RawHexEncoding {
    fn from_rawhex(hex : &str) -> Result<Self, String>
        where Self: Sized;
    fn into_rawhex(&self) -> String;
}

impl RawHexEncoding for EncryptionPublicKey {
    fn from_rawhex(hex : &str) -> Result<Self, String> {
        use sodiumoxide::crypto::box_::PUBLICKEYBYTES;
        if hex.len() != PUBLICKEYBYTES*2 {
            return Err(format!("Wrong length. Expected {} characters.", PUBLICKEYBYTES*2));
        }
        let bytes = try!(hex_to_bytes(&hex[..]).map_err(|e| format!("Could not decode hex string. ({}).", e)));
        Self::from_slice(bytes.as_slice()).ok_or("Some error that should not happen.".into())
    }
    fn into_rawhex(&self) -> String {
        bytes_to_hex(&self.0[..])
    }
}

impl RawHexEncoding for SigningPublicKey {
    fn from_rawhex(hex : &str) -> Result<Self, String> {
        use sodiumoxide::crypto::sign::PUBLICKEYBYTES;
        if hex.len() != PUBLICKEYBYTES*2 {
            return Err(format!("Wrong length. Expected {} characters.", PUBLICKEYBYTES*2));
        }
        let bytes = try!(hex_to_bytes(&hex[..]).map_err(|e| format!("Could not decode hex string. ({}).", e)));
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

    let kb = key.into_keybaseformat();
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

    let kb = key.into_keybaseformat();
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