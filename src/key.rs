//! This modules provides methods to generate new keys for encryption and
//! signing or to decode those keys from hexadecimal encoding.
//!
//! [As with keybase](https://keybase.io/docs/api/1.0/kid), the encryption key does not equal the
//! signing key.
//!
//!  * The signing key is an `EdDSA (Ed25519)` key
//!  * The encryption key is a `DH over Curve25519` key
//!
//! ## Usage
//!
//! ```
//! use rsaltpack::key::{EncryptionPublicKey, SigningPublicKey, Hex,
//!                      KeybaseKeyFormat, KeybaseKeyFormatVersion};
//!
//! // Encryption keys start with 0121
//! let chris_encr_key = Hex::from("0121b6f70a8b79a28742a0a85e493f825e7\
//!                                 9a15cddce080e59d671ccb1da9b50a07a0a");
//! let key = EncryptionPublicKey::from_keybaseformat(&chris_encr_key).unwrap();
//! println!("Chris public key for asymmetric authenticated encryption: {}",
//!          key.into_keybaseformat(KeybaseKeyFormatVersion::Version1));
//!
//! // Signing keys start with 0120
//! let chris_signing_key = Hex::from("01203a5a45c545ef4f661b8b7573711aaec\
//!                                    ee3fd5717053484a3a3e725cd68abaa5a0a");
//! assert!(SigningPublicKey::from_keybaseformat(&chris_signing_key).is_ok());
//! ```
//!
//!
//! ## Notes Regarding Keybase
//!
//! During key generation in keybase, the signing key signs the encryption key, see
//!
//! * `client/go/engine/kex2_provisionee.go` : `cacheKeys()`, `HandleDidCounterSign()`
//! * also see `client/go/libkb/naclwrap.go` : `makeNaclSigningKeyPair()`, `makeNaclDHKeyPair()`
//!   - `makeNaclDHKeyPair()` uses `NaCls` `box.GenerateKey()`
//!   - `makeNaclSigningKeyPair()` **uses `ed25519.GenerateKey()` but not `NaCl`!**
//!
//! Signing doesn't use [old `NaCl` signatures
//! (`crypto_sign_edwards25519sha512batch`)](http://nacl.cr.yp.to/sign.html) but the
//! [Ed25519](https://ed25519.cr.yp.to/).
//! I guess the `NaCl` lib of keybase did not
//! support Ed25519 at time of writing their code, so they used
//! [github:agl/ed25519](https://github.com/agl/ed25519)
//! instead of the `NaCl` primitives. But this has changed and
//! [now](../../sodiumoxide/crypto/sign/index.html)
//! we can simply use `NaCl` aka `sodiumoxide`.
//!
//!
//! # Security Note
//!
//! The library in the background, `sodiumoxide`, has implemented
//! Drop for `SecretKey`. During `drop()`, the secret key data is wiped
//! from memory.
//!

pub use sodiumoxide::crypto::box_::PublicKey as EncryptionPublicKey;
pub use sodiumoxide::crypto::box_::SecretKey as EncryptionSecretKey;
pub use sodiumoxide::crypto::box_::PUBLICKEYBYTES as ENCRYPTIONPUBLICKEYBYTES;
pub use sodiumoxide::crypto::box_::SECRETKEYBYTES as ENCRYPTIONSECRETKEYBYTES;

pub use sodiumoxide::crypto::sign::PublicKey as SigningPublicKey;
pub use sodiumoxide::crypto::sign::SecretKey as SigningSecretKey;
pub use sodiumoxide::crypto::sign::PUBLICKEYBYTES as SIGNPUBLICKEYBYTES;
pub use sodiumoxide::crypto::sign::SECRETKEYBYTES as SIGNSECRETKEYBYTES;

pub use sodiumoxide::crypto::secretbox::Key; // symmmetric encryption
pub use sodiumoxide::crypto::secretbox;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use ring_pwhash::scrypt::{scrypt, ScryptParams};

use sodiumoxide::utils::memzero;

use base64;
use rmpv;
use serde_bytes;

use std::fmt;
use std::str::from_utf8;
use std::borrow::Cow;
use self::errors::*;

pub mod errors {
    error_chain! {
        types { KeyError, KeyErrorKind, KeyResultExt, KeyResult; }

        errors {
            #[doc = "String has wrong length. Data: (received_len_hex_format)"]
            KeybaseKeyWrongLength(length: usize) {
                description("String has wrong length. \
                    Keybase formated keys have a length of 70 chars.")
                display("String has wrong length. \
                    Expected 70 chars but got {} chars.", length)
            }

            #[doc = "Given string is not a keybase public key."]
            KeybaseKeyNotAPublicKey {
                description("Given string is not a keybase public key. \
                    Keybase formated keys end with `0a`.")
            }

            #[doc = "Unsupported keybase key version. Data: (received_version)"]
            KeybaseKeyUnsupportedVersion(v: u32) {
                description("Unsupported keybase key version.")
                display("Unsupported keybase key version. Got version {}.", v)
            }

            #[doc = "Given key is not a encryption key"]
            KeybaseKeyNotAnEncryptionKey {
                description("Given key is not an encryption key. \
                    Keybase encryption keys start with `0121`.")
            }

            #[doc = "Given key is not a signing key"]
            KeybaseKeyNotASigningKey {
                description("Given key is not a signing key. \
                    Keybase signing keys start with `0120`.")
            }

            #[doc = "Wrong Length. Data: (received_len, expected_len)"]
            WrongLength(received_len: usize, expected_len: usize) {
                description("Hex encoded data has wrong length.")
                display("Hex encoded data has wrong length. \
                    Expected {} chars but got {} chars.", expected_len, received_len)
            }

            #[doc = "Error while decoding hex encoded string."]
            CouldNotDecodeHex {
                description("Error while decoding hex encoded string. \
                    Only ascii numerals and chars from a-f are allowed.")
            }

            #[doc = "Error while parsing secret key store"]
            CouldNotParseSecretKeyStore {
                description("Error while parsing secret key store.")
            }

            #[doc = "Error while parsing a keybase packet. Got unsupported packet type."]
            UnsupportedKeybasePacket {
                description("Error while parsing a keybase packet. Got unsupported packet type.")
            }
        }

        foreign_links {

            Utf8Error(::std::str::Utf8Error) #[doc = "Foreign error: std::str::Utf8Error"];

            ParseIntError(::std::num::ParseIntError)
            #[doc = "Foreign error: std::num::ParseIntError"];

            Base64Error(::base64::DecodeError) #[doc = "Foreign error: base64::DecodeError"];

            MessagePackError(::rmpv::decode::Error) #[doc = "Foreign error: rmpv::decode::Error"];

            MessagePackError2(::rmp_serde::decode::Error) #[doc = "Foreign error: rmp_serde::decode::Error"];
        }
    }

    error_chain_option_ext!(KeyError, KeyErrorKind, KeyOptionExt);

}


/// Composition of a public key and a secret key for
/// asymmetric authenticated encryption.
///
/// A keypair typically belongs to one user.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncryptionKeyPair {
    pub p: EncryptionPublicKey,
    pub s: EncryptionSecretKey,
}

impl EncryptionKeyPair {
    /// Generates a new, random keypair.
    pub fn gen() -> EncryptionKeyPair {
        let (p, s) = box_::gen_keypair();
        EncryptionKeyPair { p: p, s: s }
    }
}

/// Composition of a public key and a secret key for signatures.
///
/// A keypair typically belongs to one user.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SigningKeyPair {
    pub p: SigningPublicKey,
    pub s: SigningSecretKey,
}

impl SigningKeyPair {
    /// Generates a new, random keypair.
    pub fn gen() -> SigningKeyPair {
        let (p, s) = sign::gen_keypair();
        SigningKeyPair { p: p, s: s }
    }
}

/// A KeyPair, either for encryption or for signing.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum KeyPair {
    Encryption(EncryptionKeyPair),
    Signing(SigningKeyPair),
}

impl From<EncryptionKeyPair> for KeyPair {
    fn from(s: EncryptionKeyPair) -> Self {
        KeyPair::Encryption(s)
    }
}

impl From<SigningKeyPair> for KeyPair {
    fn from(s: SigningKeyPair) -> Self {
        KeyPair::Signing(s)
    }
}

impl KeyPair {
    /// Returns the the `EncryptionKeyPair` or None, if this `KeyPair` is
    /// a `SigningKeyPair`.
    pub fn as_encryption_keypair(&self) -> Option<EncryptionKeyPair> {
        match *self {
            KeyPair::Encryption(ref ekp) => Some(ekp.clone()),
            _ => None,
        }
    }

    /// Returns the the `SigningKeyPair` or None, if this `KeyPair` is
    /// a `EncryptionKeyPair`.
    pub fn as_signing_keypair(&self) -> Option<SigningKeyPair> {
        match *self {
            KeyPair::Signing(ref skp) => Some(skp.clone()),
            _ => None,
        }
    }
}

/// A 16 byte salt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Salt16(pub [u8; 16]);

/// String that holds hex encoded binary data.
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Hex<'a>(pub Cow<'a, str>);

impl<'a> Hex<'a> {
    /// Returns a reference to `self` if the string has the expected length in bytes.
    ///
    /// # Errors
    /// This function can return the `KeyErrorKinds`
    ///
    ///  - `WrongLength`
    ///
    pub fn assert_len(&'a self, len: usize) -> KeyResult<&'a Self> {
        if self.0.len() != len * 2 {
            bail!(KeyErrorKind::WrongLength(self.0.len(), len * 2));
        }
        Ok(self)
    }

    /// Parses hex formatted data.
    ///
    /// # Errors
    /// This function can return the `KeyErrorKinds`
    ///
    ///  - `CouldNotDecodeHex`
    ///
    pub fn to_bytes(&self) -> KeyResult<Vec<u8>> {
        let mut bin = Vec::with_capacity(self.0.len() / 2 + 1);
        for b in self.0.as_bytes().chunks(2) {
            let c = from_utf8(b).chain_err(|| KeyErrorKind::CouldNotDecodeHex)?;
            bin.push(u8::from_str_radix(c, 16)
                .chain_err(|| KeyErrorKind::CouldNotDecodeHex)?);
        }
        Ok(bin)
    }

    /// Formats bytes as lowercase hexadecimal string.
    pub fn from_bytes(bin: &[u8]) -> Hex {
        use std::fmt::Write;
        let mut out = String::with_capacity(bin.len() * 2);
        for b in bin.iter() {
            write!(out, "{:02x}", b).ok();
        }
        Hex(out.into())
    }
}

impl<'a> fmt::Display for Hex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<'a> AsRef<str> for Hex<'a> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'a> From<&'a str> for Hex<'a> {
    fn from(hexstr: &'a str) -> Hex<'a> {
        Hex(hexstr.into())
    }
}

impl<'a> From<String> for Hex<'a> {
    fn from(hexstr: String) -> Hex<'a> {
        Hex(hexstr.into())
    }
}

/// A trait for types that can be created from a byte slice.
///
/// This trait is implemented for all `FoobarKey` types to have a common interface for the
/// `from_slice` methods implemented in `sodiumoxide`.
pub trait FromSlice: Sized {
    /// Returns the expected length in bytes.
    fn slice_len() -> usize;
    /// Converts from a slice.
    fn from_slice(bytes: &[u8]) -> Option<Self>;
}

macro_rules! impl_FromSlice {
    ($for:ty, $len_const:expr) => (
        impl FromSlice for $for {
            fn slice_len() -> usize {
                $len_const
            }
            fn from_slice(bytes: &[u8]) -> Option<Self> {
                Self::from_slice(bytes)
            }
        }
    );
}

impl_FromSlice!(EncryptionPublicKey, ENCRYPTIONPUBLICKEYBYTES);
impl_FromSlice!(EncryptionSecretKey, ENCRYPTIONSECRETKEYBYTES);
impl_FromSlice!(SigningPublicKey, SIGNPUBLICKEYBYTES);
impl_FromSlice!(SigningSecretKey, SIGNSECRETKEYBYTES);
impl_FromSlice!(Key, secretbox::KEYBYTES);

impl FromSlice for Salt16 {
    fn slice_len() -> usize {
        16
    }

    fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut salt = Salt16([0; 16]);
        salt.0.copy_from_slice(&bytes[0..16]);
        Some(salt)
    }
}

/// A trait for types that can be transformed into a byte slice.
///
/// This trait is implemented for all `FoobarKey` types to have a common
/// implementation for the `RawHexEncoding` trait.
pub trait AsSlice {
    /// Returns the binary representation.
    fn as_slice(&self) -> &[u8];
}

macro_rules! impl_AsSlice {
    ($for:ty) => (
        impl AsSlice for $for {
            fn as_slice(&self) -> &[u8] {
                &self.0[..]
            }
        }
    );
}

impl_AsSlice!(EncryptionPublicKey);
impl_AsSlice!(EncryptionSecretKey);
impl_AsSlice!(SigningPublicKey);
impl_AsSlice!(SigningSecretKey);
impl_AsSlice!(Key);
impl_AsSlice!(Salt16);


/// Checks the common traits of [keybase formated keys](https://keybase.io/docs/api/1.0/kid) and
/// returns the type part.
///
/// # Errors
/// This function can return the `KeyErrorKinds`
///
///  - `KeybaseKeyNotAPublicKey`
///  - `KeybaseKeyUnsupportedVersion`
///  - `KeybaseKeyWrongLength`
///
fn check_keybase_format(bin: &[u8]) -> KeyResult<u32> {
    let len = bin.len();
    if len < 3 {
        bail!(KeyErrorKind::KeybaseKeyWrongLength(len * 2));
    }
    if *bin.last().unwrap() != 10 {
        // hex: 0a
        bail!(KeyErrorKind::KeybaseKeyNotAPublicKey);
    }
    if bin[0] != 1 {
        // hex: 01
        bail!(KeyErrorKind::KeybaseKeyUnsupportedVersion(bin[0] as u32));
    }
    if bin.len() != 35 {
        bail!(KeyErrorKind::KeybaseKeyWrongLength(len * 2));
    }
    Ok(bin[1] as u32)
}

/// The possible versions for formating keybase KIDs.
///
/// Default is implemented and will always be the newest version.
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum KeybaseKeyFormatVersion {
    Version1,
}

impl Default for KeybaseKeyFormatVersion {
    fn default() -> Self {
        KeybaseKeyFormatVersion::Version1
    }
}

/// Helper to convert `EncryptionPublicKey`s and `SigningPublicKey`s
/// from and to the [keybase KID format](https://keybase.io/docs/api/1.0/kid).
pub trait KeybaseKeyFormat: Sized {
    /// Parses a key given in keybase's human readable KID style.
    ///
    /// # Errors
    /// This function can return the `KeyErrorKinds`
    ///
    ///  - `KeybaseKeyNotAPublicKey`
    ///  - `KeybaseKeyUnsupportedVersion`
    ///  - `KeybaseKeyWrongLength`
    ///  - `KeybaseKeyNotAnEncryptionKey` or `KeybaseKeyNotASigningKey`
    ///  - `CouldNotDecodeHex`
    ///
    fn from_keybaseformat(keybase_formatted_key: &Hex) -> KeyResult<Self>;

    /// Formats the key data in keybases human readable KID style.
    fn into_keybaseformat(&self, v: KeybaseKeyFormatVersion) -> Hex;
}

impl KeybaseKeyFormat for EncryptionPublicKey {
    fn from_keybaseformat(keybase_formatted_key: &Hex) -> KeyResult<Self> {
        let bytes = keybase_formatted_key.to_bytes()?;
        if check_keybase_format(&bytes)? != 0x21 {
            bail!(KeyErrorKind::KeybaseKeyNotAnEncryptionKey);
        }
        Ok(Self::from_slice(&bytes[2..34]).unwrap())
    }
    fn into_keybaseformat(&self, v: KeybaseKeyFormatVersion) -> Hex {
        match v {
            KeybaseKeyFormatVersion::Version1 => {
                let mut s = String::with_capacity(70);
                s.push_str("0121"); // version  01, type 21=DH_over_Curve25519=encryption
                s.push_str(Hex::from_bytes(&self.0[..]).as_ref());
                s.push_str("0a");
                s.into()
            }
        }
    }
}


impl KeybaseKeyFormat for SigningPublicKey {
    fn from_keybaseformat(keybase_formatted_key: &Hex) -> KeyResult<Self> {
        let bytes = keybase_formatted_key.to_bytes()?;
        if check_keybase_format(&bytes)? != 0x20 {
            bail!(KeyErrorKind::KeybaseKeyNotASigningKey);
        }
        Ok(Self::from_slice(&bytes[2..34]).unwrap())
    }
    fn into_keybaseformat(&self, v: KeybaseKeyFormatVersion) -> Hex {
        match v {
            KeybaseKeyFormatVersion::Version1 => {
                let mut s = String::with_capacity(70);
                s.push_str("0120"); // version  01, type 20=EdDSA=signing
                s.push_str(Hex::from_bytes(&self.0[..]).as_ref());
                s.push_str("0a");
                s.into()
            }
        }
    }
}

/// Helper to convert `EncryptionPublicKey` and `SigningPublicKey`
/// from and to a simple unstructured hex representation.
pub trait RawHexEncoding: Sized {
    /// Parses a hex string.
    ///
    /// # Errors
    /// This function can return the `KeyErrorKinds`
    ///
    ///  - `WrongLength`
    ///  - `CouldNotDecodeHex`
    fn from_rawhex(hex: &Hex) -> KeyResult<Self>;

    /// Formats the data as raw hex.
    fn into_rawhex(&self) -> Hex;

    /// Returns the length of the formatted data.
    fn formatted_len() -> usize;
}

impl<T> RawHexEncoding for T
where
    T: FromSlice + AsSlice,
{
    fn formatted_len() -> usize {
        T::slice_len() * 2
    }

    fn from_rawhex(hex: &Hex) -> KeyResult<Self> {
        let bytes = hex.assert_len(T::slice_len())?.to_bytes()?;
        Ok(Self::from_slice(bytes.as_slice()).unwrap())
    }

    fn into_rawhex(&self) -> Hex {
        Hex::from_bytes(self.as_slice())
    }
}


#[allow(bad_style)]
/// Derive the `lksec` key from the keybase password, a device salt and a part of the `lksec_key`
/// that is usually saved on `keybase.io`.
///
/// # Where to get the information
///
/// - The password is the keybase users main password.
/// - Get the `salt` from `~/.config/keybase/config.json` .
/// - Login on `keybase.io` and GET `https://keybase.io/_/api/1.0/key/fetch_private.json`. Look
///   for `lks_server_half` that belongs to the device that the mpack keyring is from.
///
/// # Algorithm
///
/// - Use the `scrypt` key derivation function to derive a 320 byte key from the user password
///   and the given salt. Use the parameters N=32768, r=8, p=1.
/// - Slice the derived key:
///   ``` derivedKey = concat!(macKey_48, macKey_48, chipherKey_32, chipherKey_32, chipherKey_32,
///                            pwh_32, edssa_32, dh_32, lks_32)
///   ```
///   The numbers are the sub key lengths.
/// - XOR the `lks_32` with the `lks_server_half`. This is the lksec key.
///
/// # Original Source
///
/// [`func StretchPassphrase`]
/// (https://github.com/keybase/client/blob/master/go/libkb/passphrase_stream.go#L17)
/// [`lksIndex`: Position of lks key in second part of their derived key]
/// (https://github.com/keybase/client/blob/master/go/libkb/passphrase_stream.go#L50)
/// [`func DeriveKey(): usage of `scrypt` in `triplesec`]
/// (https://github.com/keybase/client/blob/master/go/vendor/github.com/keybase/
/// go-triplesec/triplesec.go#L74)
///
pub fn keybase_derive_lksec_key(salt: &Salt16, passwd: &[u8], lks_server_half: &Key) -> Key {

    // scrypt: scryptsalsa208sha256
    //  Go code: derivedKey = scrypt.Key(passphrase, salt, N=32768, r=8, p=1, keyLen=dkLen)
    //  By the way: `libsodium` maps (OpsLimit=1<<20, Memlimit=1<<25) to (N=32768, R=8, p=1).
    //  But: `libsodium` uses a 32 byte salt, length is not configurable, whereby keybase uses
    //       only 16 bytes. Because of that we have to use scrypt from crate ring-pwhash.
    let mut derivedKey = vec![0; 320];
    scrypt(
        passwd,
        salt.as_slice(),
        &ScryptParams::new(15, 8, 1),
        &mut derivedKey,
    );

    // Do not use collect() because then there would remain parts of the key in deallocated
    // memory.
    let mut lks_full = Key::from_slice(&[0; 32]).unwrap();
    {
        let lks_client_half = &derivedKey[288..320];
        lks_full
            .0
            .iter_mut()
            .zip(lks_client_half)
            .zip(lks_server_half.as_slice())
            .map(|((f, c), s)| *f = *c ^ *s)
            .count();
    }

    memzero(&mut derivedKey);

    lks_full
}


#[derive(Debug, Serialize, Deserialize)]
//#[serde(tag = "tag")]
#[serde(untagged)]
enum KeybasePacketBody {
    //#[serde(rename = 513)]
    SKB(KeybasePacketBodySKB),
    None
}

/// [Tags](https://github.com/keybase/client/blob/ae85c9ebd5f2aa9b556184ef82b3def7e82b94c8/go/libkb/constants.go#L379)
#[derive(Serialize, Deserialize, Debug)]
struct KeybasePacket {
    body: KeybasePacketBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<KeybasePacketHash>,
    tag: u64,
    version: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeybasePacketHash {
    #[serde(rename="type")]
    typ: u64,
    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}

/// https://github.com/keybase/client/blob/2c4b9ff0eda734dfd3ec1e27e126056940dbf7ad/go/libkb/skb.go#L41
#[derive(Serialize, Deserialize, Debug)]
struct KeybasePacketBodySKB {
    #[serde(rename = "priv")]
    priv_ : KeybasePacketSKBPriv,
    #[serde(rename = "pub", with = "serde_bytes")]
    pub_ : Vec<u8>,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    algotype: Option<u64>,
}

/// https://github.com/keybase/client/blob/2c4b9ff0eda734dfd3ec1e27e126056940dbf7ad/go/libkb/skb.go#L65
#[derive(Serialize, Deserialize, Debug)]
struct KeybasePacketSKBPriv {
    #[serde(with = "serde_bytes")]
    data : Vec<u8>,
    encryption : u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase_generation : Option<u64>,
}

/// Double check tag because deserializing used try and error instead of tag.
fn check_tag(p: &KeybasePacket) -> KeyResult<()> {
    match (p.tag, &p.body) {
        (513, &KeybasePacketBody::SKB(_)) => Ok(()),
        (_tag, _) => Err(KeyErrorKind::UnsupportedKeybasePacket.into())
    }
}

pub fn open_keybase_keyring2(base64mpack: &str, lksec_key: &Key) -> KeyResult<Vec<KeyPair>> {
    let mpack = base64::decode(base64mpack)?;
    let packets : Vec<KeybasePacket> = ::rmp_serde::from_slice(&mpack)?;
    let mut keys = vec![];
    for packet in &packets {
        check_tag(packet).unwrap();
        if let KeybasePacketBody::SKB(ref body) = packet.body {
            match body.algotype.chain_err(|| "Missing algorithm type information.")? {
                32 => {
                    if check_keybase_format(&body.pub_)? != 32 {
                        bail!("Key type mismatch");
                    }
                    if body.priv_.encryption == 100 {
                        // 100 = LKSecVersion. decrypt priv key
                        let nonce = &body.priv_.data[0..24];
                        let encrypted_priv_key = &body.priv_.data[24..];
                        let secret_key = secretbox::open(
                            encrypted_priv_key,
                            &secretbox::Nonce::from_slice(nonce).unwrap(),
                            lksec_key,
                        ).ok()
                            .chain_err(|| "Wrong Lksec Key")?;
                        keys.push(
                            SigningKeyPair {
                                p: SigningPublicKey::from_slice(&body.pub_[2..34])
                                    .chain_err(|| "Wrong number of bytes for signing public key.")?,
                                s: SigningSecretKey::from_slice(&secret_key)
                                    .chain_err(|| "Wrong number of bytes for signing secret key.")?,
                            }.into(),
                        );
                    }
                }
                33 => {
                    if check_keybase_format(&body.pub_)? != 33 {
                        bail!("Key type mismatch");
                    }
                    if body.priv_.encryption == 100 {
                        // 100 = LKSecVersion. decrypt priv key
                        let nonce = &body.priv_.data[0..24];
                        let encrypted_priv_key = &body.priv_.data[24..];
                        let secret_key = secretbox::open(
                            encrypted_priv_key,
                            &secretbox::Nonce::from_slice(nonce).unwrap(),
                            lksec_key,
                        ).ok()
                            .chain_err(|| "Wrong Lksec Key")?;
                        keys.push(
                            EncryptionKeyPair {
                                p: EncryptionPublicKey::from_slice(&body.pub_[2..34])
                                    .chain_err(|| "Wrong number of bytes for encryption public key.")?,
                                s: EncryptionSecretKey::from_slice(&secret_key)
                                    .chain_err(|| "Wrong number of bytes for encryption secret key.")?,
                            }.into(),
                        );
                    }
                }
                _ => {} // Unknown type
            }
        }
    }

    Ok(keys)
}

/// Parses and decrypts the current (June 2017) keybase secret key format as found in
/// `~/.config/keybase/secretkeys.$USER.mpack` on linux systems. The `lksec_key` can be obtained
/// using the `keybase_derive_lksec_key` function.
///
/// # Errors
/// This function can return the `KeyErrorKinds`
///
///  - `Base64Error`
///  - `CouldNotParseSecretKeyStore`
///
/// # Original Source
///
/// [Open Secretbox](https://github.com/keybase/client/blob/master/go/libkb/lksec.go#L407)
pub fn open_keybase_keyring(base64mpack: &str, lsec_key: &Key) -> KeyResult<Vec<KeyPair>> {
    let mpack = base64::decode(base64mpack)?;
    let mut mpack_reader = &mpack[..];
    let structured = rmpv::decode::read_value_ref(&mut mpack_reader)
        .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore)?;
    let items = structured
        .as_array()
        .chain_err(|| "Expected root element to be an array.")
        .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore)?;
    let mut keys = vec![];
    for map in items {
        if find_integer_in_map("version", map)? != 1 {
            bail!("Unsupported key version.");
        }
        let body = find_key_in_map("body", map)?;
        match find_integer_in_map("type", body)? {
            32 => {
                let priv_ = find_key_in_map("priv", body)?;
                let encryption = find_integer_in_map("encryption", priv_)?;
                let priv_key_data = find_binary_in_map("data", priv_)?;
                let pub_key_data = find_binary_in_map("pub", body)?;
                if check_keybase_format(pub_key_data)? != 32 {
                    bail!("Key type mismatch");
                }
                if encryption == 100 {
                    // 100 = LKSecVersion. decrypt priv key
                    let nonce = &priv_key_data[0..24];
                    let encrypted_priv_key = &priv_key_data[24..];
                    let secret_key = secretbox::open(
                        encrypted_priv_key,
                        &secretbox::Nonce::from_slice(nonce).unwrap(),
                        lsec_key,
                    ).ok()
                        .chain_err(|| "Wrong Key")?;
                    keys.push(
                        SigningKeyPair {
                            p: SigningPublicKey::from_slice(&pub_key_data[2..34])
                                .chain_err(|| "Wrong number of bytes for signing public key.")?,
                            s: SigningSecretKey::from_slice(&secret_key)
                                .chain_err(|| "Wrong number of bytes for signing secret key.")?,
                        }.into(),
                    );
                }
            }
            33 => {
                let priv_ = find_key_in_map("priv", body)?;
                let encryption = find_integer_in_map("encryption", priv_)?;
                let priv_key_data = find_binary_in_map("data", priv_)?;
                let pub_key_data = find_binary_in_map("pub", body)?;
                if check_keybase_format(pub_key_data)? != 33 {
                    bail!("Key type mismatch");
                }
                if encryption == 100 {
                    // 100 = LKSecVersion. decrypt priv key
                    let nonce = &priv_key_data[0..24];
                    let encrypted_priv_key = &priv_key_data[24..];
                    let secret_key = secretbox::open(
                        encrypted_priv_key,
                        &secretbox::Nonce::from_slice(nonce).unwrap(),
                        lsec_key,
                    ).ok()
                        .chain_err(|| "Wrong Key")?;
                    keys.push(
                        EncryptionKeyPair {
                            p: EncryptionPublicKey::from_slice(&pub_key_data[2..34])
                                .chain_err(|| "Wrong number of bytes for encryption public key.")?,
                            s: EncryptionSecretKey::from_slice(&secret_key)
                                .chain_err(|| "Wrong number of bytes for encryption secret key.")?,
                        }.into(),
                    );
                }
            }
            _ => {} // Unknown type
        }
    }
    Ok(keys)
}


fn find_key_in_map<'a>(
    searchkey: &'static str,
    map: &'a rmpv::ValueRef,
) -> KeyResult<&'a rmpv::ValueRef<'a>> {
    if let &rmpv::ValueRef::Map(ref map) = map {
        // search for version tag.
        for &(ref key, ref val) in map {
            if let &rmpv::ValueRef::String(ref strref) = key {
                if strref.as_bytes() == searchkey.as_bytes() {
                    return Ok(val);
                }
            }
        }
        return Err(KeyError::from_kind(format!("No {} field found.", searchkey).into()))
            .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore);
    }
    Err(KeyError::from_kind(format!("Expected map with field {}.", searchkey).into()))
        .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore)
}

fn find_integer_in_map<'a>(searchkey: &'static str, map: &'a rmpv::ValueRef) -> KeyResult<u64> {
    find_key_in_map(searchkey, map)?
        .as_u64()
        .chain_err(|| format!("Field {} is not an integer.", searchkey))
        .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore)
}

fn find_binary_in_map<'a>(searchkey: &'static str, map: &'a rmpv::ValueRef) -> KeyResult<&'a [u8]> {
    if let &rmpv::ValueRef::Binary(ref r) = find_key_in_map(searchkey, map)? {
        Ok(r)
    } else {
        Err(KeyError::from_kind(format!("Field {} is not of type binary.", searchkey).into()))
            .chain_err(|| KeyErrorKind::CouldNotParseSecretKeyStore)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const TEST_PUBLIC_KEY: &[u8] = &[
          1,   2,   3,   4,   5,   6,   7,   8,  61,  62,  63,  64,  65,  66,  67,  68,
        121, 122, 123, 124, 125, 126, 127, 128, 211, 212, 213, 214, 215, 216, 217, 218];


    #[test]
    fn test_enc_public_key_to_string() {
        let key = EncryptionPublicKey::from_slice(TEST_PUBLIC_KEY).unwrap();

        let kb = key.into_keybaseformat(KeybaseKeyFormatVersion::Version1);
        let hex = key.into_rawhex();
        assert_eq!(
            Hex::from("01020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da",),
            hex
        );
        assert_eq!(
            Hex::from("012101020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da0a",),
            kb
        );

        let bin1 = EncryptionPublicKey::from_rawhex(&hex).unwrap();
        let bin2 = EncryptionPublicKey::from_keybaseformat(&kb).unwrap();
        assert_eq!(&bin1.0, &key.0);
        assert_eq!(&bin2.0, &key.0);
    }


    #[test]
    fn test_sign_public_key_to_string() {
        let key = SigningPublicKey::from_slice(TEST_PUBLIC_KEY).unwrap();

        let kb = key.into_keybaseformat(Default::default());
        let hex = key.into_rawhex();
        assert_eq!(
            Hex::from("01020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da",),
            hex
        );
        assert_eq!(
            Hex::from("012001020304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da0a",),
            kb
        );

        let bin1 = SigningPublicKey::from_rawhex(&hex).unwrap();
        let bin2 = SigningPublicKey::from_keybaseformat(&kb).unwrap();
        assert_eq!(&bin1.0, &key.0);
        assert_eq!(&bin2.0, &key.0);
    }

    #[test]
    fn test_import_original_keybase_key() {
        let chris_ccpro_signing_key = Hex::from(
            "01203a5a45c545ef4f661b8b7573711aaecee3fd5717053484a3a3e725cd68abaa5a0a",
        );
        let chris_ccpro_encr_key = Hex::from(
            "0121b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a0a",
        );
        assert!(EncryptionPublicKey::from_keybaseformat(&chris_ccpro_encr_key).is_ok());
        assert!(EncryptionPublicKey::from_keybaseformat(&chris_ccpro_signing_key).is_err());
        assert!(SigningPublicKey::from_keybaseformat(&chris_ccpro_encr_key).is_err());
        assert!(SigningPublicKey::from_keybaseformat(&chris_ccpro_signing_key).is_ok());
    }

    #[test]
    fn test_failures() {
        let wrong_size: Hex = "2342017019274".into();
        assert!(EncryptionPublicKey::from_keybaseformat(&wrong_size).is_err());
        assert!(EncryptionPublicKey::from_rawhex(&wrong_size).is_err());
        let other = Hex::from(
            "0121b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a01",
        );
        assert!(EncryptionPublicKey::from_keybaseformat(&other).is_err()); // end != 0a
        let other_version = Hex::from(
            "0221b6f70a8b79a28742a0a85e493f825e79a15cddce080e59d671ccb1da9b50a07a01",
        );
        assert!(EncryptionPublicKey::from_keybaseformat(&other_version).is_err()); // version = 02
        let not_09af = Hex::from(
            "0121b6f70a8b79a28742a0ag5e493f825e79a15cddce080e59d671ccb1da9b50a07a0a",
        );
        assert!(EncryptionPublicKey::from_keybaseformat(&not_09af).is_err()); // char g
        let unicode = Hex::from(
            "0121bÐ6f70a8b79a28742a0ae493f825e79a15cddce080e59d671ccb1da9b50a07a0a",
        );
        assert!(EncryptionPublicKey::from_keybaseformat(&unicode).is_err()); // char Ð at boundary
        let unicode = Hex::from(
            "0Ð20304050607083d3e3f4041424344797a7b7c7d7e7f80d3d4d5d6d7d8d9da",
        );
        assert!(EncryptionPublicKey::from_rawhex(&unicode).is_err()); // char Ð at boundary
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const METHUSALEM_LKSEC_KEY: &[u8] = &[
        227, 243,  51, 214, 177, 143, 155,  96, 145,  70, 135,  83,  66, 122,  31,  10,
        249, 218, 216, 239, 171, 106, 154, 232, 119, 155,   3, 104,  57, 173, 158,  38, ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const METHUSALEM_PUBLIC_SIGNING_KEY: &[u8] = &[
         87, 120,  74, 255, 231,  78,   0, 136, 126, 100,  48, 161, 245,  42, 243, 116,
         53,  20, 130,  92,  39, 254, 214, 137, 105, 147, 133, 130, 186, 180, 114, 117 ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const METHUSALEM_SECRET_SIGNING_KEY: &[u8] = &[
         23, 121,  93, 194,  33,  35, 236, 176, 190, 216,   2, 174, 214, 248,  52,  59,
        116, 197,  47, 209, 146, 186, 140, 214, 137, 226, 110, 100,  82,  24, 238,   5,
         87, 120,  74, 255, 231,  78,   0, 136, 126, 100,  48, 161, 245,  42, 243, 116,
         53,  20, 130,  92,  39, 254, 214, 137, 105, 147, 133, 130, 186, 180, 114, 117 ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const METHUSALEM_PUBLIC_ENCRYPTION_KEY: &[u8] = &[
        114, 129,  35,  56,  91, 151, 168, 230,  43, 164,  83,  42, 155,  97, 127, 116,
         72,  44,  13, 158,  76,  73, 187,  84, 118, 218, 132, 159,   1,   2,  59, 29 ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const METHUSALEM_SECRET_ENCRYPTION_KEY: &[u8] = &[
        251, 113,  10, 173, 163, 113,  40, 169,  28, 161, 244, 252, 104,  52, 150,  35,
        215, 160,  38,  97,   0, 243,  62, 122,  32,  60, 108, 142, 136, 142, 218, 137];

    /// The private encrypted key from ~/.config/keybase/secretkeys.$USER.mpack
    const METHUSALEM_SECRETKEYRING_ENCRYPTED : &str =
        "koSkYm9keYOkcHJpdoOkZGF0YcRoO4VNlkCPdEv42EieS9FAhLp/LcrnYY98UajVTnNMeEUMK6xM2Ghl\
         Fmr4hwY23d/Q2DNZhKdkcTWCBkz81Lj1O/ohLaxsBI1LUjTdl8RQXGUmqn1NsQqxjxapo93IJ8RNNaBZ\
         xDwseG6qZW5jcnlwdGlvbmS1cGFzc3BocmFzZV9nZW5lcmF0aW9uAaNwdWLEIwEgV3hK/+dOAIh+ZDCh\
         9SrzdDUUglwn/taJaZOFgrq0cnUKpHR5cGUgpGhhc2iCpHR5cGUIpXZhbHVlxCDWx4kWg5LRCrwtgZVD\
         JLb8oY85J/qKqGvCThkGvJPQdKN0YWfNAgGndmVyc2lvbgGEpGJvZHmDpHByaXaDpGRhdGHESDC/mIIE\
         A0ZDn1dN1ehrLazgX1J7MUsidEO6MzPScB5Sfm+sbPngEITeAn7rHO18pr+lK0qIrmrhl9hgNJ1EoDU6\
         77iHWUTHqKplbmNyeXB0aW9uZLVwYXNzcGhyYXNlX2dlbmVyYXRpb24Bo3B1YsQjASFygSM4W5eo5iuk\
         UyqbYX90SCwNnkxJu1R22oSfAQI7HQqkdHlwZSGkaGFzaIKkdHlwZQildmFsdWXEIBwzbp+pqHsDiqvs\
         R+sbkG1LnNZXkrc87kfvN9EQXS6Eo3RhZ80CAad2ZXJzaW9uAQ==";

    #[test]
    #[ignore]
    fn test_decode_secret_key() {
        // Yes, these are the real secret information needed to compromise the keybase user
        // named `methusalem`.

        // Login on `keybase.io` and GET `https://keybase.io/_/api/1.0/key/fetch_private.json` .
        // Look for `lks_server_half` that belongs to the device that the mpack keyring is from.
        let lks_server_half: Key = Key::from_rawhex(
            &"d5b229015c708589911e85efa936b8e59360925a866c8ae0c4dce725803fb45f".into(),
        ).unwrap();

        // From `~/.config/keybase/config.json` .
        let salt: Salt16 = Salt16::from_rawhex(&"52b9828e97445b72057c8e2e884975c3".into()).unwrap();

        // The secret user password.
        let passwd = "JTKeNfTLnHbwOlWYJ5wO";

        // Derive the lsec key. This takes multiple seconds since it uses `scrypt` internally
        let lksec = keybase_derive_lksec_key(&salt, passwd.as_bytes(), &lks_server_half);

        let keys: Vec<KeyPair> = open_keybase_keyring(METHUSALEM_SECRETKEYRING_ENCRYPTED,
                                                      &lksec).unwrap();

        assert_eq!(lksec, Key::from_slice(METHUSALEM_LKSEC_KEY).unwrap());

        assert_eq!(
            keys[0].as_signing_keypair().unwrap().p,
            SigningPublicKey::from_slice(METHUSALEM_PUBLIC_SIGNING_KEY).unwrap()
        );

        assert_eq!(
            keys[0].as_signing_keypair().unwrap().s,
            SigningSecretKey::from_slice(METHUSALEM_SECRET_SIGNING_KEY).unwrap()
        );

        assert_eq!(
            keys[1].as_encryption_keypair().unwrap().p,
            EncryptionPublicKey::from_slice(METHUSALEM_PUBLIC_ENCRYPTION_KEY).unwrap()
        );

        assert_eq!(
            keys[1].as_encryption_keypair().unwrap().s,
            EncryptionSecretKey::from_slice(METHUSALEM_SECRET_ENCRYPTION_KEY).unwrap()
        );

    }

    #[test]
    fn test_decode_secret_key_fast() {
        let lksec = Key::from_slice(METHUSALEM_LKSEC_KEY).unwrap();

        let keys: Vec<KeyPair> = open_keybase_keyring2(METHUSALEM_SECRETKEYRING_ENCRYPTED,
                                                      &lksec).unwrap();
        assert_eq!(
            keys[0].as_signing_keypair().unwrap().s,
            SigningSecretKey::from_slice(METHUSALEM_SECRET_SIGNING_KEY).unwrap()
        );
    }
}
