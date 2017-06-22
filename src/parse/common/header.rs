
use std::io::Read;

use SaltpackMessageType;

use rmpv::decode;
use rmpv::Value;

use key::EncryptionPublicKey;

use sodiumoxide::crypto::box_;

use parse::errors::*;

#[derive(Debug)]
/// Recipient information from saltpack header (mode=encryption)
pub struct Recipient {
    pub recipient_pub: EncryptionPublicKey,
    pub payloadkey_cryptobox: Vec<u8>,
}


pub fn peel_outer_messagepack_encoding<R: Read>(mut raw: &mut R) -> Result<Vec<u8>, ParseError> {
    match decode::read_value(&mut raw) {
        Ok(Value::Binary(bin)) => Ok(bin),
        Err(s) => not_well_formed!("Not a messagepack stream. {}", s),
        e => not_well_formed!("No nested messagepack found. {:?}", e),
    }
}

pub fn get_header_array(reader: &mut &[u8]) -> Result<Vec<Value>, ParseError> {
    match decode::read_value(&mut *reader) {
        Ok(Value::Array(arr)) => Ok(arr),
        Err(s) => return not_well_formed!("Nested binary is not a messagepack stream. {}", s),
        _ => return not_well_formed!("Nested header messagepack is not of type array."),
    }
}

pub fn check_header_format_and_version(
    arr: &[Value],
    expected_version_major: u64,
    expected_version_minor: u64,
) -> Result<(), ParseError> {

    if arr.len() < 2 {
        return not_well_formed!("Header messagepack array to short. ({}<2)", arr.len());
    }

    // 4.1 check first array element to be the string "saltpack"
    let saltpack_str = match arr[0].clone() {
        Value::String(e) => {
            if e.is_str() {
                e.into_str().unwrap()
            } else {
                return not_well_formed!("First header array element is not of type string.");
            }
        }
        _ => {
            return not_well_formed!("First header array element is not of type string.");
        }
    };

    if saltpack_str != "saltpack" {
        return not_well_formed!(
            "Header magic string should be 'saltpack' but is {}",
            saltpack_str
        );
    }

    // 4.2.1 check second array element to be version number
    let version_arr = match arr[1].clone() {
        Value::Array(arr) => arr,
        _ => return not_well_formed!("Header version field is not of type array"),
    };

    if version_arr.len() != 2 {
        return not_well_formed!("Header version field is not of type array[2]");
    }

    let version_major = match version_arr[0].clone() {
        Value::Integer(i) if i.is_u64() => i.as_u64().unwrap(),
        _ => return not_well_formed!("Header version field[0] is not of type integer"),
    };

    let version_minor = match version_arr[1].clone() {
        Value::Integer(i) if i.is_u64() => i.as_u64().unwrap(),
        _ => return not_well_formed!("Header version field[1] is not of type integer"),
    };

    // 4.2.2 check version number to be [1 0]
    if version_major != expected_version_major || version_minor != expected_version_minor {
        bail!(ParseErrorKind::UnsupportedSaltpackVersion(
            version_major,
            version_minor,
        ));
    }

    Ok(())
}

pub fn check_header_len(arr: &[Value], min_len: usize) -> Result<(), ParseError> {
    if arr.len() < min_len {
        return not_well_formed!(
            "Header messagepack array to short. ({}<{})",
            arr.len(),
            min_len
        );
    }
    Ok(())
}

pub fn check_mode(arr: &[Value]) -> Result<SaltpackMessageType, ParseError> {
    match arr[2].clone() {
        Value::Integer(i) if i.is_u64() && i.as_u64().unwrap() == 0 => Ok(
            SaltpackMessageType::ENCRYPTEDMESSAGE,
        ),
        Value::Integer(i) if i.is_u64() && i.as_u64().unwrap() == 1 => Ok(
            SaltpackMessageType::SIGNEDMESSAGE,
        ),
        Value::Integer(i) if i.is_u64() && i.as_u64().unwrap() == 2 => Ok(
            SaltpackMessageType::DETACHEDSIGNATURE,
        ),
        Value::Integer(i) if i.is_u64() => Err(
            ParseErrorKind::UnknownMode(i.as_u64().unwrap()).into(),
        ),
        _ => not_well_formed!("Header mode field[2] is not of type integer"),
    }
}



pub fn read_ephemeral_public_key(arr: &[Value]) -> Result<EncryptionPublicKey, ParseError> {
    let eph_pub = match arr[3].clone() {
        Value::Binary(bin) => bin,
        _ => {
            return not_well_formed!("Header ephemeral public key field[3] is not of type binary");
        }
    };

    let eph_pub_ = EncryptionPublicKey::from_slice(&eph_pub[..]);

    if eph_pub_.is_none() {
        return not_well_formed!(
            "Header ephemeral public key has wrong size. (has {}, expected {})",
            eph_pub.len(),
            box_::PUBLICKEYBYTES
        );
    }

    Ok(eph_pub_.unwrap())
}

pub fn read_sender_secretbox(arr: &[Value]) -> Result<Vec<u8>, ParseError> {
    match arr[4].clone() {
        Value::Binary(bin) => Ok(bin),
        _ => not_well_formed!("Header sender secretbox field[4] is not of type binary"),
    }
}

pub fn get_recipients_messagepackarray(arr: &[Value]) -> Result<Option<Vec<Value>>, ParseError> {
    let has_recipients = arr.len() >= 6;

    if has_recipients {
        match arr[5].clone() {
            Value::Array(arr) => Ok(Some(arr)),
            _ => return not_well_formed!("Header recipient field is not of type array"),
        }
    } else {
        Ok(None)
    }
}

pub fn get_recipient(recipient: &Value) -> Result<Recipient, ParseError> {
    let recipient = match recipient.clone() {
        Value::Array(arr) => arr,
        _ => return not_well_formed!("Header recipient entry is not of type array"),
    };

    if recipient.len() < 2 {
        return not_well_formed!(
            "Header recipient entry has less then two fields: {}",
            recipient.len()
        );
    }

    let recipient_pub_key = match recipient[0].clone() {
        Value::Binary(bin) => bin,
        _ => return not_well_formed!("Header recipient public key is not of type binary."),
    };

    let recipient_pub_key_ = EncryptionPublicKey::from_slice(&recipient_pub_key[..]);

    if recipient_pub_key_.is_none() {
        return not_well_formed!(
            "Header recipient public key has wrong size. (has {}, expected {})",
            recipient_pub_key.len(),
            box_::PUBLICKEYBYTES
        );

    }

    let payloadkey_cryptobox = match recipient[1].clone() {
        Value::Binary(bin) => bin,
        _ => return not_well_formed!("Header payload crypto box is not of type binary."),
    };

    Ok(Recipient {
        recipient_pub: recipient_pub_key_.unwrap(),
        payloadkey_cryptobox: payloadkey_cryptobox,
    })
}
