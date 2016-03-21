

pub use ::SaltpackMessageType;
pub use ::PublicKey;
use std::io::Read;
use rmp::decode;
use rmp::value::{Value, Integer};
use std::char::from_u32;

#[derive(Debug)]
pub struct Recipient {
    recipient_pub: Vec<u8>,
    payloadkey_cryptobox : Vec<u8>
}

#[derive(Debug)]
pub struct SaltpackHeader10 {
   mode : SaltpackMessageType,
   eph_pub : Vec<u8>,
   sender_secretbox : Vec<u8>,
   recipients : Vec<Recipient>,
}

#[derive(Debug)]
pub enum ParseError{
    WrongSaltpackVersion(String, u64, u64),
    UnknownMode(String, u64),
    NotWellFormed(String),
}

pub fn read_and_assert_header_v_1_0<R>(mut raw: &mut R) -> Result<SaltpackHeader10, ParseError>
  where R: Read
{
        let nested_binary : Vec<u8> = match decode::read_value(&mut raw) {
            Ok(Value::Binary(bin)) => bin,
            Err(s) => return Err(ParseError::NotWellFormed(format!("Not a messagepack stream. {}", s))),
            _ => return Err(ParseError::NotWellFormed("No nested messagepack found.".to_string()))
        };

        let mut reader : &[u8] = nested_binary.as_slice();

        let arr : Vec<Value> = match decode::read_value(&mut reader) {
            Ok(Value::Array(arr)) => arr,
            Err(s) => return Err(ParseError::NotWellFormed(format!("Nested binary is not a messagepack stream. {}", s))),
            _ => return Err(ParseError::NotWellFormed("No nested header messagepack is not of type array.".to_string()))
        };

        if arr.len() < 2 {
            return Err(ParseError::NotWellFormed(format!("Header messagepack array to short. ({}<2)", arr.len())));
        }

        let saltpack_str = match arr.get(0).unwrap().clone() {
            Value::String(e) => e,
            _ => return Err(ParseError::NotWellFormed("First header array element is not of type string.".to_string()))
        };

        if saltpack_str != "saltpack" {
            return Err(ParseError::NotWellFormed(format!("Header magic string should be 'saltpack' but is {}", saltpack_str)));
        }

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

        if version_major != 1 || version_minor != 0 {
            return Err(ParseError::WrongSaltpackVersion(format!("Saltpack version {}.{} found. This is the decoder for Version 1.0", version_major, version_minor), version_major, version_minor));
        }

        if arr.len() < 5 {
            return Err(ParseError::NotWellFormed(format!("Header messagepack array to short. ({}<5)", arr.len())));
        }


        let mode = match arr.get(2).unwrap().clone() {
            Value::Integer(Integer::U64(i)) if i == 0 => SaltpackMessageType::ENCRYPTEDMESSAGE,
            Value::Integer(Integer::U64(i)) if i == 1 => SaltpackMessageType::SIGNEDMESSAGE,
            Value::Integer(Integer::U64(i)) if i == 2 => SaltpackMessageType::DETACHEDSIGNATURE,
            Value::Integer(Integer::U64(i)) => return Err(ParseError::UnknownMode(format!("Unknown saltpack mode. {}", i), i)),
            _ =>  return Err(ParseError::NotWellFormed(format!("Header mode field[2] is not of type integer")))
        };

        let eph_pub = match arr.get(3).unwrap().clone() {
            Value::Binary(bin) => bin,
            _ =>  return Err(ParseError::NotWellFormed(format!("Header ephemeral key field[3] is not of type binary"))),
        };

        if eph_pub.len() != 32 {
            return Err(ParseError::NotWellFormed(format!("Header ephemeral key has not length 32 but {}", eph_pub.len())));
        }

        let sender_secretbox = match arr.get(4).unwrap().clone() {
            Value::Binary(bin) => bin,
            _ =>  return Err(ParseError::NotWellFormed(format!("Header sender secretbox field[4] is not of type binary"))),
        };


        let mut result = SaltpackHeader10 {
            mode : mode,
            eph_pub : eph_pub,
            sender_secretbox : sender_secretbox,
            recipients : Vec::new(),
        };

        let has_recipients = arr.len() >= 6;

        if has_recipients {
            let recipients_arr = match arr.get(5).unwrap().clone() {
                Value::Array(arr) => arr,
                _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient field is not of type array")))
            };

            for recipient in recipients_arr.iter() {

                let recipient = match recipient.clone() {
                    Value::Array(arr) => arr,
                    _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient entry is not of type array")))
                };

                if recipient.len() < 2 {
                    return Err(ParseError::NotWellFormed(format!("Header recipient entry has less then two fields: {}", arr.len())));
                }

                let recipient_pub_key = match recipient.get(0).unwrap().clone() {
                    Value::Binary(bin) => bin,
                    _ =>  return Err(ParseError::NotWellFormed(format!("Header recipient public key is not of type binary."))),
                };

                let payloadkey_cryptobox = match recipient.get(1).unwrap().clone() {
                    Value::Binary(bin) => bin,
                    _ =>  return Err(ParseError::NotWellFormed(format!("Header payload crypto box is not of type binary."))),
                };

                let recipient = Recipient {
                    recipient_pub : recipient_pub_key,
                    payloadkey_cryptobox : payloadkey_cryptobox
                };
                result.recipients.push(recipient);
            }

        }

        Ok(result)
}

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

    #[test]
    fn it_works() {
        let raw_saltpacks = dearmor(&ARMORED_2, 1).unwrap();
        let pack1 = raw_saltpacks.get(0).unwrap();
        let mut reader : &[u8] = pack1.binary.as_slice();
        let header = read_and_assert_header_v_1_0(&mut reader).unwrap();

        assert_eq!(header.mode, SaltpackMessageType::ENCRYPTEDMESSAGE);
        assert_eq!(header.recipients.len(), 3);
    }
}
