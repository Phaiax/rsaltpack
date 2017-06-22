//! Removing base62 armor and returning binary data
//!
//! Function `dearmor(text, max)` searches for all saltpacks within `text`
//! and returns a `Dearmored` for each of them.
//!
//! Not that the returned data is still encrypted.
//!
//! ```
//! use rsaltpack::dearmor::{dearmor, Stripped, Dearmored};
//! use rsaltpack::SaltpackMessageType;
//! use std::ops::Range;
//!
//! let encoded = "Hey Friend. BEGIN RUST SALTPACK ENCRYPTEDMESSAGE. 0Eoh211G4c8rWQ6 8g6VHwCdRQSckQE 9h6k6REalLOem. END RUST SALTPACK ENCRYPTEDMESSAGE.";
//!
//! let saltpacks = dearmor(Stripped::from_utf8(encoded), 1).unwrap();
//! let decoded : &Dearmored = saltpacks.first().unwrap();
//!
//! assert_eq!(&decoded.meta.vendor, "RUST");
//! assert_eq!(decoded.meta.messagetype, SaltpackMessageType::ENCRYPTEDMESSAGE);
//! assert_eq!(&decoded.raw_bytes[3], &4);
//! assert_eq!(decoded.raw_bytes.len(), 32);
//!
//! assert_eq!(decoded.calc_range_within_original_utf8_input(encoded),
//!            Range { start: 12, end: 132 });
//! ```


use regex::bytes::Regex;
// use ramp::Int;
use std::cmp::min;
use std::vec::Vec;
use std::io::Write;
use std::ops::Range;
use ::SaltpackMessageType;
use util::Consumable;
use util::TryInto;
use base62::decode_base62;
use errors::*;

/// Removes all chars that can not occur within saltpacks.
/// (keeps [A-Za-z0-9.])
pub struct Stripped(Vec<u8>);

impl Stripped {

    pub fn from_utf8(input : &str) -> Stripped {
        let mut out = Vec::with_capacity(input.len());
        for c in input.chars().filter(Stripped::is_armor_char) {
            out.push(c as u8);
        }
        Stripped(out)
    }

    pub fn from_ascii(input : &[u8]) -> Stripped {
        let mut out = Vec::with_capacity(input.len());
        for c in input.iter().filter(Stripped::is_armor_ascii_char) {
            out.push(*c);
        }
        Stripped(out)
    }

    #[inline]
    fn is_armor_char(c : &char) -> bool {
        match *c {
            'a' ... 'z' | 'A' ... 'Z' | '0' ... '9' | '.'  => true,
            _ => false
        }
    }

    #[inline]
    fn is_armor_ascii_char(c : &&u8) -> bool {
        match **c {
            b'a' ... b'z' | b'A' ... b'Z' | b'0' ... b'9' | b'.'  => true,
            _ => false
        }
    }
}



#[derive(Debug, PartialEq)]
/// Metadata: Type of encryption and vendor name (brand).
pub struct ArmorInfo {
    pub vendor: String,
    pub messagetype: SaltpackMessageType,
}

#[derive(Debug)]
/// The decoded data and some metadata (`ArmorInfo`)
///
/// Use the method `calc_range_within_original_ascii_input()` or
/// `calc_range_within_original_utf8_input()` to find out where the
/// saltpack was located within the original string. This may be useful
/// for replacing Saltpacks within a displayed email.
pub struct Dearmored {
    pub meta: ArmorInfo,
    pub raw_bytes: Vec<u8>,
    range_within_stripped: Range<usize>,
}

/// Search for all saltpacks within `text` and return a [`Dearmored`] for each of them.
/// Returns no more than `max` dearmored saltpacks.
///
/// [`Dearmored`]: struct.Dearmored.html
pub fn dearmor(text : Stripped, max : usize) -> Result<Vec<Dearmored>> {
    let mut saltpacks = Vec::<Dearmored>::with_capacity(min(3, max));

    let mut text : Vec<u8> = text.0; // mut for inplace editing in decode_base62
    let mut text = &mut text[..]; // views allow shrinking
    let mut consumed_bytes = 0;

    for _ in 0..max {
        let end;
        if let Some( (mut encoded_data, meta, mut range) ) = find_first_saltpack(&mut text) {
            end = range.end;
            range.start += consumed_bytes;
            range.end += consumed_bytes;
            saltpacks.push( Dearmored {
                meta : meta,
                raw_bytes : decode_base62(&mut encoded_data)?,
                range_within_stripped : range.clone(),
            } );
        } else {
            break; // no saltpack found
        }
        text.consume(end);
        consumed_bytes += end;
    }

    Ok(saltpacks)
}

impl Dearmored {
    /// Calculates where in the original input this saltpack was located.
    /// Use the same text as input that was used for `Stripped::from_ascii()`
    pub fn calc_range_within_original_ascii_input(&self, unstripped_input : &[u8]) -> Range<usize> {
        let mut stripped_chars_until_start = self.range_within_stripped.start + 1;
        let mut start_saltpack = 0;
        for (i, c) in unstripped_input.iter().enumerate() {
            if Stripped::is_armor_ascii_char(&c) {
                stripped_chars_until_start -= 1;
                if stripped_chars_until_start == 0 {
                    start_saltpack = i;
                    break;
                }
            }
        }

        let mut end_saltpack = start_saltpack;
        let mut stripped_chars_until_end =
            self.range_within_stripped.end - self.range_within_stripped.start;
        for (i, c) in (&unstripped_input[start_saltpack..]).iter().enumerate() {
            if Stripped::is_armor_ascii_char(&c) {
                stripped_chars_until_end -= 1;
                if stripped_chars_until_end == 0 {
                    end_saltpack = i + start_saltpack + 1;
                    break;
                }
            }
        }
        Range {
            start: start_saltpack,
            end: end_saltpack,
        }
    }

    /// Calculates where in the original input this saltpack was located.
    /// Use the same text as input that was used for `Stripped::from_utf8()`
    pub fn calc_range_within_original_utf8_input(&self, unstripped_input : &str) -> Range<usize> {
        let mut stripped_chars_until_start = self.range_within_stripped.start + 1;
        let mut start_saltpack= 0;
        for (i, c) in unstripped_input.chars().enumerate() {
            if Stripped::is_armor_char(&c) {
                stripped_chars_until_start -= 1;
                if stripped_chars_until_start == 0 {
                    start_saltpack = i;
                    break;
                }
            }
        }

        let mut end_saltpack = start_saltpack;
        let mut stripped_chars_until_end =
            self.range_within_stripped.end - self.range_within_stripped.start;
        for (i, c) in (&unstripped_input[start_saltpack..]).chars().enumerate() {
            if Stripped::is_armor_char(&c) {
                stripped_chars_until_end -= 1;
                if stripped_chars_until_end == 0 {
                    end_saltpack = i + start_saltpack + 1;
                    break;
                }
            }
        }
        Range {
            start: start_saltpack,
            end: end_saltpack,
        }
    }
}

/// This function first finds the start marker of first saltpack.
/// Then it searches for corresponding end marker. The `input` string must have
/// been stripped. (it then only contains [A-Za-z0-9.], no more unicode)
///
/// It returns a view into the inner encoded data of the first saltpack block.
/// Also returns the information contained in the markers: vendor and messagetype
/// Third return parameter is the position of the saltpack within `input`, including markers.
fn find_first_saltpack(input : &mut [u8]) -> Option<(&mut [u8], ArmorInfo, Range<usize>)> {

    // find first begin marker
    let re : Regex = Regex::new(r"BEGIN([a-zA-Z0-9]+)?SALTPACK(ENCRYPTEDMESSAGE|SIGNEDMESSAGE|DETACHEDSIGNATURE)\.").unwrap();

    let (meta, header_pos) = {
        let cap = re.captures_iter(input).next();

        // nothing found?
        if cap.is_none() {
            return None;
        }

        // Range of BEGINxSALTPACKx.
        let header_match = cap.unwrap();
        let header_pos = Range {
            start: header_match.get(0).unwrap().start(),
            end : header_match.get(0).unwrap().end(),
        };

        // extract vendor and type
        let vendor = header_match.get(1).map(|m| m.as_bytes()).unwrap_or(&[]);
        let typ = header_match.get(2).map(|m| m.as_bytes()).unwrap_or(&[]);

        (
            ArmorInfo {
                vendor : String::from_utf8_lossy(vendor).into_owned(),
                messagetype : typ.try_into().unwrap(), // no panic as long as Regex is up to date
            },
            header_pos
        )
    };

    // assemble end marker (for later comparision)
    let footer = &make_condensed_footer(meta.vendor.as_bytes(), meta.messagetype)[..];
    let footer_len = footer.len();

    // Search one by one for occurrence of `footer`
    for footer_start in header_pos.end .. input.len()-footer_len+1 {

        if &input[footer_start..footer_start+footer_len] == footer {

            // found
            return Some( (  &mut input[header_pos.end..footer_start],
                            meta,
                            Range {
                                start : header_pos.start,
                                end : footer_start + footer_len,
                            }
                          ) );
        }
    }
    None
}

fn make_condensed_footer(vendor : &[u8], typ : SaltpackMessageType) -> Vec<u8> {
    let mut footer = Vec::with_capacity(17 + vendor.len() + 17);
    footer.write_all(b".END").unwrap();
    footer.write_all(vendor).unwrap();
    footer.write_all(b"SALTPACK").unwrap();
    footer.write_all(typ.to_condensed_str().as_bytes()).unwrap();
    footer.write_all(b".").unwrap();
    footer
}




#[cfg(test)]
mod tests {
    pub static ARMORED_1 : &'static str = "BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G7KB2OUX3itkn C30ZZBPzjc8STxf i06TIQhJ4wRFSMU hFa9gmcvl2AW8Kk qmTdLkkppPieOWq o9aWouAaMpQ9kWt eMlv17NOUUr9Gp3 fClo7khRnJ12T7j 6ZVkfDXUpznTp57 0btBywDV848jyp2 EceloYGiuOolWim 8HCx77p22iulWja ixShPFcOi1mkG2i 4Iur3QfGYeKpflx a1GXmvQLi1G99mH 625dH5HGcQ63pOb K1i7g3lXIQ9Kcfy NRDfdBIDMHJaJf1 uTKB4GJ9l4M7glS 07h9QsU4gPueyNC hzm6LmA9CFllzxy 8ZA0Ys5qDnSuwaN obowMNXpbm1nlsx fXFtMolx6ghLuEw 2s8f1jBxBQjQPwa GG90h5BbpoWGPk6 dRsou5kdNxcLaFJ KKXWTUR2h9P0P7p 9UYRsQ6QqGNiwmG wXC7YFh1xCUdAib gjZbUYUKN6KVLem hZI6XYtX2l1w8d5 jL8KJ5ZZpKhJ4JC faVWCU2VRtUFgQO ejKm6wjs6NcekTd KK4bOh5kr87cyRu 0aDjEtfMSyZZTG5 hIrEWcMq1Iotzrx iRdmY5GYf2Kx0Br 4K0rqrj8ZGa. END SALTPACK SIGNED MESSAGE.";

    pub static STRIPPED_1 : &'static [u8] = b"BEGINSALTPACKSIGNEDMESSAGE.kYM5h1pg6qz9UMnj6G7KB2OUX3itknC30ZZBPzjc8STxfi06TIQhJ4wRFSMUhFa9gmcvl2AW8KkqmTdLkkppPieOWqo9aWouAaMpQ9kWteMlv17NOUUr9Gp3fClo7khRnJ12T7j6ZVkfDXUpznTp570btBywDV848jyp2EceloYGiuOolWim8HCx77p22iulWjaixShPFcOi1mkG2i4Iur3QfGYeKpflxa1GXmvQLi1G99mH625dH5HGcQ63pObK1i7g3lXIQ9KcfyNRDfdBIDMHJaJf1uTKB4GJ9l4M7glS07h9QsU4gPueyNChzm6LmA9CFllzxy8ZA0Ys5qDnSuwaNobowMNXpbm1nlsxfXFtMolx6ghLuEw2s8f1jBxBQjQPwaGG90h5BbpoWGPk6dRsou5kdNxcLaFJKKXWTUR2h9P0P7p9UYRsQ6QqGNiwmGwXC7YFh1xCUdAibgjZbUYUKN6KVLemhZI6XYtX2l1w8d5jL8KJ5ZZpKhJ4JCfaVWCU2VRtUFgQOejKm6wjs6NcekTdKK4bOh5kr87cyRu0aDjEtfMSyZZTG5hIrEWcMq1IotzrxiRdmY5GYf2Kx0Br4K0rqrj8ZGa.ENDSALTPACKSIGNEDMESSAGE.";

    pub static ARMORED_2 : &'static str = "Holla die Waldfee! !@% >BE>GIN SAL>TPACK SIGNED> MESSAGE. >kYM5h1pg6qz9UMn j6G7KB2OUX3itkn C30ZZBPzjc8STxf> i06TIQhJ4wRFSMU hFa9gmcvl2AW8Kk    qmTdLkkppPi
                eOWq o9aWouAaMpQ9k
    Wt eMlv17NOUUr9Gp3 fClo7khRnJ12T7j 6ZVkfDXUpznTp57 0btBywDV848jyp2 EceloYGiuOolWim 8HCx77p22iulWja ixShPFcOi1mkG2i 4Iur3QfGYeKpflx a1GXmvQLi1G99mH 625dH5HGcQ63pOb K1i7g3lXIQ9Kcfy NRDfdBIDMHJaJf1 uTKB4GJ9l4M7glS 07h9QsU4gPueyNC hzm6LmA9CFllzxy 8ZA0Ys5qDnSuwaN obowMNXpbm1nlsx fXFtMolx6ghLuEw 2s8f1jBxBQjQPwa GG90h5BbpoWGPk6 dRsou5kdNxcLaFJ KKXWTUR2h9P0P7p 9UYRsQ6QqGNiwmG wXC7YFh1>>>>>xCUdAib gjZbUYUKN6KVLem hZI6XYtX2l1w8d5 jL8KJ5ZZpKhJ4JC faVWCU2VRtUFgQO ejKm6wjs6NcekTd KK4bOh5kr87cyRu 0aDjEtfMSyZZTG5 hIrEWcMq1Iotzrx iRdmY5GYf2Kx0Br 4K0rqrj8ZGa. END SALTPACK SIGNED MESSAGE.  2325235 235 2 352 5 235 2BE>GIN SAL>TPACK FAKED> MESSAGE.35 Holla die Waldfee! !@% >BE>GIN SAL>TPACK SIGNED> MESSAGE. >kYM5h1pg6qz9UMn j6G7KB2OUX3itkn C30ZZBPzjc8STxf> i06TIQhJ4wRFSMU hFa9gmcvl2AW8Kk    qmTdLkkppPi
                eOWq o9aWouAaMpQ9k
    Wt eMlv17NOUUr9Gp3 fClo7khRnJ12T7j 6ZVkfDXUpznTp57 0btBywDV848jyp2 EceloYGiuOolWim 8HCx77p22iulWja ixShPFcOi1mkG2i 4Iur3QfGYeKpflx a1GXmvQLi1G99mH 625dH5HGcQ63pOb K1i7g3lXIQ9Kcfy NRDfdBIDMHJaJf1 uTKB4GJ9l4M7glS 07h9QsU4gPueyNC hzm6LmA9CFllzxy 8ZA0Ys5qDnSuwaN obowMNXpbm1nlsx fXFtMolx6ghLuEw 2s8f1jBxBQjQPwa GG90h5BbpoWGPk6 dRsou5kdNxcLaFJ KKXWTUR2h9P0P7p 9UYRsQ6QqGNiwmG wXC7YFh1xCUdAib gjZbUYUKN6KVLem hZI6XYtX2l1w8d5 jL8KJ5ZZpKhJ4JC faVWCU2VRtUFgQO ejKm6wjs6NcekTd KK4bOh5kr87cyRu 0aDjEtfMSyZZTG5 hIrEWcMq1Iotzrx iRdmY5GYf2Kx0Br 4K0rqrj8ZGa. END SALTPACK SIGNED MESSAGE.!!";


}

#[test]
fn find_header() {
    let mut stripped = Stripped::from_utf8(&tests::ARMORED_1);
    assert_eq!(stripped.0, tests::STRIPPED_1);
    let (inners, meta, range) = find_first_saltpack(&mut stripped.0[..]).unwrap();
    assert_eq!(meta.messagetype, SaltpackMessageType::SIGNEDMESSAGE);
    assert_eq!(range, Range {start : 0, end : 664});
    assert_eq!(*inners, tests::STRIPPED_1[27..638]);
    let rawdata = decode_base62(&mut inners[..]).unwrap();
    assert_eq!(rawdata.len(), 454);
}

#[test]
fn range_simple() {
    let saltpacks = dearmor(Stripped::from_utf8(&tests::ARMORED_1), 1).unwrap();
    let decoded1 = saltpacks.first().unwrap();
    let range1 = decoded1.calc_range_within_original_utf8_input(&tests::ARMORED_1);
    println!("{}", &tests::ARMORED_1[range1.clone()]);
    assert_eq!(range1.start, 0);
    assert_eq!(range1.end, 712);
}

#[test]
fn range_complex_utf8() {
    let saltpacks = dearmor(Stripped::from_utf8(&tests::ARMORED_2), 2).unwrap();
    assert_eq!(saltpacks.len(), 2);
    let decoded1 = saltpacks.first().unwrap();
    let range1 = decoded1.calc_range_within_original_utf8_input(&tests::ARMORED_2);
    let decoded2 = saltpacks.get(1).unwrap();
    let range2 = decoded2.calc_range_within_original_utf8_input(&tests::ARMORED_2);
    assert_eq!(range1.start, 24);
    assert_eq!(range1.end, 771);
    assert_eq!(range2.start, 857);
    assert_eq!(range2.end, 1599);
}

#[test]
fn range_complex_ascii() {
    let saltpacks = dearmor(Stripped::from_ascii(&tests::ARMORED_2.as_bytes()), 2).unwrap();
    assert_eq!(saltpacks.len(), 2);
    let decoded1 = saltpacks.first().unwrap();
    let range1 = decoded1.calc_range_within_original_ascii_input(&tests::ARMORED_2.as_bytes());
    let decoded2 = saltpacks.get(1).unwrap();
    let range2 = decoded2.calc_range_within_original_ascii_input(&tests::ARMORED_2.as_bytes());
    assert_eq!(range1.start, 24);
    assert_eq!(range1.end, 771);
    assert_eq!(range2.start, 857);
    assert_eq!(range2.end, 1599);
}
