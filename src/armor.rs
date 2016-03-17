
use regex::Regex;
use ramp::Int;
use std::cmp::min;
use std::vec::Vec;
pub use std::ops::Range;
pub use ::SaltpackMessageType;


#[derive(Debug, PartialEq)]
pub struct ArmorInfo {
    pub vendorstring: String,
    pub messagetype: SaltpackMessageType,
}

#[derive(Debug)]
pub struct Dearmored {
    pub meta: ArmorInfo,
    pub binary: Vec<u8>,
}

pub fn dearmor(text : &str, max : usize) -> Result<Vec<Dearmored>, String> {
    let stripped = strip_whitespace(&text);
    let mut stripped_view = &stripped[..];
    let mut saltpacks = Vec::<Dearmored>::with_capacity(min(3, max));
    for _ in 0..max {
        if let Some( (inners, meta, range) ) = assert_and_strip_header_and_footer(&stripped_view) {
            let rawdata = try!(convert_to_bytes(&inners));
            stripped_view = &stripped_view[range.end..];
            saltpacks.push( Dearmored {
                meta : meta,
                binary : rawdata
            } );
        } else {
            break;
        }
    }
    if saltpacks.is_empty() {
        Err("No saltpacks found".to_string())
    } else {
        Ok(saltpacks)
    }
}

pub struct ArmoringStream {
    meta: ArmorInfo,
    state : ArmoringStreamState,
    buffer : [u8 ; 43],
}

/// the associated
#[derive(Debug)]
enum ArmoringStreamState {
    AtHeader{ pos: usize, header : String},
    AtData{ space_in: usize, newline_in : usize, bufpos : usize, buflen : usize },
    AtFooter{ pos: usize, footer : String},
}

const SPACE_EVERY: usize = 15;
const NEWLINE_EVERY: usize = 200;

impl ArmoringStream {
    pub fn new(vendorstring: String,
               messagetype: SaltpackMessageType) -> ArmoringStream {
        ArmoringStream {
            state : ArmoringStreamState::AtHeader {
                pos : 0,
                header : format!("BEGIN {} SALTPACK {}. ", vendorstring, messagetype.to_string())
            },
            meta : ArmorInfo {
                vendorstring : vendorstring,
                messagetype : messagetype
            },
            buffer : [0u8 ; 43]
        }
    }

    /// Reads bytes from `binary_in` and writes the armored version into `armored_out`
    /// If binary_in contains the last bytes that have to be written, set last_bytes to
    /// true. Then the footer will be written.
    ///
    /// Returns the bytes read from `binary_in` and the bytes written to `armored_out`
    pub fn armor(&mut self, mut binary_in : &[u8], last_bytes : bool, mut armored_out : &mut[u8])
    -> Result<(usize, usize), String> {
        use std::io::Write;
        let binary_in_len = binary_in.len();
        let armored_out_len = armored_out.len();
        let mut next = false;

        if let ArmoringStreamState::AtHeader{ref mut pos, ref header} = self.state {
            *pos += armored_out.write(&header.as_bytes()[*pos..]).unwrap();
            next = *pos == header.len();
        };

        if next {
            self.state = ArmoringStreamState::AtData{space_in : SPACE_EVERY,
                                                     newline_in : NEWLINE_EVERY,
                                                     bufpos : 0,
                                                     buflen : 0};
            next = false;
        }

        if let ArmoringStreamState::AtData{ref mut space_in,
                                           ref mut newline_in,
                                           ref mut bufpos,
                                           ref mut buflen } = self.state {
            while armored_out.len() > 0 {
                if bufpos == buflen {
                    // 32 byte <> 43 characters
                    if binary_in.len() >= 32 {
                        *buflen = bin_to_base62_alphabet(&binary_in[0..32], &mut self.buffer[..]);
                        binary_in = &binary_in[32..];
                        *bufpos = 0;
                    } else if binary_in.len() > 0 && last_bytes {
                        *buflen = bin_to_base62_alphabet(&binary_in[..], &mut self.buffer[..]);
                        binary_in = &[];
                        *bufpos = 0;
                    } else if binary_in.len() == 0 && last_bytes {
                        next = true;
                        break;
                    } else {
                        break; // waiting for more input data
                    }
                }
                // self.buffer vergrößern, bin_to_base62_alphabet (oder hier)
                // direkt im callback von ramps to_base_callback die leerzeichen
                // und spaces hinyufügen


            }
        }


        if let ArmoringStreamState::AtFooter{ref mut pos, ref footer} = self.state {

        }
        Ok((binary_in_len   - binary_in.len() ,
            armored_out_len - armored_out.len()))
    }




//    #[inline]
//    fn dealphabet_chunk(&mut self, len : usize) {
//        let chunk = &self.stripped[0..len];
//        for (c, b) in chunk.iter().zip(self.buff.iter_mut()) {
//            *b = Base62Blocks::dealphabet(*c);
//        }
//    }
}

use std::fmt;
impl fmt::Debug for ArmoringStream {
    fn fmt(&self, mut f : &mut fmt::Formatter) -> Result<(), fmt::Error> {
        try!(self.meta.fmt(&mut f));
        try!(self.state.fmt(&mut f));
        try!(self.buffer[..].fmt(&mut f));
        Ok(())
    }
}


///#[inline]
pub fn alphabet(i : u8) -> u8 {
    if i <= 9 {
        i + b'0'
    } else if i <= 35 {
        i + b'A' - 10
    } else {
        i + b'a' - 36
    }
}

pub fn strip_whitespace(input : &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.chars() {
        match byte {
            'a' ... 'z' | 'A' ... 'Z' | '0' ... '9' | '.' => out.push(byte),
            _ => ()
        };
    }
    out
}

pub fn assert_and_strip_header_and_footer<'a>(input : &'a str) -> Option<(&'a str, ArmorInfo, Range<usize>)> {
    let re : Regex = regex!(r"BEGIN([a-zA-Z0-9]+)?SALTPACK(ENCRYPTEDMESSAGE|SIGNEDMESSAGE|DETACHEDSIGNATURE)\.");
    let cap = re.captures_iter(input).next();
    if cap.is_none() {
        return None;
        //return Err("No Saltpack Message".to_string());
    }
    let header_match = cap.unwrap();
    let vendor = header_match.at(1).unwrap_or("");
    let typ = header_match.at(2).unwrap_or("");
    let mut footer = String::with_capacity(header_match.len());
    footer.push_str(".END");
    footer.push_str(vendor);
    footer.push_str("SALTPACK");
    footer.push_str(typ);
    footer.push_str(".");

    let typ = match typ {
        "ENCRYPTEDMESSAGE" => SaltpackMessageType::ENCRYPTEDMESSAGE,
        "SIGNEDMESSAGE" => SaltpackMessageType::SIGNEDMESSAGE,
        "DETACHEDSIGNATURE" => SaltpackMessageType::DETACHEDSIGNATURE,
        _ => panic!("typ not covered")
    };
    let header_start = header_match.pos(0).unwrap().0;
    let header_end = header_match.pos(0).unwrap().1;
    println!("FOOTER: {:?}", footer);

    for footer_start in header_end .. input.len()-footer.len()+1 {
        let footer_end = footer_start + footer.len();

        if input[footer_start..footer_end] == footer {
            let headerinfo = ArmorInfo {
                vendorstring : vendor.to_string(),
                messagetype : typ,
            };
            let range = Range {
                start : header_start,
                end : footer_end
            };
            return Some( (&input[header_end..footer_start], headerinfo, range) );
        }
    }
    None
    //Err("No corresponding footer found.".to_string())
}

pub fn convert_to_bytes<'a>(stripped_input : & str) -> Result<Vec<u8>, String> {
    let mut raw_output = vec![0u8; stripped_input.len() * 3 / 4 + 32 + 1];
    let mut raw_output_pointer = 0;
    {
        let mut block_it = stripped_input.as_len43_based_blocks();
        while let Some(base62block) = block_it.next_() {
            raw_output_pointer += base62_to_bin(base62block, &mut raw_output[raw_output_pointer..raw_output_pointer+32]);
        }
    }
    raw_output.resize(raw_output_pointer, 0);
    return Ok(raw_output);
}

pub struct Base62Blocks<'a> {
    stripped : &'a[u8],
    buff : [u8 ; 43],
}

trait To62BaseBlocks<'a> {
    fn as_len43_based_blocks(&self) -> Base62Blocks;
}

impl<'a> To62BaseBlocks<'a> for &'a str {
    fn as_len43_based_blocks(&self) -> Base62Blocks {
        Base62Blocks {
            stripped : &self.as_bytes(),
            buff : [0;43]
        }
    }
}

impl<'a> Base62Blocks<'a> {
    // iterator inferface will not comply with lifetimes
    fn next_<'b>(&'b mut self) -> Option<&'b [u8]> {
        let remaining = min(self.stripped.len(), 43);
        if remaining == 0 {
            return None
        }
        self.dealphabet_chunk(remaining);
        self.stripped = &self.stripped[remaining..];
        Some(&self.buff[0..remaining])
    }

    ///#[inline]
    pub fn dealphabet(i : u8) -> u8 {
        if i <= b'9' {
            i - b'0'
        } else if i <= b'Z' {
            i - b'A' + 10
        } else {
            i - b'a' + 36
        }
    }

    #[inline]
    fn dealphabet_chunk(&mut self, len : usize) {
        let chunk = &self.stripped[0..len];
        for (c, b) in chunk.iter().zip(self.buff.iter_mut()) {
            *b = Base62Blocks::dealphabet(*c);
        }
    }

}

pub fn base62_to_bin(base62 : &[u8], rawout : &mut[u8]) -> usize {
    let i = unsafe {
        Int::from_u8_be_radix_unchecked(base62, 62).unwrap()
    };
    i.write_big_endian_buffer(rawout).unwrap()
}

/// returns the number of bytes written into base62out
pub fn bin_to_base62_alphabet(rawin : &[u8], mut base62out : &mut[u8]) -> usize {
    assert!(rawin.len() <= 32);
    assert!(base62out.len() >= 43);
    let i = Int::from_big_endian_slice(rawin);
    let written = 0;
    i.write_radix_callback(62, |b| {
        unsafe {
            *base62out.get_unchecked_mut(written) = alphabet(b);
        }
    });
    written
}


#[cfg(test)]
mod tests {
    use super::*;

    static ARMORED_1 : &'static str = "BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G7KB2OUX3itkn C30ZZBPzjc8STxf i06TIQhJ4wRFSMU hFa9gmcvl2AW8Kk qmTdLkkppPieOWq o9aWouAaMpQ9kWt eMlv17NOUUr9Gp3 fClo7khRnJ12T7j 6ZVkfDXUpznTp57 0btBywDV848jyp2 EceloYGiuOolWim 8HCx77p22iulWja ixShPFcOi1mkG2i 4Iur3QfGYeKpflx a1GXmvQLi1G99mH 625dH5HGcQ63pOb K1i7g3lXIQ9Kcfy NRDfdBIDMHJaJf1 uTKB4GJ9l4M7glS 07h9QsU4gPueyNC hzm6LmA9CFllzxy 8ZA0Ys5qDnSuwaN obowMNXpbm1nlsx fXFtMolx6ghLuEw 2s8f1jBxBQjQPwa GG90h5BbpoWGPk6 dRsou5kdNxcLaFJ KKXWTUR2h9P0P7p 9UYRsQ6QqGNiwmG wXC7YFh1xCUdAib gjZbUYUKN6KVLem hZI6XYtX2l1w8d5 jL8KJ5ZZpKhJ4JC faVWCU2VRtUFgQO ejKm6wjs6NcekTd KK4bOh5kr87cyRu 0aDjEtfMSyZZTG5 hIrEWcMq1Iotzrx iRdmY5GYf2Kx0Br 4K0rqrj8ZGa. END SALTPACK SIGNED MESSAGE.";

    static STRIPPED_1 : &'static str = "BEGINSALTPACKSIGNEDMESSAGE.kYM5h1pg6qz9UMnj6G7KB2OUX3itknC30ZZBPzjc8STxfi06TIQhJ4wRFSMUhFa9gmcvl2AW8KkqmTdLkkppPieOWqo9aWouAaMpQ9kWteMlv17NOUUr9Gp3fClo7khRnJ12T7j6ZVkfDXUpznTp570btBywDV848jyp2EceloYGiuOolWim8HCx77p22iulWjaixShPFcOi1mkG2i4Iur3QfGYeKpflxa1GXmvQLi1G99mH625dH5HGcQ63pObK1i7g3lXIQ9KcfyNRDfdBIDMHJaJf1uTKB4GJ9l4M7glS07h9QsU4gPueyNChzm6LmA9CFllzxy8ZA0Ys5qDnSuwaNobowMNXpbm1nlsxfXFtMolx6ghLuEw2s8f1jBxBQjQPwaGG90h5BbpoWGPk6dRsou5kdNxcLaFJKKXWTUR2h9P0P7p9UYRsQ6QqGNiwmGwXC7YFh1xCUdAibgjZbUYUKN6KVLemhZI6XYtX2l1w8d5jL8KJ5ZZpKhJ4JCfaVWCU2VRtUFgQOejKm6wjs6NcekTdKK4bOh5kr87cyRu0aDjEtfMSyZZTG5hIrEWcMq1IotzrxiRdmY5GYf2Kx0Br4K0rqrj8ZGa.ENDSALTPACKSIGNEDMESSAGE.";

    static ALPHABET : &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    #[test]
    fn find_header() {
        let stripped = strip_whitespace(&ARMORED_1);
        assert_eq!(stripped, STRIPPED_1);
        let (inners, meta, range) = assert_and_strip_header_and_footer(&stripped).unwrap();
        assert_eq!(meta.messagetype, SaltpackMessageType::SIGNEDMESSAGE);
        assert_eq!(range, Range {start : 0, end : 664});
        assert_eq!(*inners, STRIPPED_1[27..638]);
        let rawdata = convert_to_bytes(&inners).unwrap();
        assert_eq!(rawdata.len(), 454);
    }

    #[test]
    fn alphabet_() {
        for (i, c) in (ALPHABET).as_bytes().iter().enumerate() {
            assert_eq!(Base62Blocks::dealphabet(*c) as usize, i);
            assert_eq!(alphabet(i as u8), *c);
        }
    }

}
