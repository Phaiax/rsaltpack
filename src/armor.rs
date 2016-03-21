
use regex::Regex;
use ramp::Int;
use std::cmp::min;
use std::vec::Vec;
use std::io::{Read, Write};
pub use std::ops::Range;
pub use ::SaltpackMessageType;
use util::Consumable;

/// This function is a short interface to ArmoringStream.
/// It will convert binary input into the base62 armored version including
/// header and footer.
pub fn armor(binary_in : &mut [u8],
             vendorstring: &str,
             messagetype: SaltpackMessageType)
             -> String {
    let mut AS = ArmoringStream::new(vendorstring.to_string(), messagetype);
    let mut out = vec![0u8; AS.predict_armored_len(binary_in.len())];
    let (_, written, ready) = AS.armor(&binary_in[..], true, &mut out[..]).unwrap();
    out.resize(written, 0);
    assert!(ready);
    unsafe { String::from_utf8_unchecked(out) }
}

/// Can be used as a streaming interface to armor large amounts of binary data.
/// But it is not recommended to use the armored version to send big amounts of
/// data. It is slow and inefficient.
pub struct ArmoringStream {
    state : ArmoringStreamState,
    buffer : [u8 ; BUF_SIZE],
    header : String,
    footer : String
}

/// State of the armor conversion method.
#[derive(Debug, PartialEq)]
enum ArmoringStreamState {
    AtHeader{ pos: usize},
    AtData{ space_in: usize, newline_in : usize, bufpos : usize, buflen : usize },
    AtFooter{ pos: usize},
    Finished,
}

/// One block of 32 byte will be converted into 43 characters, if it is not the last block.
const CHARS_PER_BLOCK: usize = 43;
/// The armored string will contain a space every 15 characters.
pub const SPACE_EVERY: usize = 15;
/// The armored string will contain a newline instead of a space every 200 words.
pub const NEWLINE_EVERY: usize = 200;
/// Storage needed to store the armored 43 characters with inserted spaces.
const BUF_SIZE : usize = CHARS_PER_BLOCK + CHARS_PER_BLOCK / SPACE_EVERY + 1;


impl ArmoringStream {

    /// Create a new streaming interface
    pub fn new(vendorstring: String,
               messagetype: SaltpackMessageType)
               -> ArmoringStream {
        ArmoringStream {
            state : ArmoringStreamState::AtHeader {pos : 0},
            buffer : [0u8 ; BUF_SIZE],
            header : format!("BEGIN {} SALTPACK {}. ", vendorstring, messagetype.to_string()),
            footer : format!(". END {} SALTPACK {}.", vendorstring, messagetype.to_string()),
        }
    }

    /// Predicts the total length of armored data including header and footer.
    /// Since the armored version is guaranteed to contain only ascii characters,
    /// the (armored output as [u8]).len() equals its utf-8 size.
    pub fn predict_armored_len(&self, binary_data_len : usize) -> usize {
        // 74.42 is the slightly down rounded efficiency (log2(62)/8)
        let without_spaces : f64 = (binary_data_len as f64) / 0.7442f64;
        let with_spaces : f64 = without_spaces + (without_spaces / SPACE_EVERY as f64);
        self.header.len() + self.footer.len() + (with_spaces as usize)
    }

    /// Reads bytes from `binary_in` and writes the armored version into `armored_out`
    /// If binary_in contains the last bytes that have to be written, set last_bytes to
    /// true. Then the footer will be written.
    ///
    /// Returns the bytes read from `binary_in`, the bytes written to `armored_out`
    /// and if the footer has been written completely.
    pub fn armor(&mut self,
                 mut binary_in : &[u8],
                 last_bytes : bool,
                 mut armored_out : &mut[u8])
                 -> Result<(usize, usize, bool), String> {

        let binary_in_len = binary_in.len();
        let armored_out_len = armored_out.len();
        let mut next = false;
        let mut ready = false;

        // Write as much header as possible.
        if let ArmoringStreamState::AtHeader{ref mut pos} = self.state {
            *pos += armored_out.write(&self.header.as_bytes()[*pos..]).unwrap();
            next = *pos == self.header.len()
        };

        // Switch to state `AtData` if header is written.
        if next {
            self.state = ArmoringStreamState::AtData{space_in : SPACE_EVERY,
                                                     newline_in : NEWLINE_EVERY,
                                                     bufpos : 0,
                                                     buflen : 0};
            next = false;
        }

        // Write as much armored data as possible.
        if let ArmoringStreamState::AtData{ref mut space_in,
                                           ref mut newline_in,
                                           ref mut bufpos,
                                           ref mut buflen } = self.state {
            while armored_out.len() > 0 { // has place to write
                if bufpos == buflen { // self.buffer got empty

                    // 32 byte <> 43 characters
                    if binary_in.len() >= 32 && armored_out.len() >= BUF_SIZE {
                        // shortcut: direct write to armored_out
                        let written = b32bytes_to_base62_formatted(&binary_in[0..32],
                                                         &mut armored_out,
                                                         &mut *space_in,
                                                         &mut *newline_in,
                                                         true);
                        armored_out.consume(written);
                        binary_in = &binary_in[32..];
                        continue; // bufpos is still buflen
                    } else if binary_in.len() >= 32 {
                        // the complete 43+x char block doesn't fit into armored_out
                        // first base62-convert next 32 input bytes into self.buffer ...
                        *buflen = b32bytes_to_base62_formatted(&binary_in[0..32],
                                                         &mut self.buffer[..],
                                                         &mut *space_in,
                                                         &mut *newline_in,
                                                         true);
                        binary_in = &binary_in[32..];
                        *bufpos = 0;
                    } else if binary_in.len() > 0 && last_bytes { // last non full block
                        *buflen = b32bytes_to_base62_formatted(&binary_in[..],
                                                         &mut self.buffer[..],
                                                         &mut *space_in,
                                                         &mut *newline_in,
                                                         false);
                        binary_in = &[]; // finish
                        *bufpos = 0;
                    } else if binary_in.len() == 0 && last_bytes {
                        next = true;
                        break;
                    } else {
                        break; // waiting for more input data
                    }
                }

                assert!(bufpos < buflen);
                // ... then write all that fits into armored_out
                *bufpos += armored_out.write(&self.buffer[*bufpos..]).unwrap();

            }
        }

        // Switch to state `AtFooter` if main data is written.
        if next {
            self.state = ArmoringStreamState::AtFooter{
                pos : 0
            };
            next = false;
        }

        // Write as much footer data as possible.
        if let ArmoringStreamState::AtFooter{ref mut pos} = self.state {
            *pos += armored_out.write(&self.footer.as_bytes()[*pos..]).unwrap();
            next = *pos == self.footer.len();
        }

        // Switch to state `Finished` if footer is written.
        if next {
            self.state = ArmoringStreamState::Finished;
        }

        if ArmoringStreamState::Finished == self.state {
            ready = true;
        }

        Ok((binary_in_len   - binary_in.len() ,
            armored_out_len - armored_out.len(),
            ready))
    }

}

use std::fmt;
impl fmt::Debug for ArmoringStream {
    fn fmt(&self, mut f : &mut fmt::Formatter) -> Result<(), fmt::Error> {
        try!(self.state.fmt(&mut f));
        try!(self.buffer[..].fmt(&mut f));
        Ok(())
    }
}


/// This function converts a zero based digit in base 62 to its ascii equivalent.
#[inline]
pub fn alphabet(i : u8) -> u8 {
    if i <= 9 {
        i + b'0'
    } else if i <= 35 {
        i + b'A' - 10
    } else {
        i + b'a' - 36
    }
}

/// This function armors one 32 byte block into 43 base62 characters.
///
/// It inserts spaces and newlines, as soon as the counters `space_in` and
/// `newline_in` reach zero. It is intended that consecutive calls always
/// get references to the same counters, so the inserted spaces are all
/// equidistant.
///
/// If `full_32` is true, it will always output 43 characters right aligned,
/// even if the 32 byte input can be represented with 42 characters.
///
/// Returns the number of bytes, that have been written into base62out.
///
/// Base62out must have place for `BUF_SIZE` characters, otherwise it will panic.
pub fn b32bytes_to_base62_formatted(raw_in : &[u8],
                               mut base62out : &mut [u8],
                               space_in : &mut usize,
                               newline_in : &mut usize,
                               full_32 : bool) -> usize {
    assert!(raw_in.len() <= 32);
    assert!(base62out.len() >= BUF_SIZE);
    assert!(*space_in > 0);
    assert!(*newline_in > 0);
    let i = Int::from_big_endian_slice(raw_in);
    let mut written = 0;
    let min_len = if full_32 { 43 } else { 0 };
    i.write_radix_callback_minlen(62, min_len, |b| {
        unsafe {
            //base62out.write(alphabet(b)).unwrap();
            *base62out.get_unchecked_mut(written) = alphabet(b);
            written += 1;
            *space_in -= 1;
            if *space_in == 0 {
                *space_in = SPACE_EVERY;
                *newline_in -= 1;
                if *newline_in == 0 {
                    *newline_in = NEWLINE_EVERY;
                    //base62out.write(alphabet(b'\n')).unwrap();
                    *base62out.get_unchecked_mut(written) = b'\n';
                    written += 1;
                } else {
                    //base62out.write(alphabet(b' ')).unwrap();
                    *base62out.get_unchecked_mut(written) = b' ';
                    written += 1;
                }
            }
        }
    });
    assert!(BUF_SIZE >= written);
    written
}



#[cfg(test)]
mod tests {
    use super::*;

    static ALPHABET : &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


    #[test]
    fn alphabet_() {
        for (i, c) in (ALPHABET).as_bytes().iter().enumerate() {
            assert_eq!(alphabet(i as u8), *c);
        }
    }

    #[test]
    fn to_base62_with_spaces() {
        let mut space_in = 3;
        let mut newline_in = 3;
        let data : [u8 ; 32] = [ 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8, ];
        let mut out = vec![b'A' ; 150];
        {
            let mut out_slice = &mut out[..];
            let written = b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in, true);
            let mut out_slice = &mut out_slice[written..];
            let written = b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in, true);
            let mut out_slice = &mut out_slice[written..];
            let written = b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in, true);
            let mut out_slice = &mut out_slice[written..];
        }
        unsafe {
            let S = String::from_utf8_unchecked(out);
            assert!(S == "0Eo h211G4c8rWQ68g6 VHwCdRQSckQE9h6\nk6REalLOem0Eoh2 11G4c8rWQ68g6VH wCdRQSckQE9h6k6 REalLOem0Eoh211 G4c8rWQ68g6VHwC dRQSckQE9h6k6RE alLOemAAAAAAAAAAAA");
        }
    }

    #[test]
    fn armoring_stream() {
        let data : [u8 ; 32] = [ 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8, ];
        let mut AS = ArmoringStream::new("RUST".to_string(), SaltpackMessageType::ENCRYPTEDMESSAGE);
        let len = AS.predict_armored_len(data.len());
        let mut out = vec![0u8; len];
        let (read, written, ready) = AS.armor(&data[..], true, &mut out[..]).unwrap();
        out.resize(written, 0);
        let S = unsafe { String::from_utf8_unchecked(out) };
        assert!(ready);
        assert_eq!(read, data.len());
        assert_eq!(written, len);
        assert_eq!(S, "BEGIN RUST SALTPACK ENCRYPTEDMESSAGE. 0Eoh211G4c8rWQ6 8g6VHwCdRQSckQE 9h6k6REalLOem. END RUST SALTPACK ENCRYPTEDMESSAGE.");
    }

}
