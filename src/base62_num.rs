
use num_bigint::BigUint;

use std::iter::repeat;

use armor::{SPACE_EVERY, NEWLINE_EVERY, BUF_SIZE, CHARS_PER_BLOCK, BYTES_PER_BLOCK};

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

#[inline]
fn dealphabet(i : u8) -> u8 {
    if i <= b'9' {
        i - b'0'
    } else if i <= b'Z' {
        i - b'A' + 10
    } else {
        i - b'a' + 36
    }
}

/// How many chars will be used for partially filled blocks?
/// For 11 bytes we need CHARBLOCKSIZE_BY_BYTEBLOCKSIZE[11]=15
/// charcters in base62.
const CHARBLOCKSIZE_BY_BYTEBLOCKSIZE : &[usize] = &[
    0, // 0 bytes
    2, // 1 bytes
    3, // 2 bytes
    5, // 3 bytes
    6, // 4 bytes
    7, // 5 bytes
    9, // 6 bytes
    10, // 7 bytes
    11, // 8 bytes
    13, // 9 bytes
    14, // 10 bytes
    15, // 11 bytes
    17, // 12 bytes
    18, // 13 bytes
    19, // 14 bytes
    21, // 15 bytes
    22, // 16 bytes
    23, // 17 bytes
    25, // 18 bytes
    26, // 19 bytes
    27, // 20 bytes
    29, // 21 bytes
    30, // 22 bytes
    31, // 23 bytes
    33, // 24 bytes
    34, // 25 bytes
    35, // 26 bytes
    37, // 27 bytes
    38, // 28 bytes
    39, // 29 bytes
    41, // 30 bytes
    42, // 31 bytes
    43, // 32 bytes
    ];

#[derive(PartialEq, Eq, Copy, Clone)]
enum CharblockSize {
    Valid, Invalid
}

use self::CharblockSize::{Valid, Invalid};

/// How many bytes were encoded with a partially filled char group (<43 chars)?
/// A group of 15 characters must be decoded into
/// BYTEBLOCKSIZE_BY_CHARBLOCKSIZE[15]=11 bytes.
/// Not all char block sizes are valid, for example a group of 4 characters
/// is invalid and should return an error.
const BYTEBLOCKSIZE_BY_CHARBLOCKSIZE : &[(usize, CharblockSize)] = &[
    (0, Valid), // 0 chars
    (0, Invalid), // 1 chars (!)
    (1, Valid), // 2 chars
    (2, Valid), // 3 chars
    (2, Invalid), // 4 chars (!)
    (3, Valid), // 5 chars
    (4, Valid), // 6 chars
    (5, Valid), // 7 chars
    (5, Invalid), // 8 chars (!)
    (6, Valid), // 9 chars
    (7, Valid), // 10 chars
    (8, Valid), // 11 chars
    (8, Invalid), // 12 chars (!)
    (9, Valid), // 13 chars
    (10, Valid), // 14 chars
    (11, Valid), // 15 chars
    (11, Invalid), // 16 chars (!)
    (12, Valid), // 17 chars
    (13, Valid), // 18 chars
    (14, Valid), // 19 chars
    (14, Invalid), // 20 chars (!)
    (15, Valid), // 21 chars
    (16, Valid), // 22 chars
    (17, Valid), // 23 chars
    (17, Invalid), // 24 chars (!)
    (18, Valid), // 25 chars
    (19, Valid), // 26 chars
    (20, Valid), // 27 chars
    (20, Invalid), // 28 chars (!)
    (21, Valid), // 29 chars
    (22, Valid), // 30 chars
    (23, Valid), // 31 chars
    (23, Invalid), // 32 chars (!)
    (24, Valid), // 33 chars
    (25, Valid), // 34 chars
    (26, Valid), // 35 chars
    (26, Invalid), // 36 chars (!)
    (27, Valid), // 37 chars
    (28, Valid), // 38 chars
    (29, Valid), // 39 chars
    (29, Invalid), // 40 chars (!)
    (30, Valid), // 41 chars
    (31, Valid), // 42 chars
    (32, Valid), // 43 chars
    ];

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
#[allow(unused_variables)]
pub fn b32bytes_to_base62_formatted(raw_in : &[u8],
                               base62out : &mut [u8],
                               space_in : &mut usize,
                               newline_in : &mut usize) -> usize {
    assert!(raw_in.len() <= 32);
    assert!(base62out.len() >= BUF_SIZE);
    assert!(*space_in > 0);
    assert!(*newline_in > 0);

    let mut written = 0;
    let output_len = CHARBLOCKSIZE_BY_BYTEBLOCKSIZE[raw_in.len()];

    let i = BigUint::from_bytes_be(raw_in);

    let base62 = i.to_radix_le(62);
    assert!(output_len >= base62.len());
    let leading_zeros = output_len - base62.len();

    // rev(): write as big-endian
    for &b in repeat(&0u8).take(leading_zeros).chain(base62.iter().rev()) {
        unsafe {
            *base62out.get_unchecked_mut(written) = alphabet(b);
            written += 1;
            *space_in -= 1;
            if *space_in == 0 {
                *space_in = SPACE_EVERY;
                *newline_in -= 1;
                if *newline_in == 0 {
                    *newline_in = NEWLINE_EVERY;
                    *base62out.get_unchecked_mut(written) = b'\n';
                    written += 1;
                } else {
                    *base62out.get_unchecked_mut(written) = b' ';
                    written += 1;
                }
            }
        }
    };
    assert!(BUF_SIZE >= written);
    written
}


#[inline]
/// Decodes a block of max [`CHARS_PER_BLOCK`] ascii chars to
/// raw data (max [`BYTES_PER_BLOCK`] bytes).
/// Returns the number of bytes written.
/// [`CHARS_PER_BLOCK`]: ../armor/constant.CHARS_PER_BLOCK.html
/// [`BYTES_PER_BLOCK`]: ../armor/constant.BYTES_PER_BLOCK.html
pub fn decode_base62_block(base62 : &[u8], mut out_buffer : &mut[u8]) -> Result<usize, String> {
    use std::io::Write;

    let (needed_output_len, valid) = BYTEBLOCKSIZE_BY_CHARBLOCKSIZE[base62.len()];
    if valid == Invalid {
        return Err("Error while decoding base62: Invalid block size.".to_string())
    }

    assert!(out_buffer.len() >= needed_output_len);

    let i = BigUint::from_radix_be(&base62, 62).unwrap();
    let as_bytes = i.to_bytes_be();

    let mut missing = needed_output_len - as_bytes.len();
    while missing > 0 {
        out_buffer.write(&[0]).ok(); // assert! guarantees enough writable space
        missing -= 1;
    }

    out_buffer.write(&as_bytes).ok(); // assert! guarantees enough writable space

    println!("inlen {} needed {} as_bytes {}", base62.len(), needed_output_len, as_bytes.len());
    Ok(needed_output_len)
}

/// Decodes stripped (only ascii, no whitespace) base62 coded data into its raw representation
/// Reuses the ascii_input as buffer, that means the data is unusable afterwards.
pub fn decode_base62<'a>(ascii_input : &mut [u8]) -> Result<Vec<u8>, String> {
    // base62 efficiency is 75%, so we can assume maximum raw data length.
    // (+rounding +last non full block needs still place of a full block (max 32))
    let max_output_size = ascii_input.len() * 3 / 4 + 1 + 32;

    let mut raw_output = vec![0u8; max_output_size];
    let mut raw_output_pointer = 0;
    {
        for (input_chunk, output_chunk) in ascii_input.chunks_mut(CHARS_PER_BLOCK)
                                       .zip(raw_output.chunks_mut(BYTES_PER_BLOCK)) {
            // dealphabet in place
            for c in input_chunk.iter_mut() {
                *c = dealphabet(*c);
            }

            raw_output_pointer += decode_base62_block(input_chunk, output_chunk)?;

        }

    }
    raw_output.resize(raw_output_pointer, 0);
    return Ok(raw_output);
}




#[cfg(test)]
mod tests {
    use super::*;

    static ALPHABET : &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


    #[test]
    fn test_alphabet() {
        for (i, c) in (ALPHABET).as_bytes().iter().enumerate() {
            assert_eq!(alphabet(i as u8), *c);
        }
    }


    #[test]
    fn test_dealphabet() {
        for (i, c) in (tests::ALPHABET).as_bytes().iter().enumerate() {
            assert_eq!(dealphabet(*c) as usize, i);
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
            let written = b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in);
            let mut out_slice = &mut out_slice[written..];
            let written = b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in);
            let mut out_slice = &mut out_slice[written..];
            b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in);
        }
        unsafe {
            let s = String::from_utf8_unchecked(out);
            assert!(s == "0Eo h211G4c8rWQ68g6 VHwCdRQSckQE9h6\nk6REalLOem0Eoh2 11G4c8rWQ68g6VH wCdRQSckQE9h6k6 REalLOem0Eoh211 G4c8rWQ68g6VHwC dRQSckQE9h6k6RE alLOemAAAAAAAAAAAA");
        }
    }


}