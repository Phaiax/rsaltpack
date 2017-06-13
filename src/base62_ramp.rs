


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
                               base62out : &mut [u8],
                               space_in : &mut usize,
                               newline_in : &mut usize,
                               full_32 : bool) -> usize {
    return 0; /*
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
    */
}

#[inline]
/// Decodes a block of max [`CHARS_PER_BLOCK`] ascii chars to
/// raw data (max [`BYTES_PER_BLOCK`] bytes).
/// Returns the number of bytes written.
/// [`CHARS_PER_BLOCK`]: ../armor/constant.CHARS_PER_BLOCK.html
/// [`BYTES_PER_BLOCK`]: ../armor/constant.BYTES_PER_BLOCK.html
pub fn decode_base62_block(base62 : &[u8], rawout : &mut[u8]) -> usize {
    return 0;
   /* let i = unsafe {
        Int::from_u8_be_radix_unchecked(base62, 62).unwrap()
    };
    i.write_big_endian_buffer(rawout).unwrap()*/
}

/// Decodes stripped (only ascii, no whitespace) base62 coded data into its raw representation
/// Reuses the ascii_input as buffer, that means the data is unusable afterwards.
pub fn decode_base62<'a>(ascii_input : &mut [u8]) -> Result<Vec<u8>, String> {
    // base62 efficiency is 75%, so we can assume maximum raw data length.
    // (+rounding +last non full block needs still place of a full block (max 32))
    let mut raw_output = vec![0u8; ascii_input.len() * 3 / 4 + 1 + 32];
    let mut raw_output_pointer = 0;
    {
        for (input_chunk, output_chunk) in ascii_input.chunks_mut(CHARS_PER_BLOCK)
                                       .zip(raw_output.chunks_mut(BYTES_PER_BLOCK)) {
            // dealphabet in place
            for c in input_chunk.iter_mut() { *c = dealphabet(*c); }
            raw_output_pointer += decode_base62_block(input_chunk, output_chunk);

        }

    }
    raw_output.resize(raw_output_pointer, 0);
    return Ok(raw_output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use util::Consumable;

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
            b32bytes_to_base62_formatted(&data, &mut out_slice, &mut space_in, &mut newline_in, true);
        }
        unsafe {
            let s = String::from_utf8_unchecked(out);
            assert!(s == "0Eo h211G4c8rWQ68g6 VHwCdRQSckQE9h6\nk6REalLOem0Eoh2 11G4c8rWQ68g6VH wCdRQSckQE9h6k6 REalLOem0Eoh211 G4c8rWQ68g6VHwC dRQSckQE9h6k6RE alLOemAAAAAAAAAAAA");
        }
    }
}