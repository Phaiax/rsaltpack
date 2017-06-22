//! Armoring binary data with [base62](https://saltpack.org/armoring) encoding.
//!
//! Nonetheless it is not recommended to to send large amounts of data (many MB)
//! armored (as ascii). Better just send the unarmored binary data.
//!
//! ## With encryption
//!
//! Do not use anything of this module. Instead use the [armor() method of
//! struct Saltpack](../encrypt/struct.Saltpack.html#method.armor).
//!
//! You may want to use the method [valid_vendor()](fn.valid_vendor.html).
//!
//! ## You probably do not want to use this directly:
//!
//! Use [ArmoringStream](struct.ArmoringStream.html) as a streaming interface.
//!
//! Use the funciton [armor()](fn.armor.html) to armor a the binary data
//! at once. Header and footer will be written immediatly.

use std::io::Write;
use std::fmt;
use std::cmp;

use util::Consumable;
use base62::b32bytes_to_base62_formatted;

pub use ::SaltpackMessageType;
use errors::*;

/// This function does the same as [ArmoringStream](struct.ArmoringStream.html),
/// but in one rush.
///
/// It will convert binary input into the base62 armored version including
/// header and footer.
///
/// It can fail if the vendorstring contains invalid characters.
pub fn armor(binary_in : &mut [u8],
             vendorstring: &str,
             messagetype: SaltpackMessageType)
             -> Result<String> {
    let mut armoring_stream = ArmoringStream::new(vendorstring, messagetype)?;
    let mut out = vec![0u8; armoring_stream.predict_armored_len(binary_in.len())];
    let (_, written) = armoring_stream.armor(&binary_in[..], true, &mut out[..]).unwrap();
    out.resize(written, 0);
    assert!(armoring_stream.is_done());
    Ok(unsafe { String::from_utf8_unchecked(out) })
}

/// Check if a vendor string is valid. The vendor string must only contain
/// these characters: Regex: [a-zA-Z0-9]*
pub fn valid_vendor(vendor : &str) -> Result<()> {
    fn in_(c : char, first : char, last : char) -> bool {
        first <= c && c <= last
    }
    for c in vendor.chars() {
        if ! (in_(c, 'a', 'z') || in_(c, 'A', 'Z') || in_(c, '0', '9')) {
            bail!(ErrorKind::BadVendorString(c, vendor.into()));
        }
    }
    Ok(())
}

/// A streaming interface to armor large amounts of binary data.
pub struct ArmoringStream {
    /// What do we write currently?
    state : ArmoringStreamState,
    header : String,
    footer : String,
}

/// Internal state of the armor conversion method.
enum ArmoringStreamState{
    /// Header means BEGIN {} SALTPACK {}.
    AtHeader {
        pos_within_header: usize,
    },
    /// Data means the base62 coded data
    AtData {
        /// How many chars to be written until we put the next space
        space_in: usize,
        /// How many words to be written until we put the next newline
        newline_in : usize,
        /// Buffer of converted base62 data
        out_buffer : [u8 ; BUF_SIZE],
        /// pos in `out_buffer`
        bufpos : usize,
        /// used len of `out_buffer` (depends on number and positon of spaces)
        buflen : usize,
        /// This is an optionally used buffer for incoming raw data, in case that
        /// the incomming data has some remaining bytes, but less than BYTES_PER_BLOCK.
        /// These remaining bytes will be read anyway and need to be concated
        /// with future data. (This pre-reading prevents locks)
        in_buffer : InBuffer,
    },
    /// Footer means: END {} SALTPACK {}.
    AtFooter {
        pos_within_footer: usize,
    },
    Finished,
}

#[derive(Debug, PartialEq)]
enum InBuffer {
    Unused,
    Used {
        filled_until: usize,
        buffer : [u8 ; BYTES_PER_BLOCK],
    }
}

/// The base62 scheme is based on blocks with length of 32 byte of binary data
pub const BYTES_PER_BLOCK: usize = 32;
/// One block of 32 byte will be converted into 43 characters, if it is not the last block.
pub const CHARS_PER_BLOCK: usize = 43;
/// The armored string will contain a space every 15 characters.
pub const SPACE_EVERY: usize = 15;
/// The armored string will contain a newline instead of a space every 200 words.
pub const NEWLINE_EVERY: usize = 200;
/// Storage needed to store the armored 43 characters with inserted spaces.
/// (there can be 2 or 3 spaces within one block)
pub const BUF_SIZE : usize = CHARS_PER_BLOCK + CHARS_PER_BLOCK / SPACE_EVERY + 1;


impl ArmoringStream {

    /// Create a new streaming interface
    pub fn new(vendorstring: &str,
               messagetype: SaltpackMessageType)
               -> Result<ArmoringStream> {
        valid_vendor(vendorstring)?;
        Ok(ArmoringStream{
            state : ArmoringStreamState::AtHeader{
                pos_within_header : 0,
            },
            header : format!("BEGIN {} SALTPACK {}. ", vendorstring, messagetype.to_string()),
            footer : format!(". END {} SALTPACK {}.", vendorstring, messagetype.to_string()),
        })
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
    /// Returns the bytes read from `binary_in`, the bytes written to `armored_out`.
    /// Call `is_done()` to figure out if everything (incl. footer) has been written.
    pub fn armor(&mut self,
                 mut binary_in : &[u8],
                 last_bytes : bool,
                 mut armored_out : &mut[u8])
                 -> Result<(usize, usize)> {

        let binary_in_len = binary_in.len();
        let armored_out_len = armored_out.len();

        self.put_header(&mut armored_out);

        self.put_data(&mut binary_in, last_bytes, &mut armored_out);

        self.put_footer(&mut armored_out);

        Ok((binary_in_len   - binary_in.len() ,
            armored_out_len - armored_out.len()))
    }

    // the double &mut is to borrow the slice, and not to create a new borrowed
    // slice from the old one. This way the `armored_out.write()` does modify its
    // size even in the calling function.
    fn put_header(&mut self, armored_out : &mut &mut[u8]) {
        let mut next = false; // work around borrowing problems

        // Write as much header as possible.
        if let ArmoringStreamState::AtHeader{ref mut pos_within_header} = self.state {
            *pos_within_header += armored_out.write(
                &self.header.as_bytes()[*pos_within_header..]).unwrap();
            if *pos_within_header == self.header.len() {
                next = true;
            }
        };
        // Switch to state `AtData` if header is written.
        if next {
            self.proceed_to_data_state();
        }

    }

    fn proceed_to_data_state(&mut self) {
        if ! self.state.is_at_header() {
            panic!("Armor internal error: Must be within AtHeader state to proceed to AtData state");
        }
        self.state = ArmoringStreamState::AtData{
            space_in : SPACE_EVERY,
            newline_in : NEWLINE_EVERY,
            out_buffer : [0 ; BUF_SIZE],
            bufpos : 0,
            buflen : 0,
            in_buffer : InBuffer::Unused,
        };
    }

    // see put_header for explanation of the `&mut &mut`
    fn put_data(&mut self,
                binary_in : &mut &[u8],
                last_bytes : bool,
                armored_out : &mut &mut[u8]) {


        let mut next = false; // work around borrowing problems
        let mut clear_in_buffer = false; // work around borrowing problems

        // Write as much armored data as possible.
        if let ArmoringStreamState::AtData{ref mut space_in,
                                           ref mut newline_in,
                                           ref mut out_buffer,
                                           ref mut bufpos,
                                           ref mut buflen,
                                           ref mut in_buffer } = self.state {

            while armored_out.len() > 0 { // has place to write

                // first write remaining data from `out_buffer` if needed
                if *bufpos != *buflen {
                    assert!(*bufpos < *buflen);
                    // ... then write all that fits into armored_out
                    *bufpos += armored_out.write(
                        &out_buffer[*bufpos..*buflen]).unwrap();
                    // start loop again to check if still space in `armored_out`
                    continue;

                } else if let InBuffer::Used { ref mut filled_until,
                                               ref mut buffer, } = *in_buffer {

                    if *filled_until != BYTES_PER_BLOCK {
                        if !binary_in.is_empty() {
                            // more bytes need to be inserted into in_buffer until
                            // a full block is available

                            let needed = BYTES_PER_BLOCK - *filled_until;
                            let take = cmp::min(needed, binary_in.len());
                            let end = *filled_until + take;
                            (&mut (*buffer)[*filled_until..end]).copy_from_slice(&binary_in[0..take]);
                            *filled_until = end;
                            (*binary_in).consume(take);
                            continue;
                        } else { // binary_in.is_empty()

                            if last_bytes {
                                *buflen = b32bytes_to_base62_formatted(&buffer[..*filled_until],
                                                             &mut out_buffer[..],
                                                             &mut *space_in,
                                                             &mut *newline_in);
                                *bufpos = 0;
                                clear_in_buffer = true;
                            } else { // !last_bytes
                                break; // wait for next call to armor() which will deliver more bytes
                            }
                        }
                    } else { // filled_until == BYTES_PER_BLOCK
                        // simply write into out_buffer, no direct write into armored_out
                        *buflen = b32bytes_to_base62_formatted(&buffer[0..BYTES_PER_BLOCK],
                                                         &mut out_buffer[..],
                                                         &mut *space_in,
                                                         &mut *newline_in);
                        *bufpos = 0;
                        clear_in_buffer = true; // in_buffer still borrowed here
                    }
                }

                if clear_in_buffer {
                    *in_buffer = InBuffer::Unused;
                    clear_in_buffer = false;
                    continue;
                }

                if *bufpos == *buflen && *in_buffer == InBuffer::Unused { // out_buffer got empty

                    // 32 byte <> 43 characters
                    if binary_in.len() >= BYTES_PER_BLOCK && armored_out.len() >= BUF_SIZE {
                        // shortcut: direct conversion into armored_out
                        let written = b32bytes_to_base62_formatted(&binary_in[0..BYTES_PER_BLOCK],
                                                         &mut *armored_out,
                                                         &mut *space_in,
                                                         &mut *newline_in);
                        armored_out.consume(written);
                        binary_in.consume(BYTES_PER_BLOCK);
                        continue; // bufpos is still buflen

                    } else if binary_in.len() >= BYTES_PER_BLOCK {
                        // the complete 43+x char block doesn't fit into armored_out
                        // first base62-convert next 32 input bytes into out_buffer ...
                        *buflen = b32bytes_to_base62_formatted(&binary_in[0..BYTES_PER_BLOCK],
                                                         &mut out_buffer[..],
                                                         &mut *space_in,
                                                         &mut *newline_in);
                        binary_in.consume(BYTES_PER_BLOCK);
                        *bufpos = 0;
                        continue; // Then write partly to armored_out

                    } else if binary_in.len() < BYTES_PER_BLOCK && ! last_bytes {
                        // not enough bytes to make a base62 conversion, but read the
                        // incomming bytes anyway to prevent locks. (A lock would happen
                        // if the caller of armor() has multiple Vec<>s that it is puting
                        // into armor() once after another. If a base64 raw chunk is parted
                        // across two of these vecs, the caller of armor() does not think
                        // about concating the vecs to create that chunk. So this function does)
                        let mut b = [0u8; BYTES_PER_BLOCK];
                        (&mut b[..binary_in.len()]).copy_from_slice(binary_in);

                        *in_buffer = InBuffer::Used {
                            filled_until: binary_in.len(),
                            buffer : b,
                        };
                        binary_in.consume(binary_in.len());

                    } else if binary_in.len() > 0 && last_bytes { // last non full block
                        *buflen = b32bytes_to_base62_formatted(&binary_in[..],
                                                         &mut out_buffer[..],
                                                         &mut *space_in,
                                                         &mut *newline_in);
                        binary_in.consume(binary_in.len()); // finish
                        *bufpos = 0;
                    } else if binary_in.len() == 0 && last_bytes {
                        next = true;
                        break;
                    } else {
                        break; // waiting for more input data
                    }
                }


            }
        }

        // Switch to state `AtFooter` if main data is written.
        if next {
            self.proceed_to_footer_state();
        }
    }

    fn proceed_to_footer_state(&mut self) {
        if ! self.state.is_at_data() {
            panic!("Armor internal error: Must be within AtData state to proceed to AtFooter state");
        }
        self.state = ArmoringStreamState::AtFooter{
            pos_within_footer : 0,
        };
    }

    // see put_header for explanation of the `&mut &mut`
    fn put_footer(&mut self, armored_out : &mut &mut[u8]) {
        let mut next = false; // work around borrowing problems

        // Write as much footer data as possible.
        if let ArmoringStreamState::AtFooter{ref mut pos_within_footer} = self.state {
            *pos_within_footer += armored_out.write(
                &self.footer.as_bytes()[*pos_within_footer..]).unwrap();
            if *pos_within_footer == self.footer.len() {
                next = true;
            }
        }

        // Switch to state `Finished` if footer is written.
        if next {
            self.finish();
        }
    }

    fn finish(&mut self) {
        if ! self.state.is_at_footer() {
            panic!("Armor internal error: Must be within AtFooter state to proceed to Finished state");
        }
        self.state = ArmoringStreamState::Finished;
    }

    /// Returns `true` if header, data and footer have been written completely.
    pub fn is_done(&self) -> bool {
        self.state.is_finished()
    }

    /// Stops writing and reading anything. `is_done` will be `true`.
    pub fn cancel(&mut self) {
        self.state = ArmoringStreamState::Finished;
    }

}

impl fmt::Debug for ArmoringStream {
    fn fmt(&self, mut f : &mut fmt::Formatter) -> fmt::Result {
        self.state.fmt(&mut f)?;
        Ok(())
    }
}

impl fmt::Debug for ArmoringStreamState {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("not implemented")
    }
}

impl ArmoringStreamState {
    fn is_at_header(&self) -> bool {
        match *self { ArmoringStreamState::AtHeader{..} => true, _ => false }
    }
    fn is_at_data(&self) -> bool {
        match *self { ArmoringStreamState::AtData{..} => true, _ => false }
    }
    fn is_at_footer(&self) -> bool {
        match *self { ArmoringStreamState::AtFooter{..} => true, _ => false }
    }
    fn is_finished(&self) -> bool {
        match *self { ArmoringStreamState::Finished => true, _ => false }
    }
}





#[cfg(test)]
mod tests {
    use super::*;
    use util::Consumable;


    #[test]
    fn armoring_stream() {
        let data : [u8 ; 32] = [ 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8, ];
        let mut armoring_stream = ArmoringStream::new("RUST", SaltpackMessageType::ENCRYPTEDMESSAGE).unwrap();
        let len = armoring_stream.predict_armored_len(data.len());
        let mut out = vec![0u8; len];
        let (read, written) = armoring_stream.armor(&data[..], true, &mut out[..]).unwrap();
        out.resize(written, 0);
        let s = unsafe { String::from_utf8_unchecked(out) };
        assert!(armoring_stream.is_done());
        assert_eq!(read, data.len());
        assert_eq!(written, len);
        assert_eq!(s, "BEGIN RUST SALTPACK ENCRYPTED MESSAGE. 0Eoh211G4c8rWQ6 8g6VHwCdRQSckQE 9h6k6REalLOem. END RUST SALTPACK ENCRYPTED MESSAGE.");
    }

    #[test]
    fn in_buffer() {
        let data : [u8 ; 32] = [ 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8,
                                 1, 2, 3, 4, 5, 6, 7, 8, ];

        let mut armoring_stream = ArmoringStream::new("RUST", SaltpackMessageType::ENCRYPTEDMESSAGE).unwrap();
        let mut out = vec![0u8; armoring_stream.predict_armored_len(data.len() * 3)];

        {

            let mut out_buf = &mut out[..];
            // do not deliver enough data to make a block
            let (read, written) = armoring_stream.armor(&data[0..15], false, &mut out_buf).unwrap();
            assert_eq!(read, 15);
            let header_len = "BEGIN RUST SALTPACK ENCRYPTED MESSAGE. ".len();
            assert_eq!(written, header_len);
            out_buf.consume(written);

            // still do not deliver enough data
            let (read, written) = armoring_stream.armor(&data[15..25], false, &mut out_buf).unwrap();
            assert_eq!(read, 10);
            assert_eq!(written, 0);
            out_buf.consume(written);

            // now deliver data until 32 bytes are complete
            let (read, written) = armoring_stream.armor(&data[25..32], false, &mut out_buf).unwrap();
            assert_eq!(read, 7);
            println!("{:?}", String::from_utf8_lossy(&out_buf[0..written]));
            assert_eq!(written, 45);
            out_buf.consume(written);

            // next try: use in_buffer(), and then use it again
            let (read, written) = armoring_stream.armor(&data[0..24], false, &mut out_buf).unwrap();
            assert_eq!(read, 24);
            assert_eq!(written, 0);
            out_buf.consume(written);

            let (read, written) = armoring_stream.armor(&data[0..32], false, &mut out_buf).unwrap();
            assert_eq!(read, 32);
            assert_eq!(written, 46);
            out_buf.consume(written);

            // now add 0 new bytes but use the 24 bytes from the in_buffer for the last not full block
            let (read, written) = armoring_stream.armor(&data[0..0], true, &mut out_buf).unwrap();
            println!("{:?}", String::from_utf8_lossy(out_buf));
            assert_eq!(read, 0);
            assert_eq!(written, 73);
            out_buf.consume(written);
        }


    }

}
