
pub mod header;
pub mod encryption;


use std::io::Write;

use std::char::from_u32;

pub use self::header::ParseError;
pub use self::header::Recipient;
pub use self::encryption::EncryptionHeaderVerifyError;
pub use self::encryption::DecryptionError;

/// Removes the outer vector by concating the inner vectors.
/// Zeros out the old plaintext data before dropping the input
pub fn concat(mut chunks : Vec<Vec<u8>>) -> Vec<u8> {
    let len = chunks.iter().fold(0, |l, inner| l + inner.len());
    let mut ret = Vec::with_capacity(len);
    for mut  inner in chunks.iter_mut() {
        ret.write_all(&inner[..]).unwrap();
        for c in inner.iter_mut() {
            *c = 0;
        }
    }
    ret
}

// #############################################################################
// #######             TESTING                          ########################
// #############################################################################


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
