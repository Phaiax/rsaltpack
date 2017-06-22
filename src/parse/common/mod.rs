
pub mod header;
pub mod encryption;

pub use self::header::Recipient;

/// Concats the inner vectors.
///
/// Zeros out the old plaintext data before dropping the input.
pub fn concat(mut chunks: Vec<Vec<u8>>) -> Vec<u8> {
    use std::io::Write;

    let len = chunks.iter().fold(0, |l, inner| l + inner.len());
    let mut ret = Vec::with_capacity(len);
    for mut inner in &mut chunks {
        ret.write_all(&inner[..]).unwrap();
        for c in inner.iter_mut() {
            *c = 0;
        }
    }
    ret
}


#[allow(dead_code)]
/// For testing purposes.
pub(crate) fn print_debug_as_str(reader: &[u8]) {
    use std::char::from_u32;

    for b in reader.iter() {
        let c: u8 = *b;
        let i: u32 = c as u32;
        let c = from_u32(i);
        if let Some(c) = c {
            print!("{}", c);
        }
    }
    println!("");
}
