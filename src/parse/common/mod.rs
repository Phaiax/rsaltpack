
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

#[cfg(test)]
mod tests {
    use super::concat;

    #[test]
    fn concat_does_zeroing() {
        let test_ptr;
        {
            let data1 = vec![1u8, 2, 3, 4, 5, 6];
            let data2 = vec![1, 2, 3, 4, 5, 6];
            test_ptr = data1.as_ptr();
            let multi = vec![data1, data2];
            assert_eq!(3, unsafe { *(test_ptr.offset(2)) });
            let cat = concat(multi);
            assert_eq!(*&cat[8], 3);
            // drop everything
        }
        assert_eq!(0, unsafe { *(test_ptr.offset(2)) });
        assert_eq!(0, unsafe { *(test_ptr.offset(4)) });
    }
}
