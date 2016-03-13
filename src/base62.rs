//! # base62
//!
//! Alphabet:
//!
//! A = Length of Alphabet = 62
//! B = Block of B Bytes to encode = 32
//! C = Length of output character block (256**B <= A**C) = 43 = ceiling(B*8/log_2(A))
//!
//!
//!
//!
//!
//! Conversion is stolen from https://github.com/nrc/zero/blob/master/src/lib.rs

use ramp::Int;
use ramp::ll::limb::Limb;
use std::mem::transmute;
use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::io::Read;
use std::ptr::Unique;
use alloc::raw_vec::RawVec;

/*
pub fn encode(bytes : &[u8]) -> String {

  return "".to_string();
}


pub fn decode(base62 : String) -> Vec<u8> {
  return vec![1, 2];
}
*/


///
///
/// NUMCHARS_FOR_NUMBYTES[num_input_bytes <= 32]
static NUMCHARS_FOR_NUMBYTES : [u8;33] = [ 0, 2, 3, 5, 6, 7, 9, 10, 11,
                                    13, 14, 15, 17, 18, 19, 21, 22, 23, 25, 26,
                                    27, 29, 30, 31, 33, 34, 35, 37, 38,
                                    39, 41, 42, 43];


pub fn as_u32_mut<'a>(bytes : &'a mut [u8; 4]) -> &'a mut u32 {
    unsafe { transmute(bytes as *const [u8; 4] as *const u8 as *const u32)  }
}

pub fn as_u32<'a>(bytes : &'a [u8; 4]) -> &'a u32 {
    unsafe { transmute(bytes as *const [u8; 4] as *const u8 as *const u32)  }
}

pub fn as_u32_be<'a>(bytes : &'a [u8; 4]) -> u32 {
    u32::from_be(*as_u32(bytes))
}

#[cfg(target_pointer_width = "32")]
pub fn bigint_from_cursor(reader : &mut Cursor<u8>) -> Int {
    // bigint is 32 bytes, that makes 32/4=8 limbs on 32bit machines
    panic!("Not tested for 32bit systems");
}

#[cfg(target_pointer_width = "64")]
pub fn bigint_from_cursor(reader : &mut Cursor<&[u8]>) -> (Int, usize) {
    let mut r : Int;
    // bigint has to represent 32 bytes, that makes 32/8=4 limbs on 64bit machines
    //let mut heap_limbs : Box<[Limb; 4]> = Box::new([Limb(0), Limb(0), Limb(0), Limb(0)]);

    // 32 bytes in Big Endian:  { msbyte:[msbit  lsbit] .... lsbyte[]  }

    let mut it = (*reader).by_ref().bytes();

    if let Some(next_u8) = it.next() {
        r = Int::from(next_u8.unwrap());
    } else {
        r = Int::zero();
        return (r, 0);
    }

    for i in 1..32 { // the other bytes
        if let Some(next_u8) = it.next() {
            r = r << 8;
            r = r + Int::from(next_u8.unwrap());
        } else {
            return (r, i);
        }
    }
    (r, 32)
}
//porEeh8cn4QrWbhKmFSNts5zn00MWVux8d4G112ipE0

#[inline]
pub fn base62_single(i : Int, s : &mut String) {
    if i < 10 {
        s.push( (b'0' + u8::from(&i)) as char);
    } else if i < 36 {
        s.push( (b'A' + u8::from(&i) - 10) as char);
    } else if i < 62 {
        s.push( (b'a' + u8::from(&i) - 36) as char);
    } else {
        panic!("Programm logic error.");
    }
}



pub fn base62_block(i : Int, l : usize) -> String {
    let mut ret = String::with_capacity(43);
    let base = Int::from(62);
    let mut quot = i;
    let mut rem = Int::zero();
    for _ in 0..NUMCHARS_FOR_NUMBYTES[l] {
        let (quot2, rem) = quot.divmod(&base);
        base62_single(rem, &mut ret);
        // 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
        quot = quot2;
    }
    ret
}


pub fn base62_stream(reader : &mut Cursor<&[u8]>) -> String {
    let mut ret = String::with_capacity(20000);
    loop {
        let (bigint, len) = bigint_from_cursor(&mut reader.by_ref());
        if len == 0 {
            break;
        }
        ret.push_str(&base62_block(bigint, len));
    }

    ret
}

/*



*/


#[cfg(test)]
#[allow(unused_variables)]
mod test {
    use super::*;
    use std::mem::transmute;
    use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
    use std::io::Cursor;
    use ramp::Int;




    #[test]
    fn test_base62_single() {
        fn c2b62(i : u8) -> String {
            let mut s = String::with_capacity(1);
            base62_single(Int::from(i), &mut s);
            s
        }
        assert_eq!("0", c2b62(0));
        assert_eq!("1", c2b62(1));
        assert_eq!("9", c2b62(9));
        assert_eq!("A", c2b62(10));
        assert_eq!("B", c2b62(11));
        assert_eq!("Z", c2b62(35));
        assert_eq!("a", c2b62(36));
        assert_eq!("z", c2b62(61));
    }

    #[test]
    fn test_base62_stream() {
        let three_blocks = (1..96).collect::<Vec<u8>>();
        let bytes : &[u8] = &three_blocks[0..95];
        let mut c = Cursor::new(bytes);
        println!("{:?}", base62_stream(&mut c));
        assert_eq!(1, 2);
    }

    #[test]
    fn test_base62_block() {
        let three_blocks = (1..96).collect::<Vec<u8>>();
        let bytes : &[u8] = &three_blocks[0..95];
        let mut c = Cursor::new(bytes);
        let (i1, l1) = bigint_from_cursor(&mut c);
        assert_eq!(base62_block(i1, l1), "123");
    }


    #[test]
    fn bigints() {
        let three_blocks = (1..96).collect::<Vec<u8>>();
        let bytes : &[u8] = &three_blocks[0..95];
        let mut c = Cursor::new(bytes);
        let (i1, l1) = bigint_from_cursor(&mut c);
        let (i2, l2) = bigint_from_cursor(&mut c);
        let (i3, l3) = bigint_from_cursor(&mut c);
        println!("{:?} read: {:?}", i1, l1);
        println!("{:?} read: {:?}", i2, l2);
        println!("{:?} read: {:?}", i3, l3);
        assert_eq!("1", i1.to_str_radix(10, true));
    }


    #[test]
    fn bytes_to_u32_using_byteorder_and_cursor_big_endian() {
        let bytes : [u8; 8] = [82, 117, 115, 116, 82, 117, 115, 117];
        let mut cursor = Cursor::new(bytes);
        let converted = cursor.read_u32::<BigEndian>().unwrap();
        let converted2 = cursor.read_u32::<BigEndian>().unwrap();
        assert_eq!(1383428980u32, converted);
        assert_eq!(1383428981u32, converted2);
    }

    #[test]
    fn bytes_to_u32_using_byteorder_big_endian() {
        let bytes : [u8; 4] = [82, 117, 115, 116];
        let converted = BigEndian::read_u32(&bytes);
        assert_eq!(1383428980u32, converted);
    }

    #[test]
    fn bytes_to_u32_big_endian() {
        let bytes : [u8; 4] = [82, 117, 115, 116];
        let converted : u32 = as_u32_be(&bytes);

        // does not point to same memory (because endian conversion)
        assert!(format!("{:p}", &bytes) !=
                format!("{:p}", &converted));

        let bytearrayaddress = format!("{:p}", &bytes);

        assert_eq!(converted, 1383428980);
    }

    #[test]
    fn bytes_to_u32() {
        let bytes : [u8; 4] = [82, 117, 115, 116];
        // Big endian interpretation: 82*256**3 + 117*256**2 + 115*256 + 116 = 1383428980
        // Little endian (intel):     116*256**3 + 115*256**2 + 117*256 + 82 = 1953723730
        let converted : & u32 = as_u32(&bytes);

        // points to same memory
        assert_eq!(format!("{:p}", &bytes),
                   format!("{:p}", converted));

        let bytearrayaddress = format!("{:p}", &bytes);

        assert_eq!(*converted, 1953723730);
    }

    #[test]
    fn bytes_to_u32_mut() {
        let mut bytes : [u8; 4] = [82, 117, 115, 116];
        let bytearrayaddress = format!("{:p}", &bytes);
        let mut converted : &mut u32 = as_u32_mut(&mut bytes);

        // points to same memory
        assert_eq!(bytearrayaddress, format!("{:p}", converted));

        *converted += 1;
        //bytes[0] += 1; // compiler error, is borrowed

        assert_eq!(*converted, 1953723731);
    }

    #[test]
    fn bytes_to_u32_mut_deref() {
        let mut bytes : [u8; 4] = [82, 117, 115, 116];
        let bytearrayaddress = format!("{:p}", &bytes);
        let mut converted = *as_u32_mut(&mut bytes);

        // converted has been copied
        assert!(bytearrayaddress != format!("{:p}", &converted));

        converted += 1;
        bytes[0] += 1; // is free again

        assert_eq!(converted, 1953723731);
    }


    #[test]
    fn test() {
        assert_eq!(3, 3);
    }

}