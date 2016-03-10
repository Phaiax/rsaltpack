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
pub fn bigint_from_cursor(reader : &mut Cursor<&[u8]>) -> Int {

    // bigint has to represent 32 bytes, that makes 32/8=4 limbs on 64bit machines
    let mut heap_limbs : Box<[Limb; 4]> = Box::new([Limb(0), Limb(0), Limb(0), Limb(0)]);

    if let Ok(next_limb) = (*reader).read_u64::<BigEndian>() {
        heap_limbs[0] = Limb(next_limb);
    }
    if let Ok(next_limb) = (*reader).read_u64::<BigEndian>() {
        heap_limbs[1] = Limb(next_limb);
    }
    if let Ok(next_limb) = (*reader).read_u64::<BigEndian>() {
        heap_limbs[2] = Limb(next_limb);
    }
    if let Ok(next_limb) = (*reader).read_u64::<BigEndian>() {
        heap_limbs[3] = Limb(next_limb);
    }

    let mut limbs : RawVec<Limb> = RawVec::from_box(heap_limbs);
    let mut ptr: Unique<Limb> = Unique::new(limbs.ptr());

    Int { ptr: ptr, size: 4, cap: 4 }
}


#[cfg(test)]
#[allow(unused_variables)]
mod test {
    use super::*;
    use std::mem::transmute;
    use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
    use std::io::Cursor;


    #[test]
    fn bigints() {
        let three_blocks = (1..96).collect::<Vec<u8>>();
        let bytes : [u8] = three_blocks[..];

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