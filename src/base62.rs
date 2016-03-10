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
//!

use std::mem::transmute;

pub fn encode(bytes : &[u8]) -> String {

  return "".to_string();
}


pub fn decode(base62 : String) -> Vec<u8> {
  return vec![1, 2];
}

pub fn as_i32(bytes : &[u8; 32]) -> Result<i32, String> {
  Ok(unsafe { transmute::<&[u8; 32], i32>(bytes) })
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bytes_to_i32() {
        let bytes : &[u8; 4] = &[82, 117, 115, 116, 152, 23, 13, 252];
        let i = as_i32(bytes).unwrap();
        assert_eq!(i, 2);
    }


    static TEST_HEADER_JSON : &'static str = "";
    static TEST_HEADER_SIMPLE : &'static str = "[\"saltpack\",[1,0],0,\"ad\",\"35\",[[\"wer\",\"werwt\"]]]";
    static TEST_HEADER_MOREFIELDS : &'static str = "[\"saltpack\",[1,0],0,\"ad\",\"35\",[[\"wer\",\"werwt\"]], 234]";
    static TEST_HEADER_AS_DICT : &'static str = "{\"identifier\":\"saltpack\",\"version\":[1,0],\"kind\":0,\"s1\":\"ad\",\"s2\":\"35\",\"recipients\":[[\"wer\",\"werwt\"]]}";
    static TEST_HEADER_AS_DICT_MOREFIELDS : &'static str = "{\"identifier\":\"saltpack\",\"version\":[1,0],\"kind\":0,\"s1\":\"ad\",\"s2\":\"35\",\"recipients\":[[\"wer\",\"werwt\"]], \"erg\" : 1243}";
    #[test]
    fn test() {
        assert_eq!(3, 3);
    }

}