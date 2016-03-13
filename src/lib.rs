
#![feature(custom_derive, plugin, alloc)]
#![plugin(serde_macros)]
#![plugin(regex_macros)]

extern crate serde;
extern crate serde_json;
extern crate ramp;
extern crate byteorder;
extern crate alloc;
extern crate regex;
extern crate rmp;

pub mod headerpacket;
pub mod armor;

#[derive(Debug, PartialEq)]
pub enum SaltpackMessageType {
    ENCRYPTEDMESSAGE,
    SIGNEDMESSAGE,
    DETACHEDSIGNATURE
}


// step 1: iter through input string.as_bytes() and copy u8 to extra array if not whitespace
//         thereby convert from letter to associated number
// step 2: for each full 42 byte slice:
// step 3:  create Int from Base

#[cfg(test)]
mod test {

}
