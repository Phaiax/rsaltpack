
#![feature(custom_derive, plugin, alloc, unique)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_json;
extern crate ramp;
extern crate byteorder;
extern crate alloc;


//mod headerpacket;
mod base62;

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {
    }
}
