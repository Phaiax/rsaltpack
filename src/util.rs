use std;

/// This trait provides the consume() method.
pub trait Consumable {
    fn consume(&mut self, amt: usize);
}


impl<'a> Consumable for &'a mut [u8] {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, &mut []);
        *self = &mut this[amt..];
    }
}


impl<'a> Consumable for &'a [u8] {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, & []);
        *self = & this[amt..];
    }
}

impl<'a> Consumable for &'a str {
    #[inline]
    fn consume(&mut self, amt: usize) {
        let this = std::mem::replace(self, & "");
        *self = & this[amt..];
    }
}