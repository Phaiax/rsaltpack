
use super::*;
use dearmor::dearmor;
use dearmor::Stripped;
// use ::SaltpackMessageType;

static ARMORED_2 : &'static str = "BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiOUtMhcc4NXXRb XMxIdgQyljueFUr j9Glci9VK9gs0FD SAI1ChjLXBNvLG9 KzKYjJpeQYdhPeE 132M0VyYiPVRKkc xfxsSUuTNvDtLV8 XJEZlLNM9AEMoJ4 4cQ9dhRpULgINBK CMjxIe0olHF05oC BFiS4JEd9YfzKfB kppV8R4RZeEoU2E StUW1n6563Nynco OAZjT8O8dy3wspR KRIYp2lGwO4jhxN 7Pr1ROg89nrQbTs jIe5kKk0OcNk2nr nFwpZ2T5FflPK6A OAfEWB1ff1o0dG7 3ZSD1GzzH3LbCgj IUg0xnpclpHi37r sXoVzt731JucYGh ihnM9jHK5hhiCmx hnnZ3SyXuW443wU WxTFOzeTJ37kNsG ZNIWxfKIu5rcL8Q PwFd2Sn4Azpcdmy qzlJMvKphjTdkEC EVg0JwaSwwMbhDl OuytEL90Qlf8g9O S8S6qY4Ssw80J5V Avqz3CiiCuSUWzr ry6HdhLWWpguBQi a74pdDYBlzbjsXM lLLKaF5t46nnfB0 7APzXL7wfvRHZVF kJH1SP9WVxULDH2 gocmmy8E2XHfHri nVZU27A3EQ0d0EY IrXpllP8BkCbIc1 GuQGRaAsYH4keTR FuH0h4RoJ6J6mYh TXRceNTDqYAtzm0 Fuop8MaJedh8Pzs HtXcxYsJgPvwqsh H6R3It9Atnpjh1U u0o0uNY0lhcTB4g GHNse3LigrLbMvd oq6UkokAowoWwy2 mk4QdKuWAXrTTSH viB7AMcs5HC96mG 4pTjaXRNBT7Zrs6 fc1GCa4lMJPzSWC XM2pIvu70NCHXYB 8xW11pz1Yy3K2Cw Wz. END KEYBASE SALTPACK ENCRYPTED MESSAGE.";


#[test]
#[allow(unused_variables)]
fn test_v10() {
    let raw_saltpacks = dearmor(Stripped::from_utf8(&ARMORED_2), 1).unwrap();
    let mut reader : &[u8] = raw_saltpacks[0].raw_bytes.as_slice();
    let mut parser = Parser10::read_header(&mut reader).unwrap();
    let encrypted = parser.try_encrypted().unwrap();
    assert_eq!(encrypted.recipients.len(), 3);
    //encrypted.verify()
}

#[test]
fn test_real_keybase_msg() {

}