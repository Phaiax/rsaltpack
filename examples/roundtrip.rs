extern crate rsaltpack;

fn main() {

    // Stakeholders
    use rsaltpack::KeyPair;
    let sender = KeyPair::gen();
    let recipient = KeyPair::gen();
    let data = b"The secret passage is behind shelf 13";

    // Compose
    use rsaltpack::compose;
    let email = compose::encrypt_to_binary(
                    Some(&sender),
                    &vec![recipient.p], // sender only knows public key
                    data);

    println!("{:?}", email);

    // Retrieve
    use rsaltpack::parse;
    let mut read_email = &email[..];
    let mut header = parse::SaltpackHeader::read_header(&mut read_email).unwrap();
    if header.is_mode_encryption() {
        let mut decryptor = header.verify(&recipient.s).unwrap(); // recipient knows its secret key
        let data_2 = decryptor.read_payload(&mut read_email).map(parse::concat).unwrap();
        assert_eq!(&data[..], &data_2[..]);
    }


}