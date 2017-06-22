extern crate rsaltpack;

fn main() {

    // Stakeholders
    use rsaltpack::key::EncryptionKeyPair;
    let sender = EncryptionKeyPair::gen();
    let recipient = EncryptionKeyPair::gen();
    let data = b"The secret passage is behind shelf 13";

    // Compose
    use rsaltpack::encrypt;
    let email = encrypt::encrypt_to_binary(
        Some(&sender),
        &[recipient.p], // sender only knows public key
        data,
    );

    // Retrieve
    use rsaltpack::parse;
    let mut read_email = &email[..];
    let mut header = parse::Parser::read_header(&mut read_email).unwrap();
    if let parse::Parser::Encrypted(ref mut e) = header {
        let mut decryptor = e.verify(&recipient.s).unwrap(); // recipient knows its secret key
        let data_2 = decryptor
            .read_payload(&mut read_email)
            .map(parse::concat)
            .unwrap();
        assert_eq!(&data[..], &data_2[..]);
    }


}
