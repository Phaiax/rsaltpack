extern crate rsaltpack;

fn main() {

    // Stakeholders
    use rsaltpack::key::{EncryptionKeyPair, KeybaseKeyFormat, EncryptionPublicKey};
    let sender = EncryptionKeyPair::gen();


    let recipient = EncryptionPublicKey::from_keybaseformat(
        "012179c8d97459d58b4f41ab72265903138855e11ac525d91d8e8818d29d7bb9df1d0a",
    ).unwrap();
    let data = b"The secret passage is behind shelf 13\n";

    // Compose
    use rsaltpack::encrypt;
    let email = encrypt::encrypt_and_armor(
        Some(&sender),
        &[recipient], // sender only knows public key
        data,
        "KEYBASE",
    ).unwrap();

    println!("{}", email);

}
