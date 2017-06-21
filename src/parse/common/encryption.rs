
#[derive(Debug)]
/// Possible errors of `verify()` (mode=encryption)
pub enum EncryptionHeaderVerifyError {
    YouAreNotOneOfTheRecipients,
    NotWellFormed(String),
}

#[derive(Debug)]
/// Possible errors of `read_payload()`
pub enum DecryptionError {
    PayloadPacketVerificationError,
    PayloadDecryptionError,
    MessageTruncatedError,
    EOFOccured,
    NotWellFormed(String),
}



