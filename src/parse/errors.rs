

macro_rules! not_well_formed {
    ( $( $param:expr ),* ) => {
        {
            let msg : ParseError = format!($( $param, )*).into();
            Err(msg).chain_err(|| ParseErrorKind::NotWellFormed)
        }
    };
}

error_chain!{
    types { ParseError, ParseErrorKind, ParseResultExt, ParseResult; }

    errors {
        #[doc = "Unsupported saltpack version. Data: (major, minor)"]
        UnsupportedSaltpackVersion(major: u64, minor: u64) {
            description("Unsupported saltpack version.")
            display("Unsupported saltpack version {}.{}", major, minor)
        }

        #[doc = "Unsupported saltpack mode. Data: (mode identifier)"]
        UnknownMode(mode: u64) {
            description("Unsupported saltpack mode.")
            display("Unsupported saltpack mode: Got mode identifier {}", mode)
        }

        #[doc = "Saltpack binary format could not been parsed. Detailed error message is chained."]
        NotWellFormed {
            description("Saltpack binary format could not been parsed.")
        }

        #[doc = "The message has not been encrypted for the given private key."]
        YouAreNotOneOfTheRecipients {
            description("The message has not been encrypted for the given private key.")
        }

        #[doc = "One of the payload packets couldn't be verified."]
        PayloadPacketVerificationError {
            description("One of the payload packets couldn't be verified.")
        }

        #[doc = "One of the payload packets couldn't be decrypted."]
        PayloadDecryptionError {
            description("One of the payload packets couldn't be decrypted.")
        }

        #[doc = "Message has been truncated."]
        MessageTruncatedError {
            description("Message has been truncated.")
        }

        #[doc = "Stream ended unexpectedly."]
        EOFOccured {
            description("Stream ended unexpectedly.")
        }
    }

    foreign_links {
        MsgPackDecode(::rmpv::decode::Error) #[doc = "Foreign error: rmpv::decode::Error"];
    }
}
