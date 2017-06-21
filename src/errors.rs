

error_chain!{

    errors {
        #[doc="The base62 encoding of the armored saltpack is corrupted."]
        BadArmor {
            description("The base62 encoding of the armored saltpack is corrupted.")
        }
        #[doc="Invalid char in vendor string. Data: (invalid_char, received_vendor_string)"]
        BadVendorString(c : char, vendor: String) {
            description("Invalid char in vendor string. (BEGIN _ SALTPACK ...)")
            display("Invalid char {} in vendor string {}.", c, vendor)
        }
        #[doc="String has wrong length. Data: (received_len)"]
        KeybaseKeyWrongLength(length : usize) {
            description("String has wrong length. \
                Keybase formated keys have a length of 70 chars.")
            display("String has wrong length. \
                Expected 70 chars but got {} chars.", length)
        }
        #[doc="Given string is not a keybase public key."]
        KeybaseKeyNotAPublicKey {
            description("Given string is not a keybase public key. \
                Keybase formated keys end with `0a`.")
        }
        #[doc="Unsupported keybase key version. Data: (received_version)"]
        KeybaseKeyUnsupportedVersion(v: String) {
            description("Unsupported keybase key version.")
            display("Unsupported keybase key version. Got version {}.", v)
        }
        #[doc="Given key is not a encryption key"]
        KeybaseKeyNotAnEncryptionKey {
            description("Given key is not an encryption key. \
                Keybase encryption keys start with `0121`.")
        }
        #[doc="Given key is not a signing key"]
        KeybaseKeyNotASigningKey {
            description("Given key is not a signing key. \
                Keybase signing keys start with `0120`.")
        }
        #[doc = "Wrong Length. Data: (keytype, received_len, expected_len)"]
        RawHexEncodedKeyWrongLength(type_: String, got: usize, expected: usize) {
            description("Hex encoded key has wrong length.")
            display("Hex encoded {} key has wrong length. \
                Expected {} chars but got {} chars.", type_, expected, got)
        }
        #[doc = "Error while decoding hex encoded string."]
        CouldNotDecodeHex {
            description("Error while decoding hex encoded string. Only ascii numerals and chars from a-f are allowed.")
        }
    }
    foreign_links {

        Utf8Error(::std::str::Utf8Error) #[doc = "Foreign error: std::str::Utf8Error"];

        ParseIntError(::std::num::ParseIntError) #[doc = "Foreign error: std::num::ParseIntError"];
    }
}

