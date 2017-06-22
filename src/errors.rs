





error_chain!{
    types { Error, ErrorKind, ResultExt, Result; }

    errors {
        #[doc = "The base62 encoding of the armored saltpack is corrupted."]
        BadArmor {
            description("The base62 encoding of the armored saltpack is corrupted.")
        }

        #[doc = "Invalid char in vendor string. Data: (invalid_char, received_vendor_string)"]
        BadVendorString(c: char, vendor: String) {
            description("Invalid char in vendor string. (BEGIN _ SALTPACK ...)")
            display("Invalid char {} in vendor string {}.", c, vendor)
        }
    }

    links {
        Key(::key::errors::KeyError, ::key::errors::KeyErrorKind)
        #[doc = "Error related to key parsing."];

        Parse(::parse::errors::ParseError, ::parse::errors::ParseErrorKind)
        #[doc = "Error related to saltpack parsing."];
    }
}
