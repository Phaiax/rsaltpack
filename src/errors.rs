

macro_rules! error_chain_option_ext {
    ( $error:ident, $errorkind:ident, $optionext:ident ) => (
        /// Additional methods for `Option`, for easy interaction with error_chain.
        pub trait $optionext<T> {
            /// If the `Option` is an `None` then `chain_err` evaluates the closure,
            /// which returns *some type that can be converted to `ErrorKind`*.
            fn chain_err<F, EK>(self, callback: F) -> ::std::result::Result<T, $error>
            where
                F: FnOnce() -> EK,
                EK: Into<$errorkind>;
        }

        impl<T> $optionext<T> for ::std::option::Option<T>
        {
            fn chain_err<F, EK>(self, callback: F) -> ::std::result::Result<T, $error>
            where
                F: FnOnce() -> EK,
                EK: Into<$errorkind>,
            {
                self.ok_or_else(move || $error::from_kind(callback().into()))
            }
        }
    );
}


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
