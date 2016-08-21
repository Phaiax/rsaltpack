//! Sign data
//!
//!

use ::key::SigningKeyPair;

use sodiumoxide::randombytes::randombytes_into;
//use sodiumoxide::crypto::sign::SIGNEDMESSAGE

use serde::Serialize;
use serde::bytes::ByteBuf;
use rmp_serde::Serializer;

/// [format name, version, mode, sender public key, nonce, ]
#[derive(Serialize, PartialEq, Debug)]
struct HeaderSerializable(String, (u32, u32), u32, ByteBuf, ByteBuf, );
/// [signature, payload chunk, ]
#[derive(Serialize, PartialEq, Debug)]
struct PayloadPacketSerializable(ByteBuf, ByteBuf);


struct Nonce ( [u8; 32] );
impl Nonce {
    fn make_rand() -> Self {
        let mut n = Nonce ( [0; 32] );
        randombytes_into(&mut n[..]);
        n
    }
}

/// Main interface to create new saltpacks.
pub struct Saltpack {
    sender : SigningKeyPair,
    nonce : Nonce,
    header_hash : Option<Vec<u8>>,

    input_buffer : VecDeque<Vec<u8>>,
    next_packet_number : u64,

    output_buffer : VecDeque<Vec<u8>>,
}

impl Saltpack {
    pub fn sign(sender : SigningKeyPair) -> Saltpack {
        let mut new_saltpack = Saltpack {
            sender : sender,
            nonce : Nonce::make_rand(),
            header_hash : None,

            next_packet_number : 0,

            output_buffer : VecDeque::with_capacity(10),
        }
        new_saltpack.compose_saltpack_header();
        new_saltpack
    }

    fn compose_saltpack_header(&mut self) {

        // As in the encryption spec, the header packet is serialized into a MessagePack array object, hashed with SHA512 to produce the header hash, and then serialized again into a MessagePack bin object.
        // -> ENC5 ENC6 ENC7 ENC8

        // ENC5 Collect the format name, version, and mode into a list, followed by ...
        let mode = SaltpackMessageType::SIGNEDMESSAGE;
        let header = HeaderSerializable ( "saltpack".to_string(),
                                          (1, 0),
                                          mode.to_int(),
                                          ByteBuf::from(Vec::from(&self.sender.p.0[..])),
                                          ByteBuf::from(Vec::from(&self.nonce.0[..])));

        // ENC6 Serialize the list from #5 into a MessagePack array object.
        // estimate buf size
        let bufsize = size_of::<HeaderSerializable>()
                        + header.0.len()
                        + header.3.len()
                        + header.4.len()
                        + 3*8; // backup
        let mut header_inner_messagepack = Vec::<u8>::with_capacity(bufsize);

        header.serialize(&mut Serializer::new(&mut header_inner_messagepack)).unwrap();

        // ENC7 Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.
        let headerhash = hash(&header_inner_messagepack[..]);
        self.header_hash = Some(Vec::from(&headerhash.0[..]));

        // ENC8 Serialize the bytes from #6 again into a MessagePack bin object. These twice-encoded bytes are the header packet.
        let mut header_outer_messagepack = Vec::with_capacity(header_inner_messagepack.len() + 10);
        ByteBuf::from(header_inner_messagepack).serialize(&mut Serializer::new(&mut header_outer_messagepack)).unwrap();
        self.output_buffer.push_back(header_outer_messagepack);

    }

    fn encrypt_next_packet(&mut self) -> bool {
        // To make each signature, the sender first takes the SHA512 hash of the concatenation of three values:
        //      the header hash from above
        //      the packet sequence number, as a 64-bit big-endian unsigned integer, where the first payload packet is zero
        //      the payload chunk

        let mut cat = Vec::with_capacity( self.header_hash.as_ref().unwrap().len()
                                          + 8
                                          + secretbox_payload.len());
        cat.extend_from_slice(&self.header_hash.as_ref().unwrap()[..]);
        cat.extend_from_slice(&nonce.0[..]);
        cat.extend_from_slice(&secretbox_payload[..]);


    }


}