use tirse::{
    BinarySerializer, BinarySerializerDelegate, WriteWrapper, ErrorAdapter, IoError,
    BinaryDeserializer, BinaryDeserializerDelegate, BinaryDeserializerError, ReadWrapper,
};
use byteorder::{ByteOrder, BigEndian};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use either::Either;
use std::io;

struct BDelegate;

impl BinarySerializerDelegate for BDelegate {
    type Variant = u16;
    type Length = u16;
    type SequenceLength = ();
    type Char = u32;

    fn encode_variant(v: u32) -> Self::Variant {
        v as _
    }

    fn encode_length(v: usize) -> Self::Length {
        v as _
    }

    fn encode_sequence_length(v: usize) -> Self::SequenceLength {
        let _ = v;
        ()
    }

    fn encode_char(v: char) -> Self::Char {
        v as _
    }
}

impl BinaryDeserializerDelegate for BDelegate {
    type SmallBuffer = [u8; 8];

    fn variant_size() -> usize {
        core::mem::size_of::<u16>()
    }

    fn length_size() -> usize {
        core::mem::size_of::<u16>()
    }

    fn sequence_length_size() -> usize {
        0
    }

    fn char_size() -> usize {
        core::mem::size_of::<u32>()
    }

    fn decode_variant<E>(bytes: &[u8]) -> u32
    where
        E: ByteOrder,
    {
        E::read_u16(bytes) as _
    }

    fn decode_length<E>(bytes: &[u8]) -> usize
    where
        E: ByteOrder,
    {
        match Self::length_size() {
            8 => E::read_u64(bytes) as usize,
            4 => E::read_u32(bytes) as usize,
            _ => E::read_u16(bytes) as usize,
        }
    }

    fn decode_sequence_length<E>(bytes: &[u8]) -> Option<usize>
    where
        E: ByteOrder,
    {
        let _ = bytes;
        None
    }

    fn decode_char<E>(bytes: &[u8]) -> Result<char, u32>
    where
        E: ByteOrder,
    {
        let code = E::read_u32(bytes);
        core::char::from_u32(code).ok_or(code)
    }
}

type BSerializer<W> = BinarySerializer<WriteWrapper<W>, BigEndian, BDelegate, String>;
type BDeserializer<'de, R> = BinaryDeserializer<'de, R, BigEndian, BDelegate, String>;
pub type BDeserializerError<E> = ErrorAdapter<Either<BinaryDeserializerError, E>, String>;

pub fn serialize_into_slice<T, B>(v: &T, buffer: &mut B)
where
    T: Serialize,
    B: AsMut<[u8]>,
{
    let serializer = BSerializer::new(io::Cursor::new(buffer.as_mut()));
    v.serialize(serializer).unwrap();
}

pub fn serialize_into_vec<T>(v: &T) -> Vec<u8>
where
    T: Serialize,
{
    let mut buffer = Vec::new();
    let serializer = BSerializer::new(&mut buffer);
    v.serialize(serializer).unwrap();
    buffer
}

pub fn deserialize_from_slice<'de, T, B>(buffer: &'de B) -> Result<T, BDeserializerError<IoError>>
where
    T: Deserialize<'de>,
    B: AsRef<[u8]>,
{
    let deserializer = BDeserializer::new(buffer.as_ref().iter());
    T::deserialize(deserializer)
}

pub fn deserialize_from_reader<T, R>(read: R) -> Result<T, BDeserializerError<io::Error>>
where
    T: DeserializeOwned,
    R: io::Read,
{
    let deserializer = BDeserializer::new(ReadWrapper::from(read));
    T::deserialize(deserializer)
}
