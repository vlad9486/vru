use generic_array::{GenericArray, ArrayLength, typenum};
use std::string::FromUtf8Error;

pub trait ByteSource {
    fn read<L>(&mut self) -> Result<GenericArray<u8, L>, ()>
    where
        L: ArrayLength<u8>;

    fn read_dynamic(&mut self, buffer: &mut [u8]) -> Result<(), ()>;
}

impl ByteSource for &[u8] {
    fn read<L>(&mut self) -> Result<GenericArray<u8, L>, ()>
    where
        L: ArrayLength<u8>,
    {
        if self.len() < L::USIZE {
            Err(())
        } else {
            let mut a = GenericArray::default();
            a.clone_from_slice(&self[..L::USIZE]);
            *self = &mut &self[L::USIZE..];
            Ok(a)
        }
    }

    fn read_dynamic(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        if self.len() < buffer.len() {
            Err(())
        } else {
            buffer.clone_from_slice(&self[..buffer.len()]);
            *self = &mut &self[buffer.len()..];
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Coding {
    Primitive(PrimitiveCoding),
    String,
    Array(usize, Box<Coding>),
    List(Box<Coding>),
    Option(Box<Coding>),
    Struct(Vec<(String, Coding)>),
    Enum(Vec<(u16, String, Coding)>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PrimitiveCoding {
    Unit,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    Float,
    Timestamp,
}

#[derive(Clone)]
pub enum Value {
    Primitive(PrimitiveValue),
    String(String),
    Array(Vec<Value>),
    List(Vec<Value>),
    Option(Option<Box<Value>>),
    Struct(Vec<(String, Value)>),
    Enum(u16, String, Box<Value>),
}

pub enum DecodeError {
    UnexpectedEnd(()),
    Utf8(FromUtf8Error),
    UnknownTag,
}

impl Value {
    pub fn decode<B>(data: &mut B, coding: &Coding) -> Result<Self, DecodeError>
    where
        B: ByteSource,
    {
        match coding {
            &Coding::Primitive(ref coding) => PrimitiveValue::decode(data, coding)
                .map(Value::Primitive)
                .map_err(DecodeError::UnexpectedEnd),
            &Coding::String => {
                let length = data.read()
                    .map(|a| u32::from_be_bytes(a.into()) as usize)
                    .map_err(DecodeError::UnexpectedEnd)?;
                let mut buffer = Vec::with_capacity(length);
                data.read_dynamic(buffer.as_mut())
                    .map_err(DecodeError::UnexpectedEnd)?;
                String::from_utf8(buffer)
                    .map(Value::String)
                    .map_err(DecodeError::Utf8)
            },
            &Coding::Array(length, ref coding) => {
                (0..length)
                    .try_fold(Vec::with_capacity(length), |mut v, _| {
                        Self::decode(data, coding)
                            .map(|value| {
                                v.push(value);
                                v
                            })
                    })
                    .map(Value::Array)
            },
            &Coding::List(ref coding) => {
                let length = data.read()
                    .map(|a| u32::from_be_bytes(a.into()) as usize)
                    .map_err(DecodeError::UnexpectedEnd)?;
                Self::decode(data, &Coding::Array(length, coding.clone()))
            },
            &Coding::Option(ref coding) => {
                let tag = data.read::<typenum::U1>()
                    .map(|a| a[0] == 0xff)
                    .map_err(DecodeError::UnexpectedEnd)?;
                if tag {
                     Self::decode(data, coding)
                        .map(|v| Value::Option(Some(Box::new(v))))
                } else {
                    Ok(Value::Option(None))
                }
            },
            &Coding::Struct(ref scheme) => {
                scheme.iter()
                    .try_fold(Vec::with_capacity(scheme.len()), |mut v, &(ref name, ref coding)| {
                        Self::decode(data, coding)
                            .map(|value| {
                                v.push((name.clone(), value));
                                v
                            })
                    })
                    .map(Value::Struct)
            },
            &Coding::Enum(ref tags) => {
                let target_id = data.read()
                    .map(|a| u16::from_be_bytes(a.into()))
                    .map_err(DecodeError::UnexpectedEnd)?;
                if let Some((id, name, coding)) = tags.iter().find(|&x| target_id == x.0) {
                    Self::decode(data, coding)
                        .map(|value| Value::Enum(id.clone(), name.clone(), Box::new(value)))
                } else {
                    Err(DecodeError::UnknownTag)
                }
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use std::iter;

        fn encode_iter<'a, I>(it: I) -> Vec<u8> 
        where
            I: Iterator<Item = &'a Value>,
        {
            it.fold(Vec::new(), |mut v, value| {
                v.append(&mut value.encode());
                v
            })
        }

        match self {
            &Value::Primitive(ref primitive_value) => primitive_value.encode(),
            &Value::String(ref string) => {
                let buffer = string.as_bytes();
                let mut v = vec![0; 4 + buffer.len()];
                v[0..4].clone_from_slice((buffer.len() as u32).to_be_bytes().as_ref());
                v[4..].clone_from_slice(buffer);
                v
            },
            &Value::Array(ref array) => encode_iter(array.iter()),
            &Value::List(ref list) => {
                let length = Value::Primitive(PrimitiveValue::U32(list.len() as u32));
                encode_iter(iter::once(&length).chain(list.iter()))
            },
            &Value::Option(None) => Value::Primitive(PrimitiveValue::Bool(false)).encode(),
            &Value::Option(Some(ref value)) => {
                let tag = Value::Primitive(PrimitiveValue::Bool(true));
                encode_iter(iter::once(&tag).chain(iter::once(value.as_ref())))
            },
            &Value::Struct(ref fields) => encode_iter(fields.iter().map(|&(_, ref value)| value)),
            &Value::Enum(ref id, _, ref value) => {
                let tag = Value::Primitive(PrimitiveValue::U16(id.clone()));
                encode_iter(iter::once(&tag).chain(iter::once(value.as_ref())))
            },
        }
    }    
}

#[derive(Clone)]
pub enum PrimitiveValue {
    Unit(()),
    Bool(bool),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Float(f64),
    Timestamp(i64),
}

impl PrimitiveValue {
    pub fn decode<B>(data: &mut B, coding: &PrimitiveCoding) -> Result<Self, ()>
    where
        B: ByteSource,
    {
        match coding {
            &PrimitiveCoding::Unit => Ok(PrimitiveValue::Unit(())),
            &PrimitiveCoding::Bool => data.read::<typenum::U1>()
                .map(|a| PrimitiveValue::Bool(a[0] == 0xff)),
            &PrimitiveCoding::I8 => data.read::<typenum::U1>()
                .map(|a| PrimitiveValue::I8(a[0] as i8)),
            &PrimitiveCoding::U8 => data.read::<typenum::U1>()
                .map(|a| PrimitiveValue::U8(a[0] as u8)),
            &PrimitiveCoding::I16 => data.read()
                .map(|a| PrimitiveValue::I16(i16::from_be_bytes(a.into()))),
            &PrimitiveCoding::U16 => data.read()
                .map(|a| PrimitiveValue::U16(u16::from_be_bytes(a.into()))),
            &PrimitiveCoding::I32 => data.read()
                .map(|a| PrimitiveValue::I32(i32::from_be_bytes(a.into()))),
            &PrimitiveCoding::U32 => data.read()
                .map(|a| PrimitiveValue::U32(u32::from_be_bytes(a.into()))),
            &PrimitiveCoding::I64 => data.read()
                .map(|a| PrimitiveValue::I64(i64::from_be_bytes(a.into()))),
            &PrimitiveCoding::U64 => data.read()
                .map(|a| PrimitiveValue::U64(u64::from_be_bytes(a.into()))),
            &PrimitiveCoding::Float => data.read()
                .map(|a| PrimitiveValue::Float(f64::from_be_bytes(a.into()))),
            &PrimitiveCoding::Timestamp => data.read()
                .map(|a| PrimitiveValue::Timestamp(i64::from_be_bytes(a.into()))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            &PrimitiveValue::Unit(()) => Vec::new(),
            &PrimitiveValue::Bool(v) => [if v { 0xff } else { 0x00 }].to_vec(),
            &PrimitiveValue::I8(v) => [v as u8].to_vec(),
            &PrimitiveValue::U8(v) => [v].to_vec(),
            &PrimitiveValue::I16(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::U16(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::I32(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::U32(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::I64(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::U64(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::Float(v) => v.to_be_bytes().to_vec(),
            &PrimitiveValue::Timestamp(v) => v.to_be_bytes().to_vec(),
        }
    } 
}
