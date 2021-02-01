// usually mtu bigger or equal 1492
// maximal size of ip header is 60
// maximal size of tcp header is 60
// let's reserve some space for encapsulated protocols if any,
// round packet size to 1280
// size of message authentication code is 16
// size of payload of one packet is 1280 - 16 = 1264

use std::{ops::Add, io};
use rac::generic_array::{GenericArray, ArrayLength, typenum};
use bytes::{BytesMut, Buf};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Decoder;
use vru_transport::protocol::TrivialUnidirectional as Cipher;
use super::utils;

type Packet = GenericArray<u8, <typenum::U1024 as Add<typenum::U240>>::Output>;
const PACKET_SIZE: usize = 1264;
const FULL_PACKET_SIZE: usize = 1280;

pub enum Message {
    Arbitrary(Vec<u8>),
    Invoices(Vec<Invoice>),
    Contract(Contract),
    Close([u8; 32]),
}

pub struct Invoice {
    pub invoice_id: [u8; 32],
    pub value: u64,
    pub currency: [u8; 8],
    pub deepness: u8,
}

pub struct Contract {
    pub invoice_id: [u8; 32],
    pub timestamp: u64,
    pub issuer_signature_elliptic: [u8; 64],
    pub issuer_signature: [u8; 2701],
}

macro_rules! read_safe {
    ($slice:expr, $length:expr) => {{
        if $slice.len() >= $length {
            let mut buffer = [0; $length];
            buffer.clone_from_slice(&$slice[0..$length]);
            *$slice = &$slice[$length..];
            Ok(buffer)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Unexpected end"))
        }
    }};
}

pub enum DecoderError {
    Io(io::Error),
    MacMismatch,
    BadTag,
}

impl From<io::Error> for DecoderError {
    fn from(e: io::Error) -> Self {
        DecoderError::Io(e)
    }
}

pub struct MessageDecoder {
    cipher: Cipher,
    header: Option<Packet>,
}

impl MessageDecoder {
    pub fn new(cipher: Cipher) -> Self {
        MessageDecoder {
            cipher: cipher,
            header: None,
        }
    }
}

fn copy_array<B, L>(bytes: &mut B) -> GenericArray<u8, L>
where
    B: Buf,
    L: ArrayLength<u8>,
{
    let mut buffer = GenericArray::default();
    bytes.copy_to_slice(buffer.as_mut());
    buffer
}

impl Decoder for MessageDecoder {
    type Item = Message;
    type Error = DecoderError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(header) = self.header.take() {
            let mut pos = header.as_slice();
            let discriminant = read_safe!(&mut pos, 1)?[0];
            match discriminant {
                0 => {
                    let size = u32::from_be_bytes(read_safe!(&mut pos, 4)?) as usize;
                    let mut arbitrary = vec![0; size];
                    if size <= pos.len() {
                        arbitrary.clone_from_slice(&pos[..size]);
                        Ok(Some(Message::Arbitrary(arbitrary)))
                    } else {
                        let remaining = 16 + size - pos.len();
                        let round = (((remaining - 1) / FULL_PACKET_SIZE) + 1) * FULL_PACKET_SIZE;
                        let skip = round - remaining;
                        if src.remaining() < round {
                            self.header = Some(header);
                            Ok(None)
                        } else {
                            arbitrary.resize(size + skip, 0);
                            arbitrary[0..pos.len()].clone_from_slice(pos);
                            src.copy_to_slice(&mut arbitrary[pos.len()..]);
                            let tag = copy_array(src);
                            self.cipher
                                .decrypt(b"vru", &mut arbitrary[pos.len()..], &tag)
                                .map_err(|()| DecoderError::MacMismatch)?;
                            arbitrary.resize(size, 0);
                            Ok(Some(Message::Arbitrary(arbitrary)))
                        }
                    }
                },
                1 => {
                    // TODO:
                    Ok(Some(Message::Invoices(Vec::new())))
                },
                2 => {
                    if src.remaining() < FULL_PACKET_SIZE * 2 {
                        self.header = Some(header);
                        Ok(None)
                    } else {
                        Ok(Some(Message::Contract(Contract {
                            invoice_id: read_safe!(&mut pos, 32)?,
                            timestamp: u64::from_be_bytes(read_safe!(&mut pos, 8)?),
                            issuer_signature_elliptic: read_safe!(&mut pos, 64)?,
                            issuer_signature: {
                                let mut buffer = [0; PACKET_SIZE + FULL_PACKET_SIZE];
                                src.copy_to_slice(buffer.as_mut());
                                let tag = copy_array(src);
                                self.cipher
                                    .decrypt(b"vru", buffer.as_mut(), &tag)
                                    .map_err(|()| DecoderError::MacMismatch)?;
                                let mut signature = [0; 2701];
                                let p = pos.len();
                                signature[..p].clone_from_slice(pos);
                                signature[p..].clone_from_slice(&buffer[0..(2701 - p)]);
                                signature
                            },
                        })))
                    }
                },
                3 => Ok(Some(Message::Close(read_safe!(&mut pos, 32)?))),
                _ => Err(DecoderError::BadTag),
            }
        } else {
            if src.remaining() < FULL_PACKET_SIZE {
                Ok(None)
            } else {
                let mut packet = copy_array(src);
                let tag = copy_array(src);
                self.cipher
                    .decrypt(b"vru", packet.as_mut(), &tag)
                    .map_err(|()| DecoderError::MacMismatch)?;
                self.header = Some(packet);
                self.decode(src)
            }
        }
    }
}

impl Message {
    pub async fn write<T>(self, cipher: &mut Cipher, stream: &mut T) -> Result<(), io::Error>
    where
        T: Unpin + AsyncWriteExt,
    {
        match self {
            Message::Arbitrary(arbitrary) => {
                let mut packet = Packet::default();
                let size = arbitrary.len();
                packet[0] = 0;
                packet[1..5].clone_from_slice((size as u32).to_be_bytes().as_ref());
                if size + 5 <= PACKET_SIZE {
                    packet[5..(5 + size)].clone_from_slice(arbitrary.as_ref());
                    utils::write_ciphered(cipher, stream, packet).await?;
                } else {
                    packet[5..].clone_from_slice(&arbitrary[0..(PACKET_SIZE - 5)]);
                    utils::write_ciphered(cipher, stream, packet).await?;

                    let remaining = 16 + size - (PACKET_SIZE - 5);
                    let round = (((remaining - 1) / FULL_PACKET_SIZE) + 1) * FULL_PACKET_SIZE;
                    let skip = round - remaining;
                    let mut arbitrary = arbitrary;
                    arbitrary.resize(size + skip, 0);
                    utils::write_all(cipher, stream, &mut arbitrary[(PACKET_SIZE - 5)..]).await?;
                    arbitrary.resize(size, 0);
                }
            },
            Message::Invoices(_) => unimplemented!(),
            Message::Contract(contract) => {
                let mut packet = Packet::default();
                let mut buffer = [0; PACKET_SIZE + FULL_PACKET_SIZE];

                packet[0] = 2;
                packet[1..33].clone_from_slice(contract.invoice_id.as_ref());
                packet[33..41].clone_from_slice(contract.timestamp.to_be_bytes().as_ref());
                packet[41..105].clone_from_slice(contract.issuer_signature_elliptic.as_ref());
                packet[105..1264].clone_from_slice(&contract.issuer_signature[0..1159]);
                buffer[0..1542].clone_from_slice(&contract.issuer_signature[1159..2701]);

                utils::write_ciphered(cipher, stream, packet).await?;
                utils::write_all(cipher, stream, buffer.as_mut()).await?;
            },
            Message::Close(secret) => {
                let mut packet = Packet::default();

                packet[0] = 3;
                packet[1..33].clone_from_slice(secret.as_ref());

                utils::write_ciphered(cipher, stream, packet).await?;
            },
        }

        Ok(())
    }
}
