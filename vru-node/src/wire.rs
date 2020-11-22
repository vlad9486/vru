// usually mtu bigger or equal 1492
// maximal size of ip header is 60
// maximal size of tcp header is 60
// let's reserve some space for encapsulated protocols if any,
// round packet size to 1280
// size of message authentication code is 16
// size of payload of one packet is 1280 - 16 = 1264

use std::{ops::Add, io};
use rac::generic_array::{GenericArray, typenum};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vru_transport::protocol::SimpleUnidirectional as Cipher;
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

impl Message {
    pub async fn read<T>(cipher: &mut Cipher, stream: &mut T) -> Result<Self, io::Error>
    where
        T: Unpin + AsyncReadExt,
    {
        let packet = utils::read_ciphered::<_, Packet>(cipher, stream).await?;
        let mut pos = packet.as_slice();

        let discriminant = read_safe!(&mut pos, 1)?[0];
        match discriminant {
            0 => {
                let size = u32::from_be_bytes(read_safe!(&mut pos, 4)?) as usize;
                let mut arbitrary = vec![0; size];
                if size <= pos.len() {
                    arbitrary.clone_from_slice(&pos[..size]);
                } else {
                    arbitrary[0..pos.len()].clone_from_slice(pos);
                    let remaining = 16 + size - pos.len();
                    let round = (((remaining - 1) / FULL_PACKET_SIZE) + 1) * FULL_PACKET_SIZE;
                    let skip = round - remaining;
                    arbitrary.resize(size + skip, 0);
                    utils::read_all(cipher, stream, &mut arbitrary[pos.len()..]).await?;
                    arbitrary.resize(size, 0);
                }
                Ok(Message::Arbitrary(arbitrary))
            },
            1 => {
                let size = u32::from_be_bytes(read_safe!(&mut pos, 4)?) as usize;
                let mut invoices = Vec::with_capacity(size);
                // TODO:
                let _ = &mut invoices;
                Ok(Message::Invoices(invoices))
            },
            2 => Ok(Message::Contract(Contract {
                invoice_id: read_safe!(&mut pos, 32)?,
                timestamp: u64::from_be_bytes(read_safe!(&mut pos, 8)?),
                issuer_signature_elliptic: read_safe!(&mut pos, 64)?,
                issuer_signature: {
                    let mut buffer = [0; PACKET_SIZE + FULL_PACKET_SIZE];
                    utils::read_all(cipher, stream, buffer.as_mut()).await?;

                    let mut signature = [0; 2701];
                    let p = pos.len();
                    signature[..p].clone_from_slice(pos);
                    signature[p..].clone_from_slice(&buffer[0..(2701 - p)]);
                    signature
                },
            })),
            3 => Ok(Message::Close(read_safe!(&mut pos, 32)?)),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "Cannot decode message, bad tag",
            )),
        }
    }

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
