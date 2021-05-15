use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

pub struct Datagram([u8; Self::SIZE]);

impl Default for Datagram {
    fn default() -> Self {
        Datagram([0; Self::SIZE])
    }
}

impl AsRef<[u8]> for Datagram {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Datagram {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Datagram {
    pub const SIZE: usize = 1280;

    pub fn link(&self) -> LinkToken {
        let mut token = LinkToken([0; 16]);
        token.0.clone_from_slice(&self.0[..16]);
        token
    }
}

#[derive(Hash, Eq, PartialEq)]
pub struct LinkToken([u8; 16]);

impl Distribution<LinkToken> for Standard {
    fn sample<R>(&self, rng: &mut R) -> LinkToken
    where
        R: Rng + ?Sized,
    {
        let mut token = LinkToken([0; 16]);
        rng.fill(token.0.as_mut());
        token
    }
}
