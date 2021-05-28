use std::path::Path;
use sled::Db;
use rac::{Array, generic_array::typenum};
use vru_session::handshake::{SecretKey, PublicKey};

pub struct Database {
    db: Db,
}

impl Database {
    pub fn open<P>(path: P) -> sled::Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(Database {
            db: sled::open(path)?,
        })
    }

    pub fn key_or_insert<F>(&self, randomize: F) -> sled::Result<(PublicKey, SecretKey)>
    where
        F: FnOnce(&mut Array<typenum::U96>),
    {
        let mut s = Array::default();
        if let Some(kp) = self.db.get(b"key_seed")? {
            s.clone_from_slice(kp.as_ref());
        } else {
            randomize(&mut s);
            self.db.insert(b"key_seed", s.as_ref())?;
        }
        Ok(PublicKey::gen(&s))
    }
}
