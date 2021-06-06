use vru_session::handshake::Identity;

pub struct Signature {
    pub lattice: [u8; 3293],
    pub elliptic: [u8; 64],
}

pub struct Invoice {
    pub id: [u8; 32],
    pub broadcast_level: u8,
    pub quantity: Vec<u8>,
    pub currency: Vec<u8>,
}

pub struct Commitment {
    pub timestamp: u64,
    pub id: [u8; 32],
    pub signature: Signature,
}

pub struct Contract {
    pub id: [u8; 32],
    pub obligor: Identity,
    pub creditor: Identity,
    pub timestamp: u64,
    pub balance: Vec<u8>,
    pub currency: Vec<u8>,
}

pub struct Signed {
    pub contract: Contract,
    pub signature: Signature,
}

pub struct Settled {
    pub contract: Contract,
    pub signature: Signature,
    pub secret: [u8; 32],
}

impl Contract {
    pub fn new(me: Identity, peer: Identity) -> Self {
        Contract {
            id: [0; 32],
            obligor: me,
            creditor: peer,
            timestamp: 0,
            balance: Vec::new(),
            currency: Vec::new(),
        }
    }
}
