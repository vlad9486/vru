use vru_noise_macros::Handshake;
use crate as vru_noise;

pub type IK<A, P0, P1> = Handshake![ A,
    "<- s",
    "-> e, es, S, ss" P0,
    "<- e, ee, se" P1,
];

pub type IKpsk1<A, P0, P1> = Handshake![ A,
    "<- s",
    "-> e, es, S, ss, psk" P0,
    "<- e, ee, se" P1,
];

pub type XK<A, P0, P1, P2> = Handshake![ A,
    "<- s",
    "-> e, es" P0,
    "<- e, ee" P1,
    "-> S, se" P2,
];
