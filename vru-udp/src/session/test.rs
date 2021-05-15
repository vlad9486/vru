use rac::{Array, Concat, Line, LineValid, generic_array::{typenum, sequence::GenericSequence}};
use super::{PublicKey, xx, TrivialRotor};

#[test]
fn handshake() {
    let Concat(Concat(i_s_seed, i_e_seed), Concat(i_pq_s_seed, i_pq_e_seed)) =
        Line::clone_array(&Array::<typenum::U256>::generate(|i| (i ^ 0x00) as u8));
    let Concat(Concat(r_s_seed, r_e_seed), Concat(r_pq_s_seed, r_pq_e_seed)) =
        Line::clone_array(&Array::<typenum::U256>::generate(|i| (i ^ 0xff) as u8));

    let (i_pk, i_sk) = PublicKey::gen(&i_s_seed);
    let (r_pk, r_sk) = PublicKey::gen(&r_s_seed);

    let r_pi = r_pk.identity();

    let orig_p = Array::<typenum::U16>::generate(|_| 0x03);
    let payload_p = orig_p.clone();
    let orig_q = Array::<typenum::U16>::generate(|_| 0x13);
    let payload_q = orig_q.clone();
    let orig_r = Array::<typenum::U16>::generate(|_| 0x23);
    let payload_r = orig_r.clone();
    let orig_s = Array::<typenum::U16>::generate(|_| 0x33);
    let payload_s = orig_s.clone();

    let (i_state, message) = xx::out0(&i_e_seed, &r_pi);
    let (r_state, message) = xx::take0_out1(&Concat(r_e_seed, r_pq_e_seed), &r_pi, &r_pk, &r_sk, message, payload_p);
    let (i_state, rr_pk, payload_p, message) =xx::take1_out2::<Array<typenum::U16>, _, _>(&Concat(i_pq_e_seed, i_pq_s_seed), i_state, &i_pk, &i_sk, message, payload_q, payload_r).ok().unwrap();
    let (mut r_cipher, r_hash, ri_pk, payload_q, payload_r, message) = xx::take2_out3::<Array<typenum::U16>, Array<typenum::U16>, _, TrivialRotor>(&r_pq_s_seed, r_state, &r_pk, &r_sk, message, payload_s).ok().unwrap();
    let (mut i_cipher, i_hash, payload_s) = xx::take_3::<Array<typenum::U16>, TrivialRotor>(i_state, &i_pk, &i_sk, message).ok().unwrap();

    let reference_hash = "77316870c248ff7f6cb6ad95b473e46290f6945a97888892ae83dbe23fa7abe4";
    assert_eq!(reference_hash, hex::encode(&i_hash));
    assert_eq!(reference_hash, hex::encode(&r_hash));

    assert_eq!(orig_p, payload_p);
    assert_eq!(orig_q, payload_q);
    assert_eq!(orig_r, payload_r);
    assert_eq!(orig_s, payload_s);

    assert_eq!(rr_pk.compress().clone_line(), r_pk.compress().clone_line());
    assert_eq!(ri_pk.compress().clone_line(), i_pk.compress().clone_line());

    for _ in 0..16 {
        let orig = rand::random::<[u8; 32]>();
        let mut a = orig.clone();
        let tag = r_cipher.encrypt(b"vru", a.as_mut());
        i_cipher.decrypt(b"vru", a.as_mut(), &tag).unwrap();
        assert_eq!(orig, a);
    }
}
