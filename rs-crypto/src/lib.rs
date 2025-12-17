#![allow(unsafe_op_in_unsafe_fn)]
use libc;
use rand::rngs::OsRng;
use xeddsa::{
    Sign, Verify,
    xed25519::{PrivateKey, PublicKey},
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xeddsa_sign(
    sk_buf: *const u8,
    msg_buf: *const u8,
    msg_len: usize,
) -> *mut u8 {
    let sig_buf = libc::malloc(64) as *mut u8;
    if sig_buf.is_null() {
        return std::ptr::null_mut();
    }

    let sk_bytes = &*(sk_buf as *const [u8; 32]);
    let msg_bytes = std::slice::from_raw_parts(msg_buf, msg_len);

    let sk = PrivateKey::from(sk_bytes);
    let sig: [u8; 64] = sk.sign(msg_bytes, OsRng);

    libc::memcpy(
        sig_buf as *mut libc::c_void,
        sig.as_ptr() as *const libc::c_void,
        64,
    );

    sig_buf
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xeddsa_verify(
    pk_buf: *const u8,
    msg_buf: *const u8,
    msg_len: usize,
    sig_buf: *const u8,
) -> bool {
    let pk_bytes = *(pk_buf as *const [u8; 32]);
    let msg_bytes = std::slice::from_raw_parts(msg_buf, msg_len);
    let sig_bytes = &*(sig_buf as *const [u8; 64]);

    let pk = PublicKey::from(&x25519_dalek::PublicKey::from(
        &x25519_dalek::StaticSecret::from(pk_bytes),
    ));

    let valid = pk.verify(msg_bytes, sig_bytes);

    valid.is_ok()
}
