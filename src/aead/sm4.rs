use crate::aead::aes::Counter;
use crate::aead::auth_error::AuthError;
use crate::aead::overlapping::Overlapping;
use crate::aead::{Aad, KeyInner, Nonce, Tag};
use crate::error::InputTooLongError;
use crate::{bb, cpu, error};
use alloc::vec::Vec;
use libsm::sm4::cipher_mode::{CipherMode, Sm4CipherMode};

const KEY_LEN: usize = 16;

#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    fn from(value: &[u8]) -> Self {
        let mut ret = Key([0; KEY_LEN]);
        ret.0.copy_from_slice(value);
        ret
    }

    fn value(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub(crate) fn init_key(
    key: &[u8],
    _cpu_features: cpu::Features,
) -> Result<KeyInner, error::Unspecified> {
    Ok(KeyInner::SM4GCM(Key::from(key)))
}

pub(crate) fn sm4_gcm_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    _cpu_features: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    let sm4_key = match key {
        KeyInner::SM4GCM(key) => key,
        _ => unreachable!(),
    };
    seal_fallback(sm4_key, nonce, aad, in_out)
}

pub(crate) fn sm4_gcm_open<'o>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out_raw: Overlapping<'o, u8>,
    received_tag: &Tag,
    _cpu_features: cpu::Features,
) -> Result<&'o mut [u8], AuthError> {
    let sm4_key = match key {
        KeyInner::SM4GCM(key) => key,
        _ => unreachable!(),
    };
    let in_data = in_out_raw.input();
    let in_len = in_data.len();
    let mut tag = [0; 16];
    tag.copy_from_slice(&in_data[in_len - 16..]);
    let calculated_tag = Tag(tag);
    bb::verify_slices_are_equal(calculated_tag.as_ref(), received_tag.as_ref())
        .map_err(|_| AuthError::new(in_len))?;
    let out_data = open_fallback(sm4_key, nonce, aad, in_data)?;
    let out = in_out_raw.into_unwritten_output();
    out.copy_from_slice(&out_data);
    Ok(out)
}

#[inline(always)]
fn seal_fallback(
    key: &Key,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, InputTooLongError> {
    let in_len = in_out.len();
    let mut counter = Counter::one(nonce);
    let sm4cm = Sm4CipherMode::new(key.value(), CipherMode::Gcm)
        .map_err(|_| InputTooLongError::new(in_len))?;
    let in_data = in_out.to_vec();

    let mut tag = [0; 16];
    let out = sm4cm
        .encrypt(&aad, &in_data, counter.increment().as_ref())
        .map_err(|_| InputTooLongError::new(in_len))?;
    in_out.copy_from_slice(&out[..out.len() - 16]);
    tag.copy_from_slice(&out[out.len() - 16..]);
    Ok(Tag(tag))
}

#[inline(always)]
fn open_fallback(
    key: &Key,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    input: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let in_len: usize = input.len();
    let mut counter = Counter::one(nonce);
    let sm4cm =
        Sm4CipherMode::new(key.value(), CipherMode::Gcm).map_err(|_| AuthError::new(in_len))?;

    let out = sm4cm
        .decrypt(&aad, &input, counter.increment().as_ref())
        .unwrap();
    Ok(out)
}
