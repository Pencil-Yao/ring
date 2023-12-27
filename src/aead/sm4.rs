use crate::aead::block::Block;
use crate::aead::{Aad, KeyInner, Nonce, Tag};
use crate::endian::BigEndian;
use crate::polyfill::ArraySplitMap;
use crate::{aead, cpu, error};
use core::ops::RangeFrom;
use libsm::sm4::cipher_mode::{CipherMode, Sm4CipherMode};

const KEY_LEN: usize = 16;

/// SM4 with gcm mod
pub static SM4_GCM: aead::Algorithm = aead::Algorithm {
    key_len: 16,
    init: init_key,
    seal: sm4_gcm_seal,
    open: sm4_gcm_open,
    id: aead::AlgorithmID::SM4_GCM,
    max_input_len: super::max_input_len(16, 2),
};

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

fn init_key(key: &[u8], _cpu_features: cpu::Features) -> Result<KeyInner, error::Unspecified> {
    Ok(KeyInner::SM4GCM(Key::from(key)))
}

fn sm4_gcm_seal(key: &KeyInner, nonce: Nonce, aad: Aad<&[u8]>, in_out: &mut [u8]) -> Tag {
    exec(key, nonce, aad, in_out, Direction::Sealing)
}

fn sm4_gcm_open(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
) -> Tag {
    exec(
        key,
        nonce,
        aad,
        in_out,
        Direction::Opening {
            in_prefix_len: src.start,
        },
    )
}

#[inline(always)] // Statically eliminate branches on `direction`.
fn exec(
    key: &KeyInner,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_out: &mut [u8],
    direction: Direction,
) -> Tag {
    let sm4_key = match key {
        KeyInner::SM4GCM(key) => key,
        _ => unreachable!(),
    };

    let mut counter = Counter::one(nonce);
    let sm4cm = Sm4CipherMode::new(sm4_key.value(), CipherMode::Gcm).unwrap();
    let in_data = in_out.to_vec();

    let mut tag = [0; 16];
    match direction {
        Direction::Opening { in_prefix_len } => {
            tag.copy_from_slice(&in_out[in_out.len() - 16..]);
            let out = sm4cm
                .decrypt(
                    &aad,
                    &in_data,
                    counter.increment().into_block_less_safe().as_ref(),
                )
                .unwrap();
            in_out[..out.len() - in_prefix_len].copy_from_slice(&out[in_prefix_len..]);
            Tag(tag)
        }
        Direction::Sealing => {
            let out = sm4cm
                .encrypt(
                    &aad,
                    &in_data,
                    counter.increment().into_block_less_safe().as_ref(),
                )
                .unwrap();
            in_out.copy_from_slice(&out[..out.len() - 16]);
            tag.copy_from_slice(&out[out.len() - 16..]);
            Tag(tag)
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Opening { in_prefix_len: usize },
    Sealing,
}

/// Nonce || Counter, all big-endian.
#[repr(transparent)]
pub(super) struct Counter([BigEndian<u32>; 4]);

impl Counter {
    pub fn one(nonce: Nonce) -> Self {
        let [n0, n1, n2] = nonce.as_ref().array_split_map(BigEndian::<u32>::from);
        Self([n0, n1, n2, 1.into()])
    }

    pub fn increment(&mut self) -> Iv {
        let iv: [[u8; 4]; 4] = self.0.map(Into::into);
        let iv = Iv(Block::from(iv));
        self.increment_by_less_safe(1);
        iv
    }

    fn increment_by_less_safe(&mut self, increment_by: u32) {
        let old_value: u32 = self.0[3].into();
        self.0[3] = (old_value + increment_by).into();
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv(Block);

impl From<Counter> for Iv {
    fn from(counter: Counter) -> Self {
        let iv: [[u8; 4]; 4] = counter.0.map(Into::into);
        Self(Block::from(iv))
    }
}

impl Iv {
    /// "Less safe" because it defeats attempts to use the type system to prevent reuse of the IV.
    #[inline]
    pub(super) fn into_block_less_safe(self) -> Block {
        self.0
    }
}
