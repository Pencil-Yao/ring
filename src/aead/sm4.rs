use crate::aead::block::Block;
use crate::aead::quic::Sample;
use crate::aead::{Aad, KeyInner, Nonce, Tag};
use crate::endian::BigEndian;
use crate::polyfill::ArraySplitMap;
use crate::{aead, cpu, error};
use core::ops::RangeFrom;
use libsm::sm4::cipher_mode::{CipherMode, Sm4CipherMode};

const KEY_LEN: usize = 16;

/// SM4 with cfb mod
pub static SM4_CFB: aead::Algorithm = aead::Algorithm {
    key_len: 16,
    init: init_key,
    seal: sm4_cfb_seal,
    open: sm4_cfb_open,
    id: aead::AlgorithmID::SM4_CFB,
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
    Ok(KeyInner::SM4CFB(Key::from(key)))
}

fn sm4_cfb_seal(key: &KeyInner, nonce: Nonce, aad: Aad<&[u8]>, in_out: &mut [u8]) -> Tag {
    exec(key, nonce, aad, in_out, Direction::Sealing)
}

fn sm4_cfb_open(
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
    Aad(_aad): Aad<&[u8]>,
    in_out: &mut [u8],
    direction: Direction,
) -> Tag {
    let sm4_key = match key {
        KeyInner::SM4CFB(key) => key,
        _ => unreachable!(),
    };

    let mut counter = Counter::one(nonce);
    let tag_iv = counter.increment();
    let sm4cm = Sm4CipherMode::new(sm4_key.value(), CipherMode::Cfb).unwrap();
    let in_data = in_out.to_vec();

    match direction {
        Direction::Opening { in_prefix_len } => {
            in_out[in_prefix_len..].copy_from_slice(
                sm4cm
                    .decrypt(
                        &in_data,
                        counter.increment().into_block_less_safe().as_ref(),
                    )
                    .unwrap()
                    .as_slice(),
            );
        }
        Direction::Sealing => in_out.copy_from_slice(
            sm4cm
                .encrypt(
                    &in_data,
                    counter.increment().into_block_less_safe().as_ref(),
                )
                .unwrap()
                .as_slice(),
        ),
    }
    let block = tag_iv.into_block_less_safe();
    Tag(*block.as_ref())
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
