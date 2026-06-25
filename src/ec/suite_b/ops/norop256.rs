// Copyright 2020 Yao Pengfei.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#![allow(dead_code)]

use crate::ec::suite_b::ops::sm2p256_norop::CURVE_PARAMS;
use crate::limb::{DoubleLimb, LIMB_BITS, Limb};
use core::cmp::Ordering;
use core::num::Wrapping;

struct u64pair(u64, u64);

impl u64pair {
    #[inline]
    fn new(a: u64, b: u64) -> Self {
        u64pair(a, b)
    }

    #[inline]
    fn u32_mul(a: u32, b: u32) -> Self {
        let mut v = u64::from(a) * u64::from(b);
        let u = v >> 32;
        v &= 0xffff_ffff;
        u64pair(v, u)
    }

    #[inline]
    fn pair_add(self, add_pair: Self) -> Self {
        let mut local = self.0 + add_pair.0;
        let mut carry = self.1 + add_pair.1;
        carry += local >> 32;
        local &= 0xffff_ffff;
        u64pair(local, carry)
    }
}

pub(crate) fn norop256_mul(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut res: [u32; 16] = [0; 16];

    let mut tmp_pair = u64pair::u32_mul(a[0], b[0]);
    res[0] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[1]))
        .pair_add(u64pair::u32_mul(a[1], b[0]));
    res[1] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[2]))
        .pair_add(u64pair::u32_mul(a[1], b[1]))
        .pair_add(u64pair::u32_mul(a[2], b[0]));
    res[2] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[3]))
        .pair_add(u64pair::u32_mul(a[1], b[2]))
        .pair_add(u64pair::u32_mul(a[2], b[1]))
        .pair_add(u64pair::u32_mul(a[3], b[0]));
    res[3] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[4]))
        .pair_add(u64pair::u32_mul(a[1], b[3]))
        .pair_add(u64pair::u32_mul(a[2], b[2]))
        .pair_add(u64pair::u32_mul(a[3], b[1]))
        .pair_add(u64pair::u32_mul(a[4], b[0]));
    res[4] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[5]))
        .pair_add(u64pair::u32_mul(a[1], b[4]))
        .pair_add(u64pair::u32_mul(a[2], b[3]))
        .pair_add(u64pair::u32_mul(a[3], b[2]))
        .pair_add(u64pair::u32_mul(a[4], b[1]))
        .pair_add(u64pair::u32_mul(a[5], b[0]));
    res[5] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[6]))
        .pair_add(u64pair::u32_mul(a[1], b[5]))
        .pair_add(u64pair::u32_mul(a[2], b[4]))
        .pair_add(u64pair::u32_mul(a[3], b[3]))
        .pair_add(u64pair::u32_mul(a[4], b[2]))
        .pair_add(u64pair::u32_mul(a[5], b[1]))
        .pair_add(u64pair::u32_mul(a[6], b[0]));
    res[6] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[0], b[7]))
        .pair_add(u64pair::u32_mul(a[1], b[6]))
        .pair_add(u64pair::u32_mul(a[2], b[5]))
        .pair_add(u64pair::u32_mul(a[3], b[4]))
        .pair_add(u64pair::u32_mul(a[4], b[3]))
        .pair_add(u64pair::u32_mul(a[5], b[2]))
        .pair_add(u64pair::u32_mul(a[6], b[1]))
        .pair_add(u64pair::u32_mul(a[7], b[0]));
    res[7] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[1], b[7]))
        .pair_add(u64pair::u32_mul(a[2], b[6]))
        .pair_add(u64pair::u32_mul(a[3], b[5]))
        .pair_add(u64pair::u32_mul(a[4], b[4]))
        .pair_add(u64pair::u32_mul(a[5], b[3]))
        .pair_add(u64pair::u32_mul(a[6], b[2]))
        .pair_add(u64pair::u32_mul(a[7], b[1]));
    res[8] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[2], b[7]))
        .pair_add(u64pair::u32_mul(a[3], b[6]))
        .pair_add(u64pair::u32_mul(a[4], b[5]))
        .pair_add(u64pair::u32_mul(a[5], b[4]))
        .pair_add(u64pair::u32_mul(a[6], b[3]))
        .pair_add(u64pair::u32_mul(a[7], b[2]));
    res[9] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[3], b[7]))
        .pair_add(u64pair::u32_mul(a[4], b[6]))
        .pair_add(u64pair::u32_mul(a[5], b[5]))
        .pair_add(u64pair::u32_mul(a[6], b[4]))
        .pair_add(u64pair::u32_mul(a[7], b[3]));
    res[10] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[4], b[7]))
        .pair_add(u64pair::u32_mul(a[5], b[6]))
        .pair_add(u64pair::u32_mul(a[6], b[5]))
        .pair_add(u64pair::u32_mul(a[7], b[4]));
    res[11] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[5], b[7]))
        .pair_add(u64pair::u32_mul(a[6], b[6]))
        .pair_add(u64pair::u32_mul(a[7], b[5]));
    res[12] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0)
        .pair_add(u64pair::u32_mul(a[6], b[7]))
        .pair_add(u64pair::u32_mul(a[7], b[6]));
    res[13] = tmp_pair.0 as u32;
    tmp_pair = u64pair::new(tmp_pair.1, 0).pair_add(u64pair::u32_mul(a[7], b[7]));
    res[14] = tmp_pair.0 as u32;
    res[15] = tmp_pair.1 as u32;
    res
}

struct u128pair(u128, u128);

impl u128pair {
    #[inline]
    fn new(a: u128, b: u128) -> Self {
        u128pair(a, b)
    }

    #[inline]
    fn u64_mul(a: u64, b: u64) -> Self {
        let mut v = u128::from(a) * u128::from(b);
        let u = v >> 64;
        v &= 0xffff_ffff_ffff_ffff;
        u128pair(v, u)
    }

    #[inline]
    fn pair_add(&self, add_pair: &Self) -> Self {
        let mut local = self.0 + add_pair.0;
        let mut carry = self.1 + add_pair.1;
        carry += local >> 64;
        local &= 0xffff_ffff_ffff_ffff;
        u128pair(local, carry)
    }

    #[inline]
    fn u64_add(a: u64, b: u64) -> Self {
        let mut v = u128::from(a) + u128::from(b);
        let mut u = 0;
        if v > 0xffff_ffff_ffff_ffff {
            u = v >> 64;
            v &= 0xffff_ffff_ffff_ffff;
        }
        u128pair(v, u)
    }

    #[inline]
    fn pair_add_u64(mut self, a: u64) -> Self {
        let mut v = self.1 + u128::from(a);
        let mut u = 0;
        if v > 0xffff_ffff_ffff_ffff {
            u = v >> 64;
            v &= 0xffff_ffff_ffff_ffff;
        }
        self.0 = v;
        self.1 = u;
        self
    }

    #[inline]
    fn pair_add_u64_after(mut self, a: u64) -> Self {
        let mut v = self.0 + u128::from(a);
        let mut u = self.1;
        if v > 0xffff_ffff_ffff_ffff {
            u += v >> 64;
            v &= 0xffff_ffff_ffff_ffff;
        }
        self.0 = v;
        self.1 = u;
        self
    }
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn u64_sub(a: Limb, b: Limb, borrow: bool) -> (Limb, bool) {
    if borrow {
        if a > b {
            return (a - b - 1, false);
        }
        return (0xffff_ffff_ffff_ffff - b + a, true);
    }
    if a < b {
        return (0xffff_ffff_ffff_ffff - b + a + 1, true);
    }
    (a - b, false)
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn u64_add(a: Limb, b: Limb, carry: bool) -> (Limb, bool) {
    let v = DoubleLimb::from(a) + DoubleLimb::from(b) + DoubleLimb::from(carry);
    let u = v >> LIMB_BITS;
    (v as Limb, u != 0)
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_mul_u128(a: &[u64], b: &[u64]) -> [u64; 8] {
    let mut res: [u64; 8] = [0; 8];

    let mut tmp_pair = u128pair::u64_mul(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[1]))
        .pair_add(&u128pair::u64_mul(a[1], b[0]));
    res[1] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[2]))
        .pair_add(&u128pair::u64_mul(a[1], b[1]))
        .pair_add(&u128pair::u64_mul(a[2], b[0]));
    res[2] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[3]))
        .pair_add(&u128pair::u64_mul(a[1], b[2]))
        .pair_add(&u128pair::u64_mul(a[2], b[1]))
        .pair_add(&u128pair::u64_mul(a[3], b[0]));
    res[3] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[1], b[3]))
        .pair_add(&u128pair::u64_mul(a[2], b[2]))
        .pair_add(&u128pair::u64_mul(a[3], b[1]));
    res[4] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[2], b[3]))
        .pair_add(&u128pair::u64_mul(a[3], b[2]));
    res[5] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0).pair_add(&u128pair::u64_mul(a[3], b[3]));
    res[6] = tmp_pair.0 as u64;
    res[7] = tmp_pair.1 as u64;

    res
}

#[inline]
pub(crate) fn norop256_add_u128(a: &[u64; 4], b: &[u64; 4]) -> [u64; 5] {
    let mut res: [u64; 5] = [0; 5];

    let mut tmp_pair = u128pair::u64_add(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[1]).pair_add_u64_after(b[1]);
    res[1] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[2]).pair_add_u64_after(b[2]);
    res[2] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[3]).pair_add_u64_after(b[3]);
    res[3] = tmp_pair.0 as u64;
    res[4] = tmp_pair.1 as u64;

    res
}

// todo error add
#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_add_u512_u128_mod(r: &mut [u64], a: &[u64; 8], b: &[u64; 8], n: &[u64; 4]) {
    let mut mid = [0; 4];
    let mut tmp_pair = u128pair::u64_add(a[0], b[0]);
    tmp_pair = tmp_pair.pair_add_u64(a[1]).pair_add_u64_after(b[1]);
    tmp_pair= tmp_pair.pair_add_u64(a[2]).pair_add_u64_after(b[2]);
    tmp_pair = tmp_pair.pair_add_u64(a[3]).pair_add_u64_after(b[3]);
    tmp_pair = tmp_pair.pair_add_u64(a[4]).pair_add_u64_after(b[4]);
    mid[0] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[5]).pair_add_u64_after(b[5]);
    mid[1] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[6]).pair_add_u64_after(b[6]);
    mid[2] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[7]).pair_add_u64_after(b[7]);
    mid[3] = tmp_pair.0 as u64;
    if tmp_pair.1 != 0 || !norop_limbs_less_than(r, n) {
        let _ = norop256_limbs_sub(r, &mid, n);
    } else {
        r.copy_from_slice(&mid);
    }
}

#[inline]
pub(crate) fn norop256_add_u512_u128(a: &[u64; 8], b: &[u64; 8]) -> [u64; 9] {
    let mut res: [u64; 9] = [0; 9];

    let mut tmp_pair = u128pair::u64_add(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[1]).pair_add_u64_after(b[1]);
    res[1] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[2]).pair_add_u64_after(b[2]);
    res[2] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[3]).pair_add_u64_after(b[3]);
    res[3] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[4]).pair_add_u64_after(b[4]);
    res[4] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[5]).pair_add_u64_after(b[5]);
    res[5] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[6]).pair_add_u64_after(b[6]);
    res[6] = tmp_pair.0 as u64;
    tmp_pair = tmp_pair.pair_add_u64(a[7]).pair_add_u64_after(b[7]);
    res[7] = tmp_pair.0 as u64;
    res[8] = tmp_pair.1 as u64;

    res
}

#[inline]
fn norop256_mul_u256_u64(a: &[u64; 4], b: &[u64; 1]) -> [u64; 5] {
    let mut res: [u64; 5] = [0; 5];

    let mut tmp_pair = u128pair::u64_mul(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0).pair_add(&u128pair::u64_mul(a[1], b[0]));
    res[1] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0).pair_add(&u128pair::u64_mul(a[2], b[0]));
    res[2] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0).pair_add(&u128pair::u64_mul(a[3], b[0]));
    res[3] = tmp_pair.0 as u64;
    res[4] = tmp_pair.1 as u64;

    res
}

#[inline]
pub(crate) fn norop256_mul_u512_u128(a: &[u64; 8], b: &[u64; 4]) -> [u64; 12] {
    let mut res: [u64; 12] = [0; 12];

    let mut tmp_pair = u128pair::u64_mul(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[1]))
        .pair_add(&u128pair::u64_mul(a[1], b[0]));
    res[1] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[2]))
        .pair_add(&u128pair::u64_mul(a[1], b[1]))
        .pair_add(&u128pair::u64_mul(a[2], b[0]));
    res[2] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[0], b[3]))
        .pair_add(&u128pair::u64_mul(a[1], b[2]))
        .pair_add(&u128pair::u64_mul(a[2], b[1]))
        .pair_add(&u128pair::u64_mul(a[3], b[0]));
    res[3] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[1], b[3]))
        .pair_add(&u128pair::u64_mul(a[2], b[2]))
        .pair_add(&u128pair::u64_mul(a[3], b[1]))
        .pair_add(&u128pair::u64_mul(a[4], b[0]));
    res[4] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[2], b[3]))
        .pair_add(&u128pair::u64_mul(a[3], b[2]))
        .pair_add(&u128pair::u64_mul(a[4], b[1]))
        .pair_add(&u128pair::u64_mul(a[5], b[0]));
    res[5] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[3], b[3]))
        .pair_add(&u128pair::u64_mul(a[4], b[2]))
        .pair_add(&u128pair::u64_mul(a[5], b[1]))
        .pair_add(&u128pair::u64_mul(a[6], b[0]));
    res[6] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[4], b[3]))
        .pair_add(&u128pair::u64_mul(a[5], b[2]))
        .pair_add(&u128pair::u64_mul(a[6], b[1]))
        .pair_add(&u128pair::u64_mul(a[7], b[0]));
    res[7] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[5], b[3]))
        .pair_add(&u128pair::u64_mul(a[6], b[2]))
        .pair_add(&u128pair::u64_mul(a[7], b[1]));
    res[8] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0)
        .pair_add(&u128pair::u64_mul(a[6], b[3]))
        .pair_add(&u128pair::u64_mul(a[7], b[2]));
    res[9] = tmp_pair.0 as u64;
    tmp_pair = u128pair::new(tmp_pair.1, 0).pair_add(&u128pair::u64_mul(a[7], b[3]));
    res[10] = tmp_pair.0 as u64;
    res[11] = tmp_pair.1 as u64;

    res
}

#[inline]
pub(crate) fn norop256_sub_u128(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut res: [u64; 4] = [0; 4];

    let (tmp, borrow) = u64_sub(a[0], b[0], false);
    res[0] = tmp;
    let (tmp, borrow) = u64_sub(a[1], b[1], borrow);
    res[1] = tmp;
    let (tmp, borrow) = u64_sub(a[2], b[2], borrow);
    res[2] = tmp;
    let (tmp, borrow) = u64_sub(a[3], b[3], borrow);
    res[3] = tmp;

    if borrow {
        unreachable!();
    }

    res
}

fn pair_u64_mul(a: u64, b: u64) -> (u128, u128) {
    let mut v = u128::from(a) * u128::from(b);
    let u = v >> 64;
    v &= 0xffff_ffff_ffff_ffff;
    (v, u)
}

fn pair_u128_add(ap: &(u128, u128), bp: &(u128, u128)) -> (u128, u128) {
    let mut local = ap.0 + bp.0;
    let mut carry = ap.1 + bp.1;
    carry += local >> 64;
    local &= 0xffff_ffff_ffff_ffff;
    (local, carry)
}

#[inline]
pub(crate) fn norop256_mul_u128_next(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut res: [u64; 8] = [0; 8];

    let mut tmp_pair = pair_u64_mul(a[0], b[0]);
    res[0] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(
        &(tmp_pair.1, 0),
        &pair_u128_add(&pair_u64_mul(a[0], b[1]), &pair_u64_mul(a[1], b[0])),
    );
    res[1] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(
        &(tmp_pair.1, 0),
        &pair_u128_add(
            &pair_u64_mul(a[0], b[2]),
            &pair_u128_add(&pair_u64_mul(a[1], b[1]), &pair_u64_mul(a[2], b[0])),
        ),
    );
    res[2] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(
        &(tmp_pair.1, 0),
        &pair_u128_add(
            &pair_u64_mul(a[0], b[3]),
            &pair_u128_add(
                &pair_u64_mul(a[1], b[2]),
                &pair_u128_add(&pair_u64_mul(a[2], b[1]), &pair_u64_mul(a[3], b[0])),
            ),
        ),
    );
    res[3] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(
        &(tmp_pair.1, 0),
        &pair_u128_add(
            &pair_u64_mul(a[1], b[3]),
            &pair_u128_add(&pair_u64_mul(a[2], b[2]), &pair_u64_mul(a[3], b[1])),
        ),
    );
    res[4] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(
        &(tmp_pair.1, 0),
        &pair_u128_add(&pair_u64_mul(a[2], b[3]), &pair_u64_mul(a[3], b[2])),
    );
    res[5] = tmp_pair.0 as u64;
    tmp_pair = pair_u128_add(&(tmp_pair.1, 0), &pair_u64_mul(a[3], b[3]));
    res[6] = tmp_pair.0 as u64;
    res[7] = tmp_pair.1 as u64;

    res
}

#[inline]
#[cfg(target_pointer_width = "32")]
pub(crate) fn norop256_limbs_add(r: &mut [Limb], a: &[Limb], b: &[Limb], num_size: usize) {
    let mut u = 0;
    for i in 0..num_size {
        let v = DoubleLimb::from(a[i]) + DoubleLimb::from(b[i]) + u;
        u = v >> LIMB_BITS;
        r[i] = v as Limb;
    }
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_limbs_add(r: &mut [Limb], a: &[Limb], b: &[Limb]) -> bool {
    let (tmp, carry) = u64_add(a[0], b[0], false);
    r[0] = tmp;
    let (tmp, carry) = u64_add(a[1], b[1], carry);
    r[1] = tmp;
    let (tmp, carry) = u64_add(a[2], b[2], carry);
    r[2] = tmp;
    let (tmp, carry) = u64_add(a[3], b[3], carry);
    r[3] = tmp;

    carry
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_limbs_add_mod(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    m: &[Limb],
    _num_size: usize,
) {
    let carry = norop256_limbs_add(r, a, b);

    if carry || norop_limbs_less_than(r, m) == false {
        let r_copy: &mut [Limb] = &mut [0; 4];
        unsafe { core::ptr::copy(r.as_ptr(), r_copy.as_mut_ptr(), 4) };
        let _borrow = norop256_limbs_sub(r, r_copy, m);
    }
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_limbs_sub<'a: 'b, 'b>(r: &mut [Limb], a: &[Limb], b: &[Limb]) -> bool {
    let (tmp, borrow) = u64_sub(a[0], b[0], false);
    r[0] = tmp;
    let (tmp, borrow) = u64_sub(a[1], b[1], borrow);
    r[1] = tmp;
    let (tmp, borrow) = u64_sub(a[2], b[2], borrow);
    r[2] = tmp;
    let (tmp, borrow) = u64_sub(a[3], b[3], borrow);
    r[3] = tmp;

    borrow
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_limbs_sub_mod(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    _m: &[Limb],
    _num_size: usize,
) {
    let borrow = norop256_limbs_sub(r, a, b);

    if borrow {
        let r_copy: &mut [Limb] = &mut [0; 4];
        unsafe { core::ptr::copy(r.as_ptr(), r_copy.as_mut_ptr(), 4) };
        let _borrow = norop256_limbs_sub(r, r_copy, &CURVE_PARAMS.r_p);
    }
}

#[inline]
#[cfg(target_pointer_width = "64")]
pub(crate) fn norop256_limbs_less_than(a: &[Limb], b: &[Limb]) -> Limb {
    if a[3] < b[3] {
        constant_time_is_zero_w(0)
    } else if a[3] > b[3] {
        constant_time_is_nonzero_w(0)
    } else {
        if a[2] < b[2] {
            constant_time_is_zero_w(0)
        } else if a[2] > b[2] {
            constant_time_is_nonzero_w(0)
        } else {
            if a[1] < b[1] {
                constant_time_is_zero_w(0)
            } else if a[1] > b[1] {
                constant_time_is_nonzero_w(0)
            } else {
                if a[0] < b[0] {
                    constant_time_is_zero_w(0)
                } else if a[0] > b[0] {
                    constant_time_is_nonzero_w(0)
                } else {
                    constant_time_is_nonzero_w(0)
                }
            }
        }
    }
}

#[inline]
pub(crate) fn norop_limbs_less_than(a: &[Limb], b: &[Limb]) -> bool {
    let la = a.len();
    let lb = b.len();

    if lb > la {
        for i in 0..lb - la {
            if b[la + i] != 0 {
                return true;
            }
        }
    }

    for i in 0..la {
        if la - i > lb && a[la - i - 1] != 0 {
            return false;
        } else if lb >= la - i {
            match a[la - i - 1].cmp(&b[la - i - 1]) {
                Ordering::Greater => return false,
                Ordering::Less => return true,
                Ordering::Equal => {}
            }
        }
    }

    false
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn constant_time_is_zero_w(a: Limb) -> Limb {
    constant_time_msb_w(!a & (Wrapping(a) - Wrapping(1)).0)
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn constant_time_is_nonzero_w(a: Limb) -> Limb {
    !constant_time_msb_w(!a & (Wrapping(a) - Wrapping(1)).0)
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn constant_time_msb_w(a: Limb) -> Limb {
    (Wrapping(0) - Wrapping(a >> (core::mem::size_of::<Limb>() * 8 - 1))).0
}
