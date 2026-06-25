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

use crate::limb::Limb;
use alloc::vec;
use core::slice;
use num_bigint::BigUint;
use num_traits::identities::Zero;

lazy_static::lazy_static! {
    static ref SM2P256_CTX: sm2p256_ctx = sm2p256_ctx::new();
}

pub(super) fn Norop_sm2p256_add(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const u8;
    let b_ptr = b as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let b_bz: &[u8] = unsafe { slice::from_raw_parts(b_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let b_big = BigUint::from_bytes_le(b_bz);
    let r_big = add_sm2p256(&a_big, &b_big);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

pub(super) fn Norop_sm2p256_mul_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const u8;
    let b_ptr = b as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let b_bz: &[u8] = unsafe { slice::from_raw_parts(b_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let b_big = BigUint::from_bytes_le(b_bz);
    let r_big = mont_pro_sm2p256(&a_big, &b_big);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

pub(super) fn Norop_sm2p256_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let r_big = mont_pro_sm2p256(&a_big, &a_big);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

// rem = a + b
pub(super) fn Norop_sm2p256_point_add(
    r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
    a: *const Limb, // [3][COMMON_OPS.num_limbs]
    b: *const Limb, // [3][COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const [u8; 32];
    let b_ptr = b as *const [u8; 32];
    let a_bz: &[[u8; 32]] = unsafe { slice::from_raw_parts(a_ptr, 3) };
    let b_bz: &[[u8; 32]] = unsafe { slice::from_raw_parts(b_ptr, 3) };
    let a_x = BigUint::from_bytes_le(&a_bz[0]);
    let a_y = BigUint::from_bytes_le(&a_bz[1]);
    let a_z = BigUint::from_bytes_le(&a_bz[2]);
    let b_x = BigUint::from_bytes_le(&b_bz[0]);
    let b_y = BigUint::from_bytes_le(&b_bz[1]);
    let b_z = BigUint::from_bytes_le(&b_bz[2]);

    let rem = norop_point_add_sm2p256(&[a_x, a_y, a_z], &[b_x, b_y, b_z]);

    let mut rem_arr = [0; 144];
    let rem_x_le = rem[0].to_bytes_le();
    let rem_y_le = rem[1].to_bytes_le();
    let rem_z_le = rem[2].to_bytes_le();
    rem_arr[..rem_x_le.len()].copy_from_slice(&rem_x_le);
    rem_arr[32..32 + rem_y_le.len()].copy_from_slice(&rem_y_le);
    rem_arr[64..64 + rem_z_le.len()].copy_from_slice(&rem_z_le);
    unsafe {
        r.copy_from(rem_arr.as_mut_ptr() as *mut Limb, 18);
    }
}

// double and add
pub(super) fn Norop_sm2p256_point_mul(
    r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
    p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
    p_x: *const Limb,      // [COMMON_OPS.num_limbs]
    p_y: *const Limb,      // [COMMON_OPS.num_limbs]
) {
    let p_scalar_ptr = p_scalar as *const u8;
    let p_x_ptr = p_x as *const u8;
    let p_y_ptr = p_y as *const u8;
    let p_scalar_bz = unsafe { slice::from_raw_parts(p_scalar_ptr, 32) };
    let p_x_bz = unsafe { slice::from_raw_parts(p_x_ptr, 32) };
    let p_y_bz = unsafe { slice::from_raw_parts(p_y_ptr, 32) };
    let p_scalar_big = BigUint::from_bytes_le(p_scalar_bz);
    let p_x_big = BigUint::from_bytes_le(p_x_bz);
    let p_y_big = BigUint::from_bytes_le(p_y_bz);

    let rem = norop_point_mul_sm2p256(&norop_to_jacobi_sm2p256(&[p_x_big, p_y_big]), &p_scalar_big);

    let mut rem_arr = [0; 144];
    let rem_x_le = rem[0].to_bytes_le();
    let rem_y_le = rem[1].to_bytes_le();
    let rem_z_le = rem[2].to_bytes_le();
    rem_arr[..rem_x_le.len()].copy_from_slice(&rem_x_le);
    rem_arr[32..32 + rem_y_le.len()].copy_from_slice(&rem_y_le);
    rem_arr[64..64 + rem_z_le.len()].copy_from_slice(&rem_z_le);
    unsafe {
        r.copy_from(rem_arr.as_mut_ptr() as *mut Limb, 18);
    }
}

// rem = a * b * r^-1 modn
pub(super) fn Norop_sm2p256_scalar_mul_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const u8;
    let b_ptr = b as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let b_bz: &[u8] = unsafe { slice::from_raw_parts(b_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let b_big = BigUint::from_bytes_le(b_bz);
    let r_big = norop_scalar_mont_pro_sm2p256(&a_big, &b_big);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

pub(super) fn Norop_sm2p256_scalar_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let a_ptr = a as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let r_big = norop_scalar_mont_pro_sm2p256(&a_big, &a_big);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

pub(super) fn Norop_sm2p256_scalar_sqr_rep_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    rep: Limb,
) {
    let a_ptr = a as *const u8;
    let a_bz: &[u8] = unsafe { slice::from_raw_parts(a_ptr, 32) };
    let a_big = BigUint::from_bytes_le(a_bz);
    let r_big = norop_scalar_mul_rep_sm2p256(&a_big, rep as usize);
    let mut r_bz = [0; 32];
    let r_raw_bz = r_big.to_bytes_le();
    r_bz[..r_raw_bz.len()].copy_from_slice(&r_raw_bz);
    unsafe {
        r.copy_from(r_bz.as_mut_ptr() as *mut Limb, 4);
    }
}

struct sm2p256_ctx {
    ffff_256: BigUint,
    ffff_32: BigUint,
    p: BigUint,
    p_inv_r_neg: BigUint,
    p0_inv_r_neg: BigUint,
    r_p: BigUint,
    rr_p: BigUint,
    n: BigUint,
    n_inv_r_neg: BigUint,
    rr_n: BigUint,
}

impl sm2p256_ctx {
    pub fn new() -> sm2p256_ctx {
        sm2p256_ctx {
            ffff_256: BigUint::from_bytes_be(
                &hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .unwrap(),
            ),
            ffff_32: BigUint::from_bytes_be(&hex::decode("ffffffff").unwrap()),
            p: BigUint::from_bytes_be(
                &hex::decode("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff")
                    .unwrap(),
            ),
            p_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("fffffffc00000001fffffffe00000000ffffffff000000010000000000000001")
                    .unwrap(),
            ),
            p0_inv_r_neg: BigUint::from_bytes_be(&hex::decode("0000000000000001").unwrap()),
            r_p: BigUint::from_bytes_be(
                &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
            ),
            rr_p: BigUint::from_bytes_be(
                &hex::decode("0400000002000000010000000100000002ffffffff0000000200000003").unwrap(),
            ),
            n: BigUint::from_bytes_be(
                &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123")
                    .unwrap(),
            ),
            n_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("6f39132f82e4c7bc2b0068d3b08941d4df1e8d34fc8319a5327f9e8872350975")
                    .unwrap(),
            ),
            rr_n: BigUint::from_bytes_be(
                &hex::decode("1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20")
                    .unwrap(),
            ),
        }
    }
}

fn mont_pro_sm2p256(a: &BigUint, b: &BigUint) -> BigUint {
    assert!(a.bits() <= 256 && b.bits() <= 256);
    let t = a * b;
    let m = (&t * &SM2P256_CTX.p_inv_r_neg) & &SM2P256_CTX.ffff_256;
    let m_mul_p = m * &SM2P256_CTX.p;
    let mut r = t + &m_mul_p;
    r >>= 256;
    if r >= SM2P256_CTX.p {
        r -= &SM2P256_CTX.p;
    }
    r
}

fn mont_pro_sm2p256_next(a: &BigUint, b: &BigUint) -> BigUint {
    assert!(a.bits() <= 256 && b.bits() <= 256);
    let a_vec = a.to_u32_digits();
    let b_vec = b.to_u32_digits();
    let b0 = u64::from(b_vec[0]);
    let mut c0 = BigUint::new(vec![0]);
    let mut r = BigUint::new(vec![0]);
    for i in 0..8 {
        let a_uint = u64::from(*a_vec.get(i).unwrap_or(&0));

        c0 = (&c0 + a_uint * b0) & &SM2P256_CTX.ffff_32;
        r += a_uint * b + &c0 * &SM2P256_CTX.p;
        r >>= 32;
        c0 = &r & &SM2P256_CTX.ffff_32;
    }
    if r >= SM2P256_CTX.p {
        r -= &SM2P256_CTX.p;
    }
    r
}

fn add_sm2p256(a: &BigUint, b: &BigUint) -> BigUint {
    assert!(a.bits() <= 256 && b.bits() <= 256);
    let mut r = a + b;
    while r >= SM2P256_CTX.p {
        r -= &SM2P256_CTX.p;
    }
    r
}

fn neg_sm2p256(a: &BigUint) -> BigUint {
    assert!(a.bits() <= 256);
    let a = a % &SM2P256_CTX.p;
    &SM2P256_CTX.p - &a
}

fn sub_sm2p256(a: &BigUint, b: &BigUint) -> BigUint {
    assert!(a.bits() <= 256 && b.bits() <= 256);
    let neg_b = neg_sm2p256(b);
    let mut r = a + &neg_b;
    while r >= SM2P256_CTX.p {
        r -= &SM2P256_CTX.p;
    }
    r
}

fn mul_sm2p256(a: &BigUint, m: usize) -> BigUint {
    assert!(a.bits() <= 256);
    mod_sm2p256(&(m * a))
}

// a << b
fn shl_sm2p256(a: &BigUint, b: usize) -> BigUint {
    assert!(a.bits() <= 256);
    let a_shl = a << b;
    mod_sm2p256(&a_shl)
}

fn mod_sm2p256(a: &BigUint) -> BigUint {
    let mut rem = a.clone();
    let mut rem_len = rem.bits();
    while rem_len > 256 {
        let left_rem = &rem >> 256;
        rem -= (&left_rem + (&left_rem >> 32) + (&left_rem >> 160) - (&left_rem >> 192))
            * &SM2P256_CTX.p;
        rem_len = rem.bits();
    }
    if rem >= SM2P256_CTX.p {
        rem -= &SM2P256_CTX.p;
    }
    rem
}

fn norop_to_mont_sm2p256(a: &BigUint) -> BigUint {
    assert!(a.bits() <= 256);
    mont_pro_sm2p256(a, &SM2P256_CTX.rr_p)
}

// todo change algorithm
fn norop_point_add_sm2p256(a: &[BigUint; 3], b: &[BigUint; 3]) -> [BigUint; 3] {
    let a_x = &a[0];
    let a_y = &a[1];
    let a_z = &a[2];
    assert!(a_x.bits() <= 256 && a_y.bits() <= 256 && a_z.bits() <= 256);
    let b_x = &b[0];
    let b_y = &b[1];
    let b_z = &b[2];
    assert!(b_x.bits() <= 256 && b_y.bits() <= 256 && b_z.bits() <= 256);

    if a_z.is_zero() {
        return b.clone();
    } else if b_z.is_zero() {
        return a.clone();
    } else if a_x == b_x && a_y == b_y && a_z == b_z {
        let rem_arr = norop_point_double_sm2p256(a);
        return rem_arr;
    }

    let a_z_sqr = mont_pro_sm2p256(&a_z, &a_z);
    let b_z_sqr = mont_pro_sm2p256(&b_z, &b_z);
    let u1 = mont_pro_sm2p256(&a_x, &b_z_sqr);
    let u2 = mont_pro_sm2p256(&b_x, &a_z_sqr);
    let a_z_cub = mont_pro_sm2p256(&a_z_sqr, &a_z);
    let b_z_cub = mont_pro_sm2p256(&b_z_sqr, &b_z);
    let s1 = mont_pro_sm2p256(&a_y, &b_z_cub);
    let s2 = mont_pro_sm2p256(&b_y, &a_z_cub);
    let h = sub_sm2p256(&u2, &u1);
    let r = sub_sm2p256(&s2, &s1);
    let r_sqr = mont_pro_sm2p256(&r, &r);
    let h_sqr = mont_pro_sm2p256(&h, &h);
    let h_cub = mont_pro_sm2p256(&h_sqr, &h);

    let lam1 = mont_pro_sm2p256(&u1, &h_sqr); // u1*h^2
    let rem_x = sub_sm2p256(&sub_sm2p256(&r_sqr, &h_cub), &shl_sm2p256(&lam1, 1));
    let rem_y = sub_sm2p256(
        &mont_pro_sm2p256(&r, &sub_sm2p256(&lam1, &rem_x)),
        &mont_pro_sm2p256(&s1, &h_cub),
    );
    let rem_z = mont_pro_sm2p256(&mont_pro_sm2p256(&a_z, &b_z), &h);

    [rem_x, rem_y, rem_z]
}

fn norop_point_double_sm2p256(a: &[BigUint; 3]) -> [BigUint; 3] {
    let a_x = &a[0];
    let a_y = &a[1];
    let a_z = &a[2];
    assert!(a_x.bits() <= 256 && a_y.bits() <= 256 && a_z.bits() <= 256);
    let delta = mont_pro_sm2p256(a_z, a_z);
    let gamma = mont_pro_sm2p256(a_y, a_y);
    let beta = mont_pro_sm2p256(a_x, &gamma);
    let alpha = mul_sm2p256(
        &mont_pro_sm2p256(&sub_sm2p256(a_x, &delta), &add_sm2p256(a_x, &delta)),
        3,
    );
    let rem_x = sub_sm2p256(&mont_pro_sm2p256(&alpha, &alpha), &shl_sm2p256(&beta, 3));
    let lam1 = sub_sm2p256(&shl_sm2p256(&beta, 2), &rem_x); // 4 * beta - x3
    let rem_y = sub_sm2p256(
        &mont_pro_sm2p256(&alpha, &lam1),
        &shl_sm2p256(&mont_pro_sm2p256(&gamma, &gamma), 3),
    );
    let lam2 = add_sm2p256(a_y, a_z);
    let rem_z = sub_sm2p256(
        &sub_sm2p256(&mont_pro_sm2p256(&lam2, &lam2), &gamma),
        &delta,
    );
    [rem_x, rem_y, rem_z]
}

fn norop_point_mul_sm2p256(a: &[BigUint; 3], scalar: &BigUint) -> [BigUint; 3] {
    let a_x = &a[0];
    let a_y = &a[1];
    let a_z = &a[2];
    assert!(a_x.bits() <= 256 && a_y.bits() <= 256 && a_z.bits() <= 256 && scalar.bits() <= 256);
    let scalar_bz = scalar.to_bytes_le();
    let mut a_order = [a[0].clone(), a[1].clone(), a[2].clone()];
    let mut rem = [
        BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
        ),
        BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
        ),
        BigUint::new(vec![0]),
    ];

    for scalar_byte in scalar_bz {
        let mut bit: usize = 0;
        while bit < 8 {
            if (scalar_byte >> bit) & 0x01 != 0 {
                rem = norop_point_add_sm2p256(&rem, &a_order);
            }
            a_order = norop_point_double_sm2p256(&a_order);
            bit += 1;
        }
    }
    rem
}

// (`a` squared `squarings` times) * b
#[inline]
fn norop_sqr_mul_sm2p256(a: &BigUint, squarings: usize, b: &BigUint) -> BigUint {
    assert!(squarings >= 1 && a.bits() <= 256);
    let mut rem = mont_pro_sm2p256(a, a);
    for _ in 1..squarings {
        rem = mont_pro_sm2p256(&rem, &rem);
    }
    mont_pro_sm2p256(&rem, b)
}

fn norop_mont_inv_sm2p256(a: &BigUint) -> BigUint {
    assert!(a.bits() <= 256);
    let b_1 = a;
    let b_11 = norop_sqr_mul_sm2p256(b_1, 1, b_1);
    let b_111 = norop_sqr_mul_sm2p256(&b_11, 1, b_1);
    let f_11 = norop_sqr_mul_sm2p256(&b_111, 3, &b_111);
    let fff = norop_sqr_mul_sm2p256(&f_11, 6, &f_11);
    let fff_111 = norop_sqr_mul_sm2p256(&fff, 3, &b_111);
    let fffffff_11 = norop_sqr_mul_sm2p256(&fff_111, 15, &fff_111);
    let ffffffff = norop_sqr_mul_sm2p256(&fffffff_11, 2, &b_11);

    // fffffff_111
    let mut acc = norop_sqr_mul_sm2p256(&fffffff_11, 1, &b_1);

    // fffffffe
    acc = mont_pro_sm2p256(&acc, &acc);

    // fffffffeffffffff
    acc = norop_sqr_mul_sm2p256(&acc, 32, &ffffffff);

    // fffffffeffffffffffffffff
    acc = norop_sqr_mul_sm2p256(&acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffff
    acc = norop_sqr_mul_sm2p256(&acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff
    acc = norop_sqr_mul_sm2p256(&acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000ffffffff
    acc = norop_sqr_mul_sm2p256(&acc, 64, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff_11
    acc = norop_sqr_mul_sm2p256(&acc, 30, &fffffff_11);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd
    norop_sqr_mul_sm2p256(&acc, 2, b_1)
}

fn norop_to_affine_sm2p256(a: &[BigUint; 3]) -> [BigUint; 2] {
    let a_x = &a[0];
    let a_y = &a[1];
    let a_z = &a[2];
    assert!(a_x.bits() <= 256 && a_y.bits() <= 256 && a_z.bits() <= 256);

    let z_inv = norop_mont_inv_sm2p256(&a_z);
    let zz_inv = mont_pro_sm2p256(&z_inv, &z_inv);
    let zzz_inv = mont_pro_sm2p256(&zz_inv, &z_inv);

    let rem_x = mont_pro_sm2p256(&a_x, &zz_inv);
    let rem_y = mont_pro_sm2p256(&a_y, &zzz_inv);

    [rem_x, rem_y]
}

fn norop_to_jacobi_sm2p256(a: &[BigUint; 2]) -> [BigUint; 3] {
    // 1 * r modsm2p256
    [
        a[0].clone(),
        a[1].clone(),
        BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
        ),
    ]
}

fn norop_scalar_mont_pro_sm2p256(a: &BigUint, b: &BigUint) -> BigUint {
    assert!(a.bits() <= 256 && b.bits() <= 256);
    let t = a * b;
    let m = (t.clone() * &SM2P256_CTX.n_inv_r_neg) & &SM2P256_CTX.ffff_256;
    let m_mul_pinv = m * &SM2P256_CTX.n;
    let mut r = t + &m_mul_pinv;
    r >>= 256;
    if r >= SM2P256_CTX.n {
        r -= &SM2P256_CTX.n;
    }
    r
}

// `a` squared `squarings` times
fn norop_scalar_mul_rep_sm2p256(a: &BigUint, squarings: usize) -> BigUint {
    assert!(squarings >= 1 && a.bits() <= 256);
    let mut rem = norop_scalar_mont_pro_sm2p256(a, a);
    for _ in 1..squarings {
        rem = norop_scalar_mont_pro_sm2p256(&rem, &rem);
    }
    rem
}

fn norop_scalar_to_mont_sm2p256(a: &BigUint) -> BigUint {
    assert!(a.bits() <= 256);
    norop_scalar_mont_pro_sm2p256(a, &SM2P256_CTX.rr_n)
}

#[cfg(test)]
mod test {
    use crate::ec::suite_b::ops::norop::*;
    use num_bigint::BigUint;

    #[test]
    fn sm2p256_elem_mul_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(
            &mont_pro_sm2p256(&a, &a).to_str_radix(16),
            "fc222e1c0698bf87fb578bfc034a02d7fdad71210581a5b0f83ece010579c786"
        );

        // 0100000000000000000000000000000000ffffffff0000000000000001 1 * r modsm2p256
        let b = BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
        );
        assert_eq!(
            &mont_pro_sm2p256(&a, &b).to_str_radix(16),
            "fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b"
        );
        assert_eq!(
            &a.to_str_radix(16),
            "fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b"
        );
    }

    #[test]
    fn sm2p256_elem_mul_next_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(
            &mont_pro_sm2p256_next(&a, &a).to_str_radix(16),
            "fc222e1c0698bf87fb578bfc034a02d7fdad71210581a5b0f83ece010579c786"
        );

        // 0100000000000000000000000000000000ffffffff0000000000000001 1 * r modsm2p256
        let b = BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000000ffffffff0000000000000001").unwrap(),
        );
        assert_eq!(
            &mont_pro_sm2p256(&a, &b).to_str_radix(16),
            "fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b"
        );
        assert_eq!(
            &a.to_str_radix(16),
            "fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b"
        );
    }

    #[test]
    fn sm2p256_to_mont_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(
            &norop_to_mont_sm2p256(&a).to_str_radix(16),
            "ffffffc400000063ffffffba00000031ffffffdc00000054ffffff8a00000051"
        );
    }

    #[test]
    fn sm2p256_neg_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffffffffffff00000001ffffffffffffffff")
                .unwrap(),
        );
        assert_eq!(
            &neg_sm2p256(&a).to_str_radix(16),
            "fffffffefffffffffffffffffffffffffffffffeffffffffffffffffffffffff"
        );
    }

    #[test]
    fn sm2p256_sub_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        let b = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(&sub_sm2p256(&a, &b).to_str_radix(16), "0");

        let a = BigUint::from_bytes_be(
            &hex::decode("0100000000000000000000000000000001000000000000000000000001").unwrap(),
        );
        let b = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffffffffffff00000001ffffffffffffffff")
                .unwrap(),
        );
        assert_eq!(
            &sub_sm2p256(&a, &b).to_str_radix(16),
            "100000000000000000000000000000000ffffffff0000000000000001"
        );
    }

    #[test]
    fn sm2p256_inv_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        let res_mon = norop_mont_inv_sm2p256(&norop_to_mont_sm2p256(&a));
        assert_eq!(
            &mont_pro_sm2p256(&res_mon, &BigUint::new(vec![1])).to_str_radix(16),
            "1b000000090000000a0000000c0000000efffffff80000001200000016"
        );
    }

    #[test]
    fn shl_sm2p256_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(
            &shl_sm2p256(&a, 7).to_str_radix(16),
            "fffe26ff0003277ffffdc6000001927ffffee37f0002a180fffc4a8000029dff"
        );
    }

    #[test]
    fn sm2p256_point_double_test() {
        let ori_point_g = [
            BigUint::from_bytes_be(
                &hex::decode("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
                    .unwrap(),
            ),
            BigUint::from_bytes_be(
                &hex::decode("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
                    .unwrap(),
            ),
        ];
        let mont_ori_point_g = [
            norop_to_mont_sm2p256(&ori_point_g[0]),
            norop_to_mont_sm2p256(&ori_point_g[1]),
        ];
        let projective_mont_point_g = norop_to_jacobi_sm2p256(&mont_ori_point_g);
        let double_projective_mont_point_g = norop_point_double_sm2p256(&projective_mont_point_g);
        assert_eq!(
            &double_projective_mont_point_g[0].to_str_radix(16),
            "398874c476a3b1f77aef3e862601440903243d78d5b614a62eda8381e63c48d6"
        );
        assert_eq!(
            &double_projective_mont_point_g[1].to_str_radix(16),
            "1fbbdfdddaf4fd475a86a7ae64921d4829f04a88f6cf4dc128385681c1a73e40"
        );
        let double_affine_mont_point_g = norop_to_affine_sm2p256(&double_projective_mont_point_g);
        assert_eq!(
            &double_affine_mont_point_g[0].to_str_radix(16),
            "d7e9c18caa5736a5349d94b5788cd2483bdc9ba2d8fa9380af037bfbc3be46a"
        );
        assert_eq!(
            &double_affine_mont_point_g[1].to_str_radix(16),
            "947e74656c21bdf5c7b145169b7157acccbd8d37c4a8e82b6a7e1a1d69db9ac1"
        );
    }

    #[test]
    fn sm2p256_point_add_test() {
        let g_2 = [
            BigUint::from_bytes_be(
                &hex::decode("0d7e9c18caa5736a5349d94b5788cd2483bdc9ba2d8fa9380af037bfbc3be46a")
                    .unwrap(),
            ),
            BigUint::from_bytes_be(
                &hex::decode("947e74656c21bdf5c7b145169b7157acccbd8d37c4a8e82b6a7e1a1d69db9ac1")
                    .unwrap(),
            ),
        ];
        let g_4 = [
            BigUint::from_bytes_be(
                &hex::decode("50dc8e3ac899dbe18a86bcb4a09f9020487ea27fe9016209393f7c5a98615060")
                    .unwrap(),
            ),
            BigUint::from_bytes_be(
                &hex::decode("6ffc31c525bce9e34d0bd55632cf70ed1de135ea7c7383bdfc099043fd619998")
                    .unwrap(),
            ),
        ];
        let pro_g_2 = norop_to_jacobi_sm2p256(&g_2);
        let pro_g_4 = norop_to_jacobi_sm2p256(&g_4);
        let pro_g_6 = norop_point_add_sm2p256(&pro_g_2, &pro_g_4);
        assert_eq!(
            &pro_g_6[0].to_str_radix(16),
            "8809697f61212fb3e78e089e5a7c37c1a0efb845a948e0f92a83eb933ccc35bc"
        );
        assert_eq!(
            &pro_g_6[1].to_str_radix(16),
            "ec95fee1f76accca446c55f4ee708c7edf32a204fc4ee23a3c6538a863b7e39c"
        );
        let aff_g_6 = norop_to_affine_sm2p256(&pro_g_6);
        assert_eq!(
            &aff_g_6[0].to_str_radix(16),
            "85e74ca08cba8047f15a876e5de34db6b1274a255e7ec73c136a9c4c0acd72ba"
        );
        assert_eq!(
            &aff_g_6[1].to_str_radix(16),
            "b568bc974b8c598a1060e7f8ec30e9848fbf6d1fc99754f808454cddb469eb37"
        );
    }

    #[test]
    fn sm2p256_point_mul_test() {
        let ori_point_g = [
            BigUint::from_bytes_be(
                &hex::decode("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
                    .unwrap(),
            ),
            BigUint::from_bytes_be(
                &hex::decode("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
                    .unwrap(),
            ),
        ];
        let mont_ori_point_g = [
            norop_to_mont_sm2p256(&ori_point_g[0]),
            norop_to_mont_sm2p256(&ori_point_g[1]),
        ];
        let projective_mont_point_g = norop_to_jacobi_sm2p256(&mont_ori_point_g);

        let scalar = shl_sm2p256(&BigUint::new(vec![31]), 8 * 1);
        let pro_point = norop_point_mul_sm2p256(&projective_mont_point_g, &scalar);
        assert_eq!(
            &pro_point[0].to_str_radix(16),
            "f1040d220835c55853e5f2ceadcea03c8b26e5b723745dccac514f6271992317"
        );
        assert_eq!(
            &pro_point[1].to_str_radix(16),
            "f5ac0f090f555f70d728e96f929453c3c5632ace89809a1d11905a20e4926568"
        );
        let aff_point = norop_to_affine_sm2p256(&pro_point);
        assert_eq!(
            &aff_point[0].to_str_radix(16),
            "914be21f176ea1565d5f9b3082854ee045851bf4a0ea1a51cc34d15e88d60eba"
        );
        assert_eq!(
            &aff_point[1].to_str_radix(16),
            "40ed89898fc05a715e4799d978c0eec5255cb9c073a666a8ecac86d12a05c368"
        );
    }

    #[test]
    fn sm2p256_scalar_mul_test() {
        let a = BigUint::from_bytes_be(&hex::decode("01").unwrap());
        let b = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122")
                .unwrap(),
        );
        assert_eq!(
            &norop_scalar_mont_pro_sm2p256(&a, &b).to_str_radix(16),
            "90c6eccfec544b7357e45ee87a7726fe811e8df2e2300b193fd2b803d21c0b39"
        );
    }

    #[test]
    fn sm2p256_calar_mul_rep_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        assert_eq!(
            &norop_scalar_mul_rep_sm2p256(&a, 5).to_str_radix(16),
            "6514d7e43c7a0114caf0ff6d4e4338fa1b02b9ae6172b1d0dcab52c1fff7a373"
        );
    }

    #[test]
    fn norop_sqr_mul_sm2p256_test() {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffc4d0000064efffffb8c00000324fffffdc600000543fffff8950000053b")
                .unwrap(),
        );
        let b = BigUint::from_bytes_be(
            &hex::decode("52ab139ac09ec8307bdb6926ab664658d3f55c3f46cdfd7516553623adc0a99a")
                .unwrap(),
        );
        assert_eq!(
            &norop_sqr_mul_sm2p256(&a, 4, &b).to_str_radix(16),
            "48a99794c338910027d03b673cc4c14afe55a1d7c4f1d8387435be63c5053e17"
        );
    }
}

#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::*;
    use num_bigint::BigUint;
    extern crate test;

    #[bench]
    fn elem_inverse_bench(bench: &mut test::Bencher) {
        // This benchmark assumes that `elem_inverse_squared()` is
        // constant-time so inverting 1 mod q is as good of a choice as
        // anything.
        let a = BigUint::from_bytes_be(&hex::decode("01").unwrap());
        bench.iter(|| {
            let _ = norop_mont_inv_sm2p256(&a);
        });
    }

    #[bench]
    fn elem_product_bench(bench: &mut test::Bencher) {
        // This benchmark assumes that the multiplication is constant-time
        // so 0 * 0 is as good of a choice as anything.
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122")
                .unwrap(),
        );
        let b = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54789")
                .unwrap(),
        );
        bench.iter(|| {
            let _ = mont_pro_sm2p256(&a, &b);
        });
    }

    #[bench]
    fn elem_product_next_bench(bench: &mut test::Bencher) {
        // This benchmark assumes that the multiplication is constant-time
        // so 0 * 0 is as good of a choice as anything.
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122")
                .unwrap(),
        );
        let b = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54789")
                .unwrap(),
        );
        bench.iter(|| {
            let _ = mont_pro_sm2p256_next(&a, &b);
        });
    }

    #[bench]
    fn elem_squared_bench(bench: &mut test::Bencher) {
        // This benchmark assumes that the squaring is constant-time so
        // 0**2 * 0 is as good of a choice as anything.
        let a = BigUint::from_bytes_be(&hex::decode("00").unwrap());
        bench.iter(|| {
            let _ = mont_pro_sm2p256(&a, &a);
        });
    }
}