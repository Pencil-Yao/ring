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

#[cfg(test)]
mod test {
    use crate::arithmetic::montgomery::R;
    use crate::cpu;
    use crate::ec::suite_b::ops::norop256::{
        norop256_add_u128, norop256_limbs_add_mod, norop256_limbs_sub_mod,
    };
    use crate::ec::suite_b::ops::sm2p256_norop::{CURVE_PARAMS, mont_pro_sm2p256_next};
    use crate::ec::suite_b::ops::{Elem, norop256, p256};
    use crate::limb::Limb;

    #[test]
    fn norop256_mul_test() {
        let a = [
            0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834,
            0xdc30061d,
        ];
        let mut b = norop256::norop256_mul(&a, &a);
        b.reverse();
        assert_eq!(
            b,
            [
                0xbd629384, 0x2acf9656, 0x5ca21d72, 0x54d6399b, 0x34c5352f, 0xf46e9a28, 0x33cb66cf,
                0x54915780, 0x90a4a4a5, 0xcd6f771e, 0xe3ff26b1, 0x8476f415, 0xde8f893a, 0x4b8c4d78,
                0x7c047cc0, 0xb84b0841
            ]
        );
    }

    #[test]
    fn norop256_mul_u128_test() {
        let a = [
            0xd89cdf6229c4bddf,
            0xacf005cd78843090,
            0xe5a220abf7212ed6,
            0xdc30061d04874834,
        ];
        let mut b = norop256::norop256_mul_u128(&a, &a);
        b.reverse();
        assert_eq!(
            b,
            [
                0xbd6293842acf9656,
                0x5ca21d7254d6399b,
                0x34c5352ff46e9a28,
                0x33cb66cf54915780,
                0x90a4a4a5cd6f771e,
                0xe3ff26b18476f415,
                0xde8f893a4b8c4d78,
                0x7c047cc0b84b0841
            ]
        );
    }

    #[test]
    fn norop256_mul_u128_next_test() {
        let a = [
            0xd89cdf6229c4bddf,
            0xacf005cd78843090,
            0xe5a220abf7212ed6,
            0xdc30061d04874834,
        ];
        let mut b = norop256::norop256_mul_u128_next(&a, &a);
        b.reverse();
        assert_eq!(
            b,
            [
                0xbd6293842acf9656,
                0x5ca21d7254d6399b,
                0x34c5352ff46e9a28,
                0x33cb66cf54915780,
                0x90a4a4a5cd6f771e,
                0xe3ff26b18476f415,
                0xde8f893a4b8c4d78,
                0x7c047cc0b84b0841
            ]
        );
    }

    #[test]
    fn mont_pro_sm2p256_next_test() {
        let a = [
            0xffffff8a00000051,
            0xffffffdc00000054,
            0xffffffba00000031,
            0xffffffc400000063,
        ];
        let b = [
            0x0000000000000001,
            0x00000000ffffffff,
            0x0000000000000000,
            0x100000000,
        ];
        let mut r = [0; 4];
        mont_pro_sm2p256_next(&mut r, &a, &b);
        r.reverse();
        assert_eq!(
            r,
            [
                0xffffffc400000063,
                0xffffffba00000031,
                0xffffffdc00000054,
                0xffffff8a00000051
            ]
        )
    }

    #[test]
    fn norop256_add_u128_test() {
        let a: [u64; 4] = [
            0x1ffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: [u64; 4] = [
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        let mut r = norop256_add_u128(&a, &b);
        r.reverse();
        assert_eq!(
            r,
            [
                1,
                0x52ab0fe7c09ece7f,
                0x7bdb64b2ab66497d,
                0xd3f55a0546ce02b8,
                0x36552eb8adc0aed5
            ]
        )
    }

    #[test]
    fn norop256_limbs_add_mod_test() {
        let r: &mut [Limb] = &mut [0; 4];
        let a: &[Limb] = &[
            0x1ffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: &[Limb] = &[
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        norop256_limbs_add_mod(r, a, b, &CURVE_PARAMS.p, r.len());
        r.reverse();
        assert_eq!(
            r,
            &[
                0x52ab0fe8c09ece7f,
                0x7bdb64b2ab66497d,
                0xd3f55a0646ce02b7,
                0x36552eb8adc0aed6
            ]
        )
    }

    #[test]
    fn norop256_limbs_sub_mod_test() {
        let r: &mut [Limb] = &mut [0; 4];
        let a: &[Limb] = &[
            0x1ffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xcffffc4d0000064e,
        ];
        let b: &[Limb] = &[
            0x1ffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xdffffc4d0000064e,
        ];
        norop256_limbs_sub_mod(r, a, b, &CURVE_PARAMS.p, r.len());
        r.reverse();
        assert_eq!(
            r,
            [
                0xeffffffeffffffff,
                0xffffffffffffffff,
                0xffffffff00000000,
                0xffffffffffffffff
            ]
        )
    }

    #[test]
    fn elem_product_bench() {
        // This benchmark assumes that the multiplication is constant-time
        // so 0 * 0 is as good of a choice as anything.
        let a: Elem<R> = Elem::zero();
        let b: Elem<R> = Elem::zero();
        let _ = p256::COMMON_OPS.elem_product(&a, &b, cpu::features());
    }
}

#[cfg(feature = "internal_benches")]
mod internal_benches {
    use crate::ec::suite_b::ops::norop256::{
        norop256_add_u128, norop256_limbs_add_mod, norop256_limbs_sub_mod, norop256_mul,
        norop256_mul_u128, norop256_mul_u128_next, norop256_sub_u128,
    };
    use crate::ec::suite_b::ops::sm2p256_norop::{CURVE_PARAMS, mont_pro_sm2p256_next};
    use crate::limb::Limb;
    use crate::{rand, signature};
    use num_bigint::BigUint;

    extern crate test;

    #[bench]
    fn norop256_mul_bench(bench: &mut test::Bencher) {
        let a = [
            0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834,
            0xdc30061d,
        ];
        bench.iter(|| {
            let _ = norop256_mul(&a, &a);
        });
    }

    #[bench]
    fn norop256_mul_biguint_bench(bench: &mut test::Bencher) {
        let a = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122")
                .unwrap(),
        );
        bench.iter(|| {
            let _ = &a * &a;
        });
    }

    #[bench]
    fn norop256_mul_u128_bench(bench: &mut test::Bencher) {
        let a = [
            0x29c4bddfd89cdf62,
            0x78843090acf005cd,
            0xf7212ed65a220ab,
            0x04874834dc30061d,
        ];
        bench.iter(|| {
            let _ = norop256_mul_u128(&a, &a);
        });
    }

    #[bench]
    fn norop256_mul_u128_next_bench(bench: &mut test::Bencher) {
        let a = [
            0x29c4bddfd89cdf62,
            0x78843090acf005cd,
            0xf7212ed65a220ab,
            0x04874834dc30061d,
        ];
        bench.iter(|| {
            let _ = norop256_mul_u128_next(&a, &a);
        });
    }

    #[bench]
    fn mont_pro_sm2p256_next_bench(bench: &mut test::Bencher) {
        let a = [
            0xffffff8a00000051,
            0xffffffdc00000054,
            0xffffffba00000031,
            0xffffffc400000063,
        ];
        let b = [
            0x0000000000000001,
            0x00000000ffffffff,
            0x0000000000000000,
            0x100000000,
        ];
        let mut r = [0; 4];
        bench.iter(|| {
            let _ = mont_pro_sm2p256_next(&mut r, &a, &b);
        });
    }

    #[bench]
    fn sm2p256_signing_bench(bench: &mut test::Bencher) {
        let rng = rand::SystemRandom::new();
        let msg = hex::decode("5905238877c774").unwrap();

        let prik = hex::decode("b8aa2a5bd9a9cf448984a247e63cb3878859d02b886e1bc63cd5c6dd46a744ab")
            .unwrap();
        let pubk = hex::decode("0479fff92a3df175895778dc9dcc825d95e8bb816c356d6c7390332294b3a20189bb24feac1a4a08ff614a4c514b985755948c0a4e49c0042e84078d4a23df6f7e").unwrap();

        let signing_alg = &signature::ECDSA_SM2P256_SM3_ASN1_SIGNING;

        let private_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            signing_alg,
            &prik,
            &pubk,
            &rand::SystemRandom::new(),
        )
        .unwrap();

        bench.iter(|| {
            let _ = private_key.sign(&rng, &msg).unwrap();
        });
    }

    #[bench]
    fn p256_signing_bench(bench: &mut test::Bencher) {
        let rng = rand::SystemRandom::new();
        let msg = hex::decode("5905238877c774").unwrap();

        let prik = hex::decode("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464")
            .unwrap();
        let pubk = hex::decode("041ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();

        let signing_alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;

        let private_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            signing_alg,
            &prik,
            &pubk,
            &rand::SystemRandom::new(),
        )
        .unwrap();

        bench.iter(|| {
            let _ = private_key.sign(&rng, &msg).unwrap();
        });
    }

    #[bench]
    fn norop256_add_u128_bench(bench: &mut test::Bencher) {
        let a: [u64; 4] = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: [u64; 4] = [
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            let _ = norop256_add_u128(&a, &b);
        });
    }

    #[bench]
    fn norop256_sub_u128_bench(bench: &mut test::Bencher) {
        let a: [u64; 4] = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: [u64; 4] = [
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            let _ = norop256_sub_u128(&a, &b);
        });
    }
    #[bench]
    fn norop256_limbs_add_mod_bench(bench: &mut test::Bencher) {
        let r: &mut [Limb] = &mut [0; 4];
        let a: &[Limb] = &[
            0x1ffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: &[Limb] = &[
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            norop256_limbs_add_mod(r, a, b, &CURVE_PARAMS.p, r.len());
        });
    }
    #[bench]
    fn norop256_limbs_sub_mod_bench(bench: &mut test::Bencher) {
        let r: &mut [Limb] = &mut [0; 4];
        let a: &[u64] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: &[u64] = &[
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            norop256_limbs_sub_mod(r, a, b, &CURVE_PARAMS.p, r.len());
        });
    }

    #[bench]
    fn p256_point_add_bench(bench: &mut test::Bencher) {
        prefixed_extern! {
            unsafe fn p256_point_add(
                r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
                a: *const Limb, // [3][COMMON_OPS.num_limbs]
                b: *const Limb, // [3][COMMON_OPS.num_limbs]
            );
        }

        let r: &mut [Limb; 12] = &mut [0; 12];
        let pro_g_2 = ([
            0x18a9143c79e730d4,
            0x5fedb60175ba95fc,
            0x7762251079fb732b,
            0xa53755c618905f76,
            0xce95560addf25357,
            0xba19e45c8b4ab8e4,
            0xdd21f325d2e88688,
            0x25885d858571ff18,
            0x0000000000000001,
            0xffffffff00000000,
            0xffffffffffffffff,
            0xfffffffe,
        ]);
        bench.iter(|| unsafe {
            p256_point_add(r.as_mut_ptr(), pro_g_2.as_ptr(), pro_g_2.as_ptr());
        });
    }

    #[bench]
    fn p256_point_mul_bench(bench: &mut test::Bencher) {
        prefixed_extern! {
            unsafe fn p256_point_mul(
                r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
                p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
                p_x: *const Limb,      // [COMMON_OPS.num_limbs]
                p_y: *const Limb,      // [COMMON_OPS.num_limbs]
            );
        }

        let r: &mut [Limb; 12] = &mut [0; 12];
        let scalar: &[Limb] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let g_2_x: &[Limb] = &[
            0x0af037bfbc3be46a,
            0x83bdc9ba2d8fa938,
            0x5349d94b5788cd24,
            0x0d7e9c18caa5736a,
        ];
        let g_2_y: &[Limb] = &[
            0x6a7e1a1d69db9ac1,
            0xccbd8d37c4a8e82b,
            0xc7b145169b7157ac,
            0x947e74656c21bdf5,
        ];
        bench.iter(|| unsafe {
            p256_point_mul(
                r.as_mut_ptr(),
                scalar.as_ptr(),
                g_2_x.as_ptr(),
                g_2_y.as_ptr(),
            );
        });
    }

    #[bench]
    fn p256_point_mul_base_bench(bench: &mut test::Bencher) {
        prefixed_extern! {
            unsafe fn p256_point_mul_base(
                r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
                g_scalar: *const Limb, // [COMMON_OPS.num_limbs]
            );
        }

        let r: &mut [Limb; 12] = &mut [0; 12];
        let scalar: &[Limb] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        bench.iter(|| unsafe {
            p256_point_mul_base(r.as_mut_ptr(), scalar.as_ptr());
        });
    }
}
