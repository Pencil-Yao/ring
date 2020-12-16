// Copyright 2015-2016 Brian Smith.
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

//! ECDSA Signatures using the P-256 and P-384 curves.
#![allow(dead_code)]

use super::digest_scalar::digest_scalar;
use crate::{
    arithmetic::montgomery::*,
    cpu, digest,
    ec::{
        self,
        suite_b::{ops::*, private_key},
    },
    error,
    io::der,
    limb, pkcs8, rand, sealed, signature,
};
use untrusted;
use core::marker::PhantomData;
use crate::ec::suite_b::ecdsa::verification::EcdsaVerificationAlgorithm;
use crate::limb::parse_big_endian_and_pad_consttime;

/// An ECDSA signing algorithm.
pub struct EcdsaSigningAlgorithm {
    curve: &'static ec::Curve,
    private_scalar_ops: &'static PrivateScalarOps,
    private_key_ops: &'static PrivateKeyOps,
    digest_alg: &'static digest::Algorithm,
    pkcs8_template: &'static pkcs8::Template,
    format_rs: fn(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize,
    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_SM2P256_SM3_ASN1_SIGNING,
}

derive_debug_via_id!(EcdsaSigningAlgorithm);

impl PartialEq for EcdsaSigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EcdsaSigningAlgorithm {}

impl sealed::Sealed for EcdsaSigningAlgorithm {}

/// An ECDSA key pair, used for signing.
pub struct EcdsaKeyPair {
    d: Scalar<R>,
    nonce_key: NonceRandomKey,
    alg: &'static EcdsaSigningAlgorithm,
    public_key: PublicKey,
}

derive_debug_via_field!(EcdsaKeyPair, stringify!(EcdsaKeyPair), public_key);

impl EcdsaKeyPair {
    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v1 `OneAsymmetricKey` with the public key
    /// included in the `ECPrivateKey` structure, as described in
    /// [RFC 5958 Section 2] and [RFC 5915]. The `ECPrivateKey` structure will
    /// not have a `parameters` field so the generated key is compatible with
    /// PKCS#11.
    ///
    /// [RFC 5915]: https://tools.ietf.org/html/rfc5915
    /// [RFC 5958 Section 2]: https://tools.ietf.org/html/rfc5958#section-2
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        let private_key = ec::Seed::generate(alg.curve, rng, cpu::features())?;
        let public_key = private_key.compute_public_key()?;
        Ok(pkcs8::wrap_key(
            &alg.pkcs8_template,
            private_key.bytes_less_safe(),
            public_key.as_ref(),
        ))
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// The input must be in PKCS#8 v1 format. It must contain the public key in
    /// the `ECPrivateKey` structure; `from_pkcs8()` will verify that the public
    /// key and the private key are consistent with each other. The algorithm
    /// identifier must identify the curve by name; it must not use an
    /// "explicit" encoding of the curve. The `parameters` field of the
    /// `ECPrivateKey`, if present, must be the same named curve that is in the
    /// algorithm identifier in the PKCS#8 header.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_pkcs8(
            alg.curve,
            alg.pkcs8_template,
            untrusted::Input::from(pkcs8),
            cpu::features(),
        )?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_bytes(
            alg.curve,
            untrusted::Input::from(private_key),
            untrusted::Input::from(public_key),
            cpu::features(),
        )?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    fn new(
        alg: &'static EcdsaSigningAlgorithm,
        key_pair: ec::KeyPair,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let (seed, public_key) = key_pair.split();
        let d = private_key::private_key_as_scalar(alg.private_key_ops, &seed);

        let d = alg
            .private_scalar_ops
            .scalar_ops
            .scalar_product(&d, &alg.private_scalar_ops.oneRR_mod_n);

        let nonce_key = NonceRandomKey::new(alg, seed, rng)?;
        Ok(Self {
            d,
            nonce_key,
            alg,
            public_key: PublicKey(public_key),
        })
    }

    /// Deprecated. Returns the signature of the `message` using a random nonce
    /// generated by `rng`.
    pub fn sign(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        // Step 4 (out of order).

        let h = {
            if self.alg.id == AlgorithmID::ECDSA_SM2P256_SM3_ASN1_SIGNING {
                let ctx = libsm::sm2::signature::SigCtx::new();
                let pk_point = ctx.load_pubkey(self.public_key()).map_err(|_| error::Unspecified)?;
                let message = ctx.recid_combine("1234567812345678", &pk_point, message);
                digest::digest(self.alg.digest_alg, &message)
            } else {
                digest::digest(self.alg.digest_alg, message)
            }
        };

        // Incorporate `h` into the nonce to hedge against faulty RNGs. (This
        // is not an approved random number generator that is mandated in
        // the spec.)
        let nonce_rng = NonceRandom {
            key: &self.nonce_key,
            message_digest: &h,
            rng,
        };

        self.sign_digest(h, &nonce_rng)
    }

    #[cfg(test)]
    fn sign_with_fixed_nonce_during_test(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        // Step 4 (out of order).
        let h = digest::digest(self.alg.digest_alg, message);

        self.sign_digest(h, rng)
    }

    /// Returns the signature of message digest `h` using a "random" nonce
    /// generated by `rng`.
    fn sign_digest(
        &self,
        h: digest::Digest,
        rng: &dyn rand::SecureRandom,
    ) -> Result<signature::Signature, error::Unspecified> {
        // NSA Suite B Implementer's Guide to ECDSA Section 3.4.1: ECDSA
        // Signature Generation.

        // NSA Guide Prerequisites:
        //
        //     Prior to generating an ECDSA signature, the signatory shall
        //     obtain:
        //
        //     1. an authentic copy of the domain parameters,
        //     2. a digital signature key pair (d,Q), either generated by a
        //        method from Appendix A.1, or obtained from a trusted third
        //        party,
        //     3. assurance of the validity of the public key Q (see Appendix
        //        A.3), and
        //     4. assurance that he/she/it actually possesses the associated
        //        private key d (see [SP800-89] Section 6).
        //
        // The domain parameters are hard-coded into the source code.
        // `EcdsaKeyPair::generate_pkcs8()` can be used to meet the second
        // requirement; otherwise, it is up to the user to ensure the key pair
        // was obtained from a trusted private key. The constructors for
        // `EcdsaKeyPair` ensure that #3 and #4 are met subject to the caveats
        // in SP800-89 Section 6.

        let ops = self.alg.private_scalar_ops;
        let scalar_ops = ops.scalar_ops;
        let cops = scalar_ops.common;
        let private_key_ops = self.alg.private_key_ops;

        for _ in 0..100 {
            // XXX: iteration conut?
            // Step 1.
            let k = private_key::random_scalar(self.alg.private_key_ops, rng)?;

            // Step 2.
            let r = private_key_ops.point_mul_base(&k);

            // Step 3.
            let mut r = {
                let (x, _) = private_key::affine_from_jacobian(private_key_ops, &r)?;
                let x = cops.elem_unencoded(&x);
                elem_reduced_to_scalar(cops, &x)
            };
            if cops.is_zero(&r) {
                continue;
            }

            // Step 4 is done by the caller.

            // Step 5.
            let e = digest_scalar(scalar_ops, h);

            // Step 6.
            let s = if self.alg.id == AlgorithmID::ECDSA_SM2P256_SM3_ASN1_SIGNING {
                static SCALAR_ONE: Scalar<Unencoded> = Scalar {
                    limbs: limbs![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    m: PhantomData,
                    encoding: PhantomData,
                };

                r = scalar_sum(cops, &r, &e);

                let da_ue = scalar_ops.scalar_unencoded(&self.d);
                let left = scalar_ops.scalar_inv_to_mont(&scalar_sum(cops, &da_ue, &SCALAR_ONE));

                let dr = scalar_ops.scalar_product(&self.d, &r);
                let right = scalar_sub(cops, &k, &dr);

                scalar_ops.scalar_product(&left, &right)
            } else {
                let k_inv = scalar_ops.scalar_inv_to_mont(&k);

                let dr = scalar_ops.scalar_product(&self.d, &r);
                let e_plus_dr = scalar_sum(cops, &e, &dr);
                scalar_ops.scalar_product(&k_inv, &e_plus_dr)
            };

            if cops.is_zero(&s) {
                continue;
            }

            // Step 7 with encoding.
            return Ok(signature::Signature::new(|sig_bytes| {
                (self.alg.format_rs)(scalar_ops, &r, &s, sig_bytes)
            }));
        }

        Err(error::Unspecified)
    }

    /// todo
    pub fn private_key(&self) -> [u8; 48] {
        let mut out = [0; 48];
        let one_scalar: Scalar<R> = Scalar {
            limbs: [1, 0, 0, 0, 0, 0],
            m: PhantomData,
            encoding: PhantomData
        };
        let d = self.alg
            .private_scalar_ops
            .scalar_ops
            .scalar_product(&self.d, &one_scalar);
        limb::big_endian_from_limbs(&d.limbs, &mut out);
        out
    }

    /// todo
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// todo
    pub fn generate_keypair(
        alg: &'static EcdsaSigningAlgorithm
    ) -> Result<Self, error::KeyRejected> {
        let rng = rand::SystemRandom::new();
        let seed = ec::Seed::generate(alg.curve, &rng, cpu::features()).map_err(|error::Unspecified| error::KeyRejected::seed_error())?;
        let key_pair = ec::KeyPair::derive(seed).map_err(|error::Unspecified| error::KeyRejected::keypair_error())?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    /// todo
    pub fn from_privatekey_bytes(
        alg: &'static EcdsaSigningAlgorithm,
        bytes: untrusted::Input,
    ) -> Result<Self, error::KeyRejected> {
        let seed = ec::Seed::from_bytes(alg.curve, bytes, cpu::features()).map_err(|error::Unspecified| error::KeyRejected::seed_error())?;
        let key_pair = ec::KeyPair::derive(seed).map_err(|error::Unspecified| error::KeyRejected::keypair_error())?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    /// todo
    pub fn split_rs<'a>(
        &self,
        alg: &'static EcdsaVerificationAlgorithm,
        signature: &untrusted::Input<'a>,
    ) -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::Unspecified> {
        signature.read_all(error::Unspecified, |input| {
            (alg.split_rs)(self.alg.private_scalar_ops.scalar_ops, input)
        })
    }

    /// todo
    pub fn format_rs<'a>(
        alg: &'static EcdsaSigningAlgorithm,
        r: &'a [u8],
        s: &'a [u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        let r_inp = untrusted::Input::from(&r);
        let mut r_limbs = [0; MAX_LIMBS];
        parse_big_endian_and_pad_consttime(r_inp, &mut r_limbs)?;
        let r: Scalar<Unencoded> = Scalar {
            limbs: r_limbs,
            m: PhantomData,
            encoding: PhantomData
        };

        let s_inp = untrusted::Input::from(&s);
        let mut s_limbs = [0; MAX_LIMBS];
        parse_big_endian_and_pad_consttime(s_inp, &mut s_limbs)?;
        let s: Scalar<Unencoded> = Scalar {
            limbs: s_limbs,
            m: PhantomData,
            encoding: PhantomData
        };

        Ok(signature::Signature::new(|sig_bytes| {
            (alg.format_rs)(alg.private_scalar_ops.scalar_ops, &r, &s, sig_bytes)
        }))
    }
}

/// Generates an ECDSA nonce in a way that attempts to protect against a faulty
/// `SecureRandom`.
struct NonceRandom<'a> {
    key: &'a NonceRandomKey,
    message_digest: &'a digest::Digest,
    rng: &'a dyn rand::SecureRandom,
}

impl core::fmt::Debug for NonceRandom<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonceRandom").finish()
    }
}

impl rand::sealed::SecureRandom for NonceRandom<'_> {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        // Use the same digest algorithm that will be used to digest the
        // message. The digest algorithm's output is exactly the right size;
        // this is checked below.
        //
        // XXX(perf): The single iteration will require two digest block
        // operations because the amount of data digested is larger than one
        // block.
        let digest_alg = self.key.0.algorithm();
        let mut ctx = digest::Context::new(digest_alg);

        // Digest the randomized digest of the private key.
        let key = self.key.0.as_ref();
        ctx.update(key);

        // The random value is digested between the key and the message so that
        // the key and the message are not directly digested in the same digest
        // block.
        assert!(key.len() <= digest_alg.block_len / 2);
        {
            let mut rand = [0u8; digest::MAX_BLOCK_LEN];
            let rand = &mut rand[..digest_alg.block_len - key.len()];
            assert!(rand.len() >= dest.len());
            self.rng.fill(rand)?;
            ctx.update(rand);
        }

        ctx.update(self.message_digest.as_ref());

        let nonce = ctx.finish();

        // `copy_from_slice()` panics if the lengths differ, so we don't have
        // to separately assert that the lengths are the same.
        dest.copy_from_slice(nonce.as_ref());

        Ok(())
    }
}

impl<'a> sealed::Sealed for NonceRandom<'a> {}

struct NonceRandomKey(digest::Digest);

impl NonceRandomKey {
    fn new(
        alg: &EcdsaSigningAlgorithm,
        seed: ec::Seed,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let mut rand = [0; digest::MAX_OUTPUT_LEN];
        let rand = &mut rand[0..alg.curve.elem_scalar_seed_len];

        // XXX: `KeyRejected` isn't the right way to model  failure of the RNG,
        // but to fix that we'd need to break the API by changing the result type.
        // TODO: Fix the API in the next breaking release.
        rng.fill(rand)
            .map_err(|error::Unspecified| error::KeyRejected::rng_failed())?;

        let mut ctx = digest::Context::new(alg.digest_alg);
        ctx.update(rand);
        ctx.update(seed.bytes_less_safe());
        Ok(NonceRandomKey(ctx.finish()))
    }
}

impl signature::KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(ec::PublicKey);

derive_debug_self_as_ref_hex_bytes!(PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn format_rs_fixed(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize {
    let scalar_len = ops.scalar_bytes_len();

    let (r_out, rest) = out.split_at_mut(scalar_len);
    limb::big_endian_from_limbs(&r.limbs[..ops.common.num_limbs], r_out);

    let (s_out, _) = rest.split_at_mut(scalar_len);
    limb::big_endian_from_limbs(&s.limbs[..ops.common.num_limbs], s_out);

    2 * scalar_len
}

fn format_rs_asn1(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize {
    // This assumes `a` is not zero since neither `r` or `s` is allowed to be
    // zero.
    fn format_integer_tlv(ops: &ScalarOps, a: &Scalar, out: &mut [u8]) -> usize {
        let mut fixed = [0u8; ec::SCALAR_MAX_BYTES + 1];
        let fixed = &mut fixed[..(ops.scalar_bytes_len() + 1)];
        limb::big_endian_from_limbs(&a.limbs[..ops.common.num_limbs], &mut fixed[1..]);

        // Since `a_fixed_out` is an extra byte long, it is guaranteed to start
        // with a zero.
        debug_assert_eq!(fixed[0], 0);

        // There must be at least one non-zero byte since `a` isn't zero.
        let first_index = fixed.iter().position(|b| *b != 0).unwrap();

        // If the first byte has its high bit set, it needs to be prefixed with 0x00.
        let first_index = if fixed[first_index] & 0x80 != 0 {
            first_index - 1
        } else {
            first_index
        };
        let value = &fixed[first_index..];

        out[0] = der::Tag::Integer as u8;

        // Lengths less than 128 are encoded in one byte.
        assert!(value.len() < 128);
        out[1] = value.len() as u8;

        out[2..][..value.len()].copy_from_slice(&value);

        2 + value.len()
    }

    out[0] = der::Tag::Sequence as u8;
    let r_tlv_len = format_integer_tlv(ops, r, &mut out[2..]);
    let s_tlv_len = format_integer_tlv(ops, s, &mut out[2..][r_tlv_len..]);

    // Lengths less than 128 are encoded in one byte.
    let value_len = r_tlv_len + s_tlv_len;
    assert!(value_len < 128);
    out[1] = value_len as u8;

    2 + value_len
}

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P256,
    private_scalar_ops: &p256::PRIVATE_SCALAR_OPS,
    private_key_ops: &p256::PRIVATE_KEY_OPS,
    digest_alg: &digest::SHA256,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_fixed,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED_SIGNING,
};

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P384,
    private_scalar_ops: &p384::PRIVATE_SCALAR_OPS,
    private_key_ops: &p384::PRIVATE_KEY_OPS,
    digest_alg: &digest::SHA384,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_fixed,
    id: AlgorithmID::ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and
/// SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P256,
    private_scalar_ops: &p256::PRIVATE_SCALAR_OPS,
    private_key_ops: &p256::PRIVATE_KEY_OPS,
    digest_alg: &digest::SHA256,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_asn1,
    id: AlgorithmID::ECDSA_P256_SHA256_ASN1_SIGNING,
};

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and
/// SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P384,
    private_scalar_ops: &p384::PRIVATE_SCALAR_OPS,
    private_key_ops: &p384::PRIVATE_KEY_OPS,
    digest_alg: &digest::SHA384,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_asn1,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1_SIGNING,
};

/// sm2_with_sm3 sign, todo
pub static ECDSA_SM2P256_SM3_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::SM2P256,
    private_scalar_ops: &sm2p256::PRIVATE_SCALAR_OPS,
    private_key_ops: &sm2p256::PRIVATE_KEY_OPS,
    digest_alg: &digest::SM3_256,
    pkcs8_template: &EC_PUBLIC_KEY_SM2P256_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_asn1,
    id: AlgorithmID::ECDSA_SM2P256_SM3_ASN1_SIGNING,
};

static EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p256_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};

static EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p384_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 24 },
    curve_id_index: 9,
    private_key_index: 0x23,
};

static EC_PUBLIC_KEY_SM2P256_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_sm2p256_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};

#[cfg(test)]
mod tests {
    use crate::{signature, test, pkcs8};
    use crate::ec::suite_b::ecdsa::signing::EcdsaKeyPair;
    use std::fs;
    use std::io::Write;

    #[test]
    fn signature_ecdsa_sign_fixed_test() {
        test::run(
            test_file!("ecdsa_sign_fixed_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                let digest_name = test_case.consume_string("Digest");
                let msg = test_case.consume_bytes("Msg");
                let d = test_case.consume_bytes("d");
                let q = test_case.consume_bytes("Q");
                let k = test_case.consume_bytes("k");

                let expected_result = test_case.consume_bytes("Sig");

                let alg = match (curve_name.as_str(), digest_name.as_str()) {
                    ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    _ => {
                        panic!("Unsupported curve+digest: {}+{}", curve_name, digest_name);
                    }
                };

                let private_key =
                    signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, &q).unwrap();
                let rng = test::rand::FixedSliceRandom { bytes: &k };

                let actual_result = private_key
                    .sign_with_fixed_nonce_during_test(&rng, &msg)
                    .unwrap();

                assert_eq!(actual_result.as_ref(), &expected_result[..]);

                Ok(())
            },
        );
    }

    #[test]
    fn signature_ecdsa_sign_asn1_test() {
        test::run(
            test_file!("ecdsa_sign_asn1_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                let digest_name = test_case.consume_string("Digest");
                let msg = test_case.consume_bytes("Msg");
                let d = test_case.consume_bytes("d");
                let q = test_case.consume_bytes("Q");
                let k = test_case.consume_bytes("k");

                let expected_result = test_case.consume_bytes("Sig");

                let alg = match (curve_name.as_str(), digest_name.as_str()) {
                    ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ("SM2-P-256", "SM3") => &signature::ECDSA_SM2P256_SM3_ASN1_SIGNING,
                    _ => {
                        panic!("Unsupported curve+digest: {}+{}", curve_name, digest_name);
                    }
                };

                let private_key =
                    signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, &q).unwrap();
                let rng = test::rand::FixedSliceRandom { bytes: &k };

                let actual_result = private_key
                    .sign_with_fixed_nonce_during_test(&rng, &msg)
                    .unwrap();

                assert_eq!(actual_result.as_ref(), &expected_result[..]);

                Ok(())
            },
        );
    }

    #[test]
    fn ecdsa_generate_pkcs8_from_pem_test() {
        let pk_file: &[u8] = include_bytes!("/home/ypf/ypf-app/test/cita/bsn-cert/priKey.pk8");
        let alg = &&signature::ECDSA_SM2P256_SM3_ASN1_SIGNING;
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, pk_file).unwrap();
        let pkcs8 = pkcs8::wrap_key(
            &alg.pkcs8_template,
            &key_pair.private_key(),
            &key_pair.public_key(),
        );

        println!("{}", hex::encode(pkcs8.as_ref()));

        let mut to_file = fs::File::create("/home/ypf/ypf-app/test/cita/bsn-cert/cert.pk8").unwrap();
        let _ = to_file.write(pkcs8.as_ref()).unwrap();
    }
}
