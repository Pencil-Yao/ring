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

use arithmetic::montgomery::*;
use {der, digest, error, private, signature};
use super::verify_jacobian_point_is_on_the_curve;
use super::ops::*;
use super::public_key::*;
use untrusted;

/// An ECDSA signature verification algorithm.
pub struct ECDSAVerificationAlgorithm {
    ops: &'static PublicScalarOps,
    digest_alg: &'static digest::Algorithm,
    split_rs:
        for<'a> fn(ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
                   -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                             error::Unspecified>,
}

impl signature::VerificationAlgorithm for ECDSAVerificationAlgorithm {
    // Verify an ECDSA signature as documented in the NSA Suite B Implementer's
    // Guide to ECDSA Section 3.4.2: ECDSA Signature Verification.
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        let public_key_ops = self.ops.public_key_ops;
        let scalar_ops = self.ops.scalar_ops;

        // NSA Guide Prerequisites:
        //
        //    Prior to accepting a verified digital signature as valid the
        //    verifier shall have:
        //
        //       1. assurance of the signatory’s claimed identity,
        //       2. an authentic copy of the domain parameters, (q, FR, a, b,
        //          SEED, G, n, h),
        //       3. assurance of the validity of the public key, and
        //       4. assurance that the claimed signatory actually possessed the
        //          private key that was used to generate the digital signature
        //          at the time that the signature was generated.
        //
        // Prerequisites #1 and #4 are outside the scope of what this function
        // can do. Prerequisite #2 is handled implicitly as the domain
        // parameters are hard-coded into the source. Prerequisite #3 is
        // handled by `parse_uncompressed_point`.
        let peer_pub_key =
            try!(parse_uncompressed_point(public_key_ops, public_key));

        let (r, s) = try!(signature.read_all(
            error::Unspecified, |input| (self.split_rs)(scalar_ops, input)));

        // NSA Guide Step 1: "If r and s are not both integers in the interval
        // [1, n − 1], output INVALID."
        let r = try!(scalar_parse_big_endian_variable(public_key_ops.common,
                                                      AllowZero::No, r));
        let s = try!(scalar_parse_big_endian_variable(public_key_ops.common,
                                                      AllowZero::No, s));

        // NSA Guide Step 2: "Use the selected hash function to compute H =
        // Hash(M)."
        // NSA Guide Step 3: "Convert the bit string H to an integer e as
        // described in Appendix B.2."
        let e = digest_scalar(scalar_ops, self.digest_alg, msg);

        // NSA Guide Step 4: "Compute w = s**−1 mod n, using the routine in
        // Appendix B.1."
        let w = scalar_ops.scalar_inv_to_mont(&s);

        // NSA Guide Step 5: "Compute u1 = (e * w) mod n, and compute
        // u2 = (r * w) mod n."
        let u1 = scalar_ops.scalar_product(&e, &w);
        let u2 = scalar_ops.scalar_product(&r, &w);

        // NSA Guide Step 6: "Compute the elliptic curve point
        // R = (xR, yR) = u1*G + u2*Q, using EC scalar multiplication and EC
        // addition. If R is equal to the point at infinity, output INVALID."
        let product =
            twin_mul(self.ops.private_key_ops, &u1, &u2, &peer_pub_key);

        // Verify that the point we computed is on the curve; see
        // `verify_affine_point_is_on_the_curve_scaled` for details on why. It
        // would be more secure to do the check on the affine coordinates if we
        // were going to convert to affine form (again, see
        // `verify_affine_point_is_on_the_curve_scaled` for details on why).
        // But, we're going to avoid converting to affine for performance
        // reasons, so we do the verification using the Jacobian coordinates.
        let z2 = try!(verify_jacobian_point_is_on_the_curve(
                        public_key_ops.common, &product));

        // NSA Guide Step 7: "Compute v = xR mod n."
        // NSA Guide Step 8: "Compare v and r0. If v = r0, output VALID;
        // otherwise, output INVALID."
        //
        // Instead, we use Greg Maxwell's trick to avoid the inversion mod `q`
        // that would be necessary to compute the affine X coordinate.
        let x = public_key_ops.common.point_x(&product);
        fn sig_r_equals_x(ops: &PublicScalarOps, r: &Elem<Unencoded>,
                          x: &Elem<R>, z2: &Elem<R>) -> bool {
            let cops = ops.public_key_ops.common;
            let r_jacobian = cops.elem_product(z2, r);
            let x = cops.elem_unencoded(x);
            ops.elem_equals(&r_jacobian, &x)
        }
        let r = self.ops.scalar_as_elem(&r);
        if sig_r_equals_x(self.ops, &r, &x, &z2) {
            return Ok(());
        }
        if self.ops.elem_less_than(&r, &self.ops.q_minus_n) {
            let r_plus_n =
                self.ops.elem_sum(&r, &public_key_ops.common.n);
            if sig_r_equals_x(self.ops, &r_plus_n, &x, &z2) {
                return Ok(());
            }
        }

        Err(error::Unspecified)
    }
}

impl private::Private for ECDSAVerificationAlgorithm {}

fn split_rs_fixed<'a>(
        ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
        -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                  error::Unspecified> {
    let scalar_len = ops.scalar_bytes_len();
    let r = try!(input.skip_and_get_input(scalar_len));
    let s = try!(input.skip_and_get_input(scalar_len));
    Ok((r, s))
}

fn split_rs_asn1<'a>(
        _ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
        -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                  error::Unspecified> {
    der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
        let r = try!(der::positive_integer(input));
        let s = try!(der::positive_integer(input));
        Ok((r, s))
    })
}

/// Calculate the digest of `msg` using the digest algorithm `digest_alg`. Then
/// convert the digest to a scalar in the range [0, n) as described in
/// NIST's FIPS 186-4 Section 4.2. Note that this is one of the few cases where
/// a `Scalar` is allowed to have the value zero.
///
/// NIST's FIPS 186-4 4.2 says "When the length of the output of the hash
/// function is greater than N (i.e., the bit length of q), then the leftmost N
/// bits of the hash function output block shall be used in any calculation
/// using the hash function output during the generation or verification of a
/// digital signature."
///
/// "Leftmost N bits" means "N most significant bits" because we interpret the
/// digest as a bit-endian encoded integer.
///
/// The NSA guide instead vaguely suggests that we should convert the digest
/// value to an integer and then reduce it mod `n`. However, real-world
/// implementations (e.g. `digest_to_bn` in OpenSSL and `hashToInt` in Go) do
/// what FIPS 186-4 says to do, not what the NSA guide suggests.
///
/// Why shifting the value right by at most one bit is sufficient: P-256's `n`
/// has its 256th bit set; i.e. 2**255 < n < 2**256. Once we've truncated the
/// digest to 256 bits and converted it to an integer, it will have a value
/// less than 2**256. If the value is larger than `n` then shifting it one bit
/// right will give a value less than 2**255, which is less than `n`. The
/// analogous argument applies for P-384. However, it does *not* apply in
/// general; for example, it doesn't apply to P-521.
fn digest_scalar(ops: &ScalarOps, digest_alg: &'static digest::Algorithm,
                 msg: untrusted::Input) -> Scalar {
    let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
    digest_scalar_(ops, digest.as_ref())
}

// This is a separate function solely so that we can test specific digest
// values like all-zero values and values larger than `n`.
fn digest_scalar_(ops: &ScalarOps, digest: &[u8]) -> Scalar {
    let cops = ops.common;
    let num_limbs = cops.num_limbs;
    let digest = if digest.len() > num_limbs * LIMB_BYTES {
        &digest[..(num_limbs * LIMB_BYTES)]
    } else {
        digest
    };

    scalar_parse_big_endian_partially_reduced_variable_consttime(
        cops, AllowZero::Yes, untrusted::Input::from(digest)).unwrap()
}

fn twin_mul(ops: &PrivateKeyOps, g_scalar: &Scalar, p_scalar: &Scalar,
            p_xy: &(Elem<R>, Elem<R>)) -> Point {
    // XXX: Inefficient. TODO: implement interleaved wNAF multiplication.
    let scaled_g = ops.point_mul_base(g_scalar);
    let scaled_p = ops.point_mul(p_scalar, p_xy);
    ops.common.point_sum(&scaled_g, &scaled_p)
}


/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_FIXED: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_FIXED: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_fixed,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve
/// and SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_asn1,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-256 curve and SHA-384.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA384_ASN1: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_asn1,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-384 curve and SHA-256.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA256_ASN1: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_asn1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve
/// and SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1: ECDSAVerificationAlgorithm =
        ECDSAVerificationAlgorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_asn1,
};


#[cfg(test)]
mod tests {
    use {digest, test};
    use super::digest_scalar_;
    use super::super::ops::*;
    use untrusted;

    #[test]
    fn ecdsa_digest_scalar_test() {
        test::from_file("src/ec/suite_b/ecdsa_digest_scalar_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let digest_name = test_case.consume_string("Digest");
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("Output");

            let (ops, digest_alg) = match
                (curve_name.as_str(), digest_name.as_str()) {
                ("P-256", "SHA256") =>
                    (&p256::PUBLIC_SCALAR_OPS, &digest::SHA256),
                ("P-256", "SHA384") =>
                    (&p256::PUBLIC_SCALAR_OPS, &digest::SHA384),
                ("P-384", "SHA256") =>
                    (&p384::PUBLIC_SCALAR_OPS, &digest::SHA256),
                ("P-384", "SHA384") =>
                    (&p384::PUBLIC_SCALAR_OPS, &digest::SHA384),
                _ => {
                    panic!("Unsupported curve+digest: {}+{}", curve_name,
                           digest_name);
                }
            };

            let num_limbs = ops.public_key_ops.common.num_limbs;
            assert_eq!(input.len(), digest_alg.output_len);
            assert_eq!(output.len(),
                       ops.public_key_ops.common.num_limbs * LIMB_BYTES);

            let expected = scalar_parse_big_endian_variable(
                ops.public_key_ops.common, AllowZero::Yes,
                untrusted::Input::from(&output)).unwrap();

            let actual = digest_scalar_(ops.scalar_ops, &input);

            assert_eq!(actual.limbs[..num_limbs], expected.limbs[..num_limbs]);

            Ok(())
        });
    }
}
