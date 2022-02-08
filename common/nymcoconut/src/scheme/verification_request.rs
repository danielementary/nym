// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use itertools::izip;
use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G1Projective, G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::ProofRequestPhase;
use crate::scheme::check_bilinear_pairing;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::{compute_kappa, compute_zeta};
use crate::scheme::{Signature, VerificationKey};
use crate::traits::{Base58, Bytable};
use crate::utils::{try_deserialize_g1_projective, try_deserialize_g2_projective};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ThetaRequestPhase {
    // parameters
    number_of_to_be_issued_vouchers: u8,
    number_of_to_be_spent_vouchers: u8,
    range_proof_base_u: u8,
    range_proof_number_of_elements_l: u8,
    // commitments
    to_be_issued_commitments: Vec<G1Projective>,
    to_be_issued_binding_number_commitments: Vec<G1Projective>,
    to_be_issued_values_commitments: Vec<G1Projective>,
    to_be_issued_serial_numbers_commitments: Vec<G1Projective>,
    to_be_spent_attributes_commitments: Vec<G2Projective>,
    to_be_spent_serial_numbers_commitments: Vec<G2Projective>,
    blinded_pay: G2Projective,
    range_proof_decompositions_commitments: Vec<Vec<G2Projective>>,
    // signatures
    to_be_spent_signatures: Vec<Signature>,
    // zero-knowledge proof
    proof: ProofRequestPhase,
}

impl TryFrom<&[u8]> for ThetaRequestPhase {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<ThetaRequestPhase> {
        let mut p = 0;
        let mut p_prime = 1;
        let number_of_to_be_issued_vouchers =
            u8::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        p = p_prime;
        p_prime += 1;
        let number_of_to_be_spent_vouchers =
            u8::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        p = p_prime;
        p_prime += 1;
        let range_proof_base_u = u8::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        p = p_prime;
        p_prime += 1;
        let range_proof_number_of_elements_l =
            u8::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        let mut to_be_issued_commitments =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for i in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_issued_commitment_bytes = bytes[p..p_prime].try_into().unwrap();
            let to_be_issued_commitment = try_deserialize_g1_projective(
                &to_be_issued_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_issued_commitment at index {}",
                    i
                )),
            )?;

            to_be_issued_commitments.push(to_be_issued_commitment);
        }

        let mut to_be_issued_binding_number_commitments =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for i in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_issued_binding_number_commitment_bytes =
                bytes[p..p_prime].try_into().unwrap();
            let to_be_issued_binding_number_commitment = try_deserialize_g1_projective(
                &to_be_issued_binding_number_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_issued_binding_number_commitment at index {}",
                    i
                )),
            )?;

            to_be_issued_binding_number_commitments.push(to_be_issued_binding_number_commitment);
        }

        let mut to_be_issued_values_commitments =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for i in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_issued_values_commitment_bytes = bytes[p..p_prime].try_into().unwrap();
            let to_be_issued_values_commitment = try_deserialize_g1_projective(
                &to_be_issued_values_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_issued_values_commitment at index {}",
                    i
                )),
            )?;

            to_be_issued_values_commitments.push(to_be_issued_values_commitment);
        }

        let mut to_be_issued_serial_numbers_commitments =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for i in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_issued_serial_numbers_commitment_bytes =
                bytes[p..p_prime].try_into().unwrap();
            let to_be_issued_serial_numbers_commitment = try_deserialize_g1_projective(
                &to_be_issued_serial_numbers_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_issued_serial_numbers_commitment at index {}",
                    i
                )),
            )?;

            to_be_issued_serial_numbers_commitments.push(to_be_issued_serial_numbers_commitment);
        }

        let mut to_be_spent_attributes_commitments =
            Vec::with_capacity(number_of_to_be_spent_vouchers as usize);
        for i in 0..number_of_to_be_spent_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_spent_attributes_commitment_bytes = bytes[p..p_prime].try_into().unwrap();
            let to_be_spent_attributes_commitment = try_deserialize_g2_projective(
                &to_be_spent_attributes_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_spent_attributes_commitment at index {}",
                    i
                )),
            )?;

            to_be_spent_attributes_commitments.push(to_be_spent_attributes_commitment);
        }

        let mut to_be_spent_serial_numbers_commitments =
            Vec::with_capacity(number_of_to_be_spent_vouchers as usize);
        for i in 0..number_of_to_be_spent_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_spent_serial_numbers_commitment_bytes = bytes[p..p_prime].try_into().unwrap();
            let to_be_spent_serial_numbers_commitment = try_deserialize_g2_projective(
                &to_be_spent_serial_numbers_commitment_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the to_be_spent_serial_numbers_commitment at index {}",
                    i
                )),
            )?;

            to_be_spent_serial_numbers_commitments.push(to_be_spent_serial_numbers_commitment);
        }

        p = p_prime;
        p_prime += 96;
        let blinded_pay_bytes = bytes[p..p_prime].try_into().unwrap();
        let blinded_pay = try_deserialize_g2_projective(
            &blinded_pay_bytes,
            CoconutError::Deserialization("failed to deserialize blinded_pay".to_string()),
        )?;

        let mut range_proof_decompositions_commitments =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for i in 0..number_of_to_be_issued_vouchers {
            let mut range_proof_decomposition_commitments =
                Vec::with_capacity(range_proof_number_of_elements_l as usize);

            for j in 0..range_proof_number_of_elements_l {
                p = p_prime;
                p_prime += 96;

                let range_proof_decomposition_commitment_bytes =
                    bytes[p..p_prime].try_into().unwrap();
                let range_proof_decomposition_commitment = try_deserialize_g2_projective(
                    &range_proof_decomposition_commitment_bytes,
                    CoconutError::Deserialization(format!(
                        "failed to deserialize the to_be_issued_commitment at index {}",
                        i
                    )),
                )?;

                range_proof_decomposition_commitments.push(range_proof_decomposition_commitment);
            }

            range_proof_decompositions_commitments.push(range_proof_decomposition_commitments);
        }

        let mut to_be_spent_signatures =
            Vec::with_capacity(number_of_to_be_spent_vouchers as usize);
        for _ in 0..number_of_to_be_spent_vouchers {
            p = p_prime;
            p_prime += 96;

            let to_be_spent_signature = Signature::try_from(&bytes[p..p_prime])?;

            to_be_spent_signatures.push(to_be_spent_signature);
        }

        p = p_prime;
        let proof = ProofRequestPhase::from_bytes(&bytes[p..])?;

        Ok(ThetaRequestPhase {
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            range_proof_base_u,
            range_proof_number_of_elements_l,
            to_be_issued_commitments,
            to_be_issued_binding_number_commitments,
            to_be_issued_values_commitments,
            to_be_issued_serial_numbers_commitments,
            to_be_spent_attributes_commitments,
            to_be_spent_serial_numbers_commitments,
            blinded_pay,
            range_proof_decompositions_commitments,
            to_be_spent_signatures,
            proof,
        })
    }
}

// functions to convert scalar to u64
fn scalar_fits_in_u64(value: &Scalar) -> bool {
    let value_bytes = value.to_bytes();

    // check that only first 64 bits are set
    for value_byte in value_bytes[8..].iter() {
        if *value_byte != 0 {
            return false;
        }
    }

    true
}

fn scalar_to_u64(value: &Scalar) -> u64 {
    assert!(scalar_fits_in_u64(value));

    // keep 8 first bytes ~= 64 first bits for u64
    let mut u64_value_bytes: [u8; 8] = [0; 8];
    let value_bytes = value.to_bytes();

    u64_value_bytes.clone_from_slice(&value_bytes[..8]);

    u64::from_le_bytes(u64_value_bytes)
}

fn decompose_value(base: u8, number_of_base_elements: u8, value: &Scalar) -> Vec<Scalar> {
    let base: u64 = base.into();
    let number_of_base_elements: u32 = number_of_base_elements.into();
    let value: u64 = scalar_to_u64(value);

    // the decomposition can only be computed for numbers in [0, base^number_of_base_elements)
    assert!(value <= base.pow(number_of_base_elements) - 1);

    let mut decomposition: Vec<Scalar> = Vec::new();
    let mut remainder = value;

    for i in (0..number_of_base_elements).rev() {
        let i_th_pow = base.pow(i);
        let i_th_base_element = remainder / i_th_pow;

        decomposition.push(Scalar::from(i_th_base_element));
        remainder %= i_th_pow;
    }

    // decomposition is little endian: base^0 | base^1 | ... | base^(number_of_base_elements - 1)
    decomposition.reverse();
    decomposition
}

impl ThetaRequestPhase {
    fn verify_proof(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        range_proof_verification_key: &VerificationKey,
    ) -> bool {
        self.proof.verify(
            params,
            verification_key,
            range_proof_verification_key,
            &self.to_be_issued_commitments,
            &self.to_be_issued_binding_number_commitments,
            &self.to_be_issued_values_commitments,
            &self.to_be_issued_serial_numbers_commitments,
            &self.to_be_spent_attributes_commitments,
            &self.to_be_spent_serial_numbers_commitments,
            &self.blinded_pay,
            &self.range_proof_decompositions_commitments,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let number_of_to_be_issued_vouchers_bytes =
            self.number_of_to_be_issued_vouchers.to_be_bytes();
        let number_of_to_be_spent_vouchers_bytes =
            self.number_of_to_be_spent_vouchers.to_be_bytes();
        let range_proof_base_u_bytes = self.range_proof_base_u.to_be_bytes();
        let range_proof_number_of_elements_l_bytes =
            self.range_proof_number_of_elements_l.to_be_bytes();

        let to_be_issued_commitment_bytes = self
            .to_be_issued_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_issued_binding_number_commitments_bytes = self
            .to_be_issued_binding_number_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_issued_values_commitments_bytes = self
            .to_be_issued_values_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_issued_serial_numbers_commitments_bytes = self
            .to_be_issued_serial_numbers_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_spent_attributes_commitments_bytes = self
            .to_be_spent_attributes_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_spent_serial_numbers_commitments_bytes = self
            .to_be_spent_serial_numbers_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let blinded_pay_bytes = self.blinded_pay.to_affine().to_compressed();

        let range_proof_decompositions_commitments_bytes = self
            .range_proof_decompositions_commitments
            .iter()
            .flatten()
            .map(|c| c.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();

        let to_be_spent_signatures_bytes = self
            .to_be_spent_signatures
            .iter()
            .map(|s| s.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        let proof_bytes = self.proof.to_bytes();

        let mut bytes = Vec::with_capacity(
            number_of_to_be_issued_vouchers_bytes.len()
                + number_of_to_be_spent_vouchers_bytes.len()
                + range_proof_base_u_bytes.len()
                + range_proof_number_of_elements_l_bytes.len()
                + to_be_issued_commitment_bytes.len()
                + to_be_issued_binding_number_commitments_bytes.len()
                + to_be_issued_values_commitments_bytes.len()
                + to_be_issued_serial_numbers_commitments_bytes.len()
                + to_be_spent_attributes_commitments_bytes.len()
                + to_be_spent_serial_numbers_commitments_bytes.len()
                + blinded_pay_bytes.len()
                + range_proof_decompositions_commitments_bytes.len()
                + to_be_spent_signatures_bytes.len()
                + proof_bytes.len(),
        );

        bytes.extend(number_of_to_be_issued_vouchers_bytes);
        bytes.extend(number_of_to_be_spent_vouchers_bytes);
        bytes.extend(range_proof_base_u_bytes);
        bytes.extend(range_proof_number_of_elements_l_bytes);
        bytes.extend(to_be_issued_commitment_bytes);
        bytes.extend(to_be_issued_binding_number_commitments_bytes);
        bytes.extend(to_be_issued_values_commitments_bytes);
        bytes.extend(to_be_issued_serial_numbers_commitments_bytes);
        bytes.extend(to_be_spent_attributes_commitments_bytes);
        bytes.extend(to_be_spent_serial_numbers_commitments_bytes);
        bytes.extend(blinded_pay_bytes);
        bytes.extend(range_proof_decompositions_commitments_bytes);
        bytes.extend(to_be_spent_signatures_bytes);
        bytes.extend(proof_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ThetaRequestPhase> {
        ThetaRequestPhase::try_from(bytes)
    }
}

impl Bytable for ThetaRequestPhase {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        ThetaRequestPhase::try_from(slice)
    }
}

impl Base58 for ThetaRequestPhase {}

pub fn randomise_and_request_vouchers(
    params: &Parameters,
    verification_key: &VerificationKey,
    range_proof_verification_key: &VerificationKey,
    number_of_to_be_issued_vouchers: u8,
    number_of_to_be_spent_vouchers: u8,
    range_proof_base_u: u8,
    range_proof_number_of_elements_l: u8,
    // secrets
    binding_number: &Scalar,
    // to be issued
    to_be_issued_values: &[Scalar],
    to_be_issued_serial_numbers: &[Scalar],
    // to be spent
    to_be_spent_values: &[Scalar],
    to_be_spent_serial_numbers: &[Scalar],
    // vouchers
    to_be_spent_vouchers: &[Signature],
) -> Result<ThetaRequestPhase> {
    // randomize the vouchers to be spent
    let (randomized_to_be_spent_vouchers, to_be_spent_blinders): (Vec<Signature>, Vec<Scalar>) =
        to_be_spent_vouchers
            .iter()
            .map(|v| v.randomise(&params))
            .unzip();

    let to_be_issued_values_decompositions = to_be_issued_values
        .iter()
        .map(|value| decompose_value(range_proof_base_u, range_proof_number_of_elements_l, value))
        .collect();

    // pub(crate) fn construct(
    //     params: &Parameters,
    //     verification_key: &VerificationKey,
    //     range_proof_verification_key: &VerificationKey,
    //     number_of_to_be_issued_vouchers: u8,
    //     number_of_to_be_spent_vouchers: u8,
    //     range_proof_base_u: u8,
    //     range_proof_number_of_elements_l: u8,
    //     // secrets
    //     binding_number: &Scalar,
    //     // to be issued
    //     to_be_issued_values_decompositions: &[Vec<Scalar>],
    //     to_be_issued_serial_numbers: &[Scalar],
    //     to_be_issued_commitments_openings: &[Scalar],
    //     to_be_issued_binding_numbers_openings: &[Scalar],
    //     to_be_issued_values_openings: &[Scalar],
    //     to_be_issued_serial_numbers_openings: &[Scalar],
    //     // to be spent
    //     to_be_spent_values: &[Scalar],
    //     to_be_spent_serial_numbers: &[Scalar],
    //     to_be_spent_blinders: &[Scalar],
    //     // range proof
    //     range_proof_blinders: &[Vec<Scalar>],
    //     // for challenge
    //     to_be_issued_commitments: &[G1Projective],
    //     to_be_issued_binding_number_commitments: &[G1Projective],
    //     to_be_issued_values_commitments: &[G1Projective],
    //     to_be_issued_serial_numbers_commitments: &[G1Projective],
    //     to_be_spent_attributes_commitments: &[G2Projective],
    //     to_be_spent_serial_numbers_commitments: &[G2Projective],
    //     blinded_pay: &G2Projective,
    //     range_proof_decompositions_commitments: &[Vec<G2Projective>],
    // ) -> Self {
    // let pi_v = ProofSpend::construct(
    //     &params,
    //     &verification_key,
    //     number_of_vouchers_spent,
    //     &binding_number,
    //     &values,
    //     &serial_numbers,
    //     &signatures_blinding_factors,
    //     &blinded_messages,
    //     &blinded_serial_numbers,
    //     &blinded_spent_amount,
    // );

    // Ok(ThetaRequestPhase {
    //     number_of_vouchers_spent,
    //     blinded_messages,
    //     blinded_serial_numbers,
    //     blinded_spent_amount,
    //     vouchers_signatures: signatures_prime,
    //     pi_v,
    // })
}

// pub fn verify_vouchers(
//     params: &Parameters,
//     verification_key: &VerificationKey,
//     theta: &ThetaRequestPhase,
//     infos: &[Scalar],
// ) -> bool {
//     if verification_key.beta_g2.len() < 4 {
//         return false;
//     }

//     if !theta.verify_proof(params, verification_key) {
//         return false;
//     }

//     let blinded_messages: Vec<_> = theta
//         .blinded_messages
//         .iter()
//         .zip(infos.iter())
//         .map(|(bm, i)| bm + verification_key.beta_g2()[3] * i)
//         .collect();

//     for (vs, bm) in izip!(theta.vouchers_signatures.iter(), blinded_messages.iter()) {
//         if !check_bilinear_pairing(
//             &vs.0.to_affine(),
//             &G2Prepared::from(bm.to_affine()),
//             &vs.1.to_affine(),
//             params.prepared_miller_g2(),
//         ) {
//             return false;
//         }

//         if bool::from(vs.0.is_identity()) {
//             return false;
//         }
//     }

//     true
// }

// #[cfg(test)]
// mod tests {
//     use crate::scheme::keygen::keygen;
//     use crate::scheme::setup::setup;

//     use super::*;

//     #[test]
//     fn theta_bytes_roundtrip() {
//         let params = setup(4).unwrap();

//         let keypair = keygen(&params);
//         let verification_key = keypair.verification_key();

//         let binding_number = params.random_scalar();

//         // test one voucher
//         let values = [Scalar::from(10)];
//         let serial_numbers = [params.random_scalar()];
//         let signatures = [Signature(
//             params.gen1() * params.random_scalar(),
//             params.gen1() * params.random_scalar(),
//         )];

//         let theta = randomise_and_prove_vouchers(
//             &params,
//             &verification_key,
//             &binding_number,
//             &values,
//             &serial_numbers,
//             &signatures,
//         )
//         .unwrap();

//         let bytes = theta.to_bytes();
//         assert_eq!(ThetaRequestPhase::try_from(bytes.as_slice()).unwrap(), theta);

//         // test three vouchers
//         let values = [Scalar::from(10), Scalar::from(10), Scalar::from(10)];
//         let serial_numbers = [
//             params.random_scalar(),
//             params.random_scalar(),
//             params.random_scalar(),
//         ];
//         let signatures = [
//             Signature(
//                 params.gen1() * params.random_scalar(),
//                 params.gen1() * params.random_scalar(),
//             ),
//             Signature(
//                 params.gen1() * params.random_scalar(),
//                 params.gen1() * params.random_scalar(),
//             ),
//             Signature(
//                 params.gen1() * params.random_scalar(),
//                 params.gen1() * params.random_scalar(),
//             ),
//         ];

//         let theta = randomise_and_prove_vouchers(
//             &params,
//             &verification_key,
//             &binding_number,
//             &values,
//             &serial_numbers,
//             &signatures,
//         )
//         .unwrap();

//         let bytes = theta.to_bytes();
//         assert_eq!(ThetaRequestPhase::try_from(bytes.as_slice()).unwrap(), theta);
//     }
// }
