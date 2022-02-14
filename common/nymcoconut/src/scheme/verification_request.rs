// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use itertools::izip;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G1Projective, G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::ProofRequestPhase;
use crate::scheme::check_bilinear_pairing;
use crate::scheme::setup::Parameters;
use crate::scheme::{SecretKey, Signature, VerificationKey};
use crate::traits::{Base58, Bytable};
use crate::utils::{hash_g1, try_deserialize_g1_projective, try_deserialize_g2_projective};

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
    pub to_be_spent_serial_numbers_commitments: Vec<G2Projective>,
    pub blinded_pay: G2Projective,
    range_proof_decompositions_commitments: Vec<Vec<G2Projective>>,
    // signatures
    to_be_spent_signatures: Vec<Signature>,
    range_proof_decompositions_signatures: Vec<Vec<Signature>>,
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
            p_prime += 48;

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
            p_prime += 48;

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
            p_prime += 48;

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
            p_prime += 48;

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

            for _ in 0..range_proof_number_of_elements_l {
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

        let mut range_proof_decompositions_signatures =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for _ in 0..number_of_to_be_issued_vouchers {
            let mut range_proof_decomposition_signatures =
                Vec::with_capacity(range_proof_number_of_elements_l as usize);

            for _ in 0..range_proof_number_of_elements_l {
                p = p_prime;
                p_prime += 96;

                let range_proof_decomposition_signature = Signature::try_from(&bytes[p..p_prime])?;
                range_proof_decomposition_signatures.push(range_proof_decomposition_signature);
            }

            range_proof_decompositions_signatures.push(range_proof_decomposition_signatures);
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
            range_proof_decompositions_signatures,
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
    if !scalar_fits_in_u64(value) {
        panic!("value must fit in a u64");
    }

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

pub type RangeProofSignatures = HashMap<u64, Signature>;

fn issue_signature(h: &G1Projective, secret_key: &SecretKey, value: &Scalar) -> Signature {
    Signature(*h, h * secret_key.x + h * secret_key.ys[0] * value)
}

pub fn issue_range_signatures(
    h: &G1Projective,
    secret_key: &SecretKey,
    base: usize,
) -> RangeProofSignatures {
    let mut range_signatures = vec![];

    for i in 0..base {
        let signature = issue_signature(&h, &secret_key, &Scalar::from(i as u64));
        range_signatures.push(signature);
    }

    (0..base)
        .collect::<Vec<_>>()
        .iter()
        .map(|value| {
            let value = *value as u64;
            (
                value,
                issue_signature(&h, &secret_key, &Scalar::from(value)),
            )
        })
        .collect::<RangeProofSignatures>()
}

fn pick_signature_for_element(signatures: &RangeProofSignatures, value: &Scalar) -> Signature {
    signatures.get(&scalar_to_u64(value)).unwrap().clone()
}

fn pick_signatures_for_decomposition(
    signatures: &RangeProofSignatures,
    decomposition: &[Scalar],
) -> Vec<Signature> {
    decomposition
        .iter()
        .map(|value| pick_signature_for_element(&signatures, &value))
        .collect()
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

        let range_proof_decompositions_signatures_bytes = self
            .range_proof_decompositions_signatures
            .iter()
            .flatten()
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
                + range_proof_decompositions_signatures_bytes.len()
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
        bytes.extend(range_proof_decompositions_signatures_bytes);
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
    range_proof_signatures: &RangeProofSignatures,
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
    to_be_spent_signatures: &[Signature],
) -> Result<ThetaRequestPhase> {
    let to_be_issued_values_decompositions: Vec<Vec<Scalar>> = to_be_issued_values
        .iter()
        .map(|value| decompose_value(range_proof_base_u, range_proof_number_of_elements_l, value))
        .collect();

    let range_proof_decompositions_signatures: Vec<Vec<Signature>> =
        to_be_issued_values_decompositions
            .iter()
            .map(|range_proof_values_decomposition| {
                pick_signatures_for_decomposition(
                    &range_proof_signatures,
                    &range_proof_values_decomposition,
                )
            })
            .collect();

    let (to_be_spent_signatures, to_be_spent_blinders): (Vec<Signature>, Vec<Scalar>) =
        to_be_spent_signatures
            .iter()
            .map(|v| v.randomise(&params))
            .unzip();
    let (range_proof_decompositions_signatures, range_proof_blinders): (
        Vec<Vec<Signature>>,
        Vec<Vec<Scalar>>,
    ) = range_proof_decompositions_signatures
        .iter()
        .map(|range_proof_decomposition_signatures| {
            range_proof_decomposition_signatures
                .iter()
                .map(|range_proof_decomposition_signature| {
                    range_proof_decomposition_signature.randomise(&params)
                })
                .unzip()
        })
        .unzip();

    let to_be_issued_commitments_openings =
        params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
    let to_be_issued_binding_numbers_openings =
        params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
    let to_be_issued_values_openings =
        params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
    let to_be_issued_serial_numbers_openings =
        params.n_random_scalars(number_of_to_be_issued_vouchers as usize);

    let to_be_issued_commitments: Vec<G1Projective> = izip!(
        to_be_issued_commitments_openings.iter(),
        to_be_issued_values_decompositions.iter(),
        to_be_issued_serial_numbers.iter()
    )
    .map(|(opening, value_decompositions, serial_number)| {
        params.gen1() * opening
            + params.hs1()[0] * binding_number
            + value_decompositions
                .iter()
                .enumerate()
                .map(|(index, value_decomposition)| {
                    params.hs1()[1] * value_decomposition
                        + params.hs1()[1]
                            * (Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                })
                .sum::<G1Projective>()
            + params.hs1()[2] * serial_number
    })
    .collect();

    let to_be_issued_hm_s: Vec<G1Projective> = to_be_issued_commitments
        .iter()
        .map(|commitment| hash_g1(commitment.to_affine().to_compressed()))
        .collect();

    let to_be_issued_binding_number_commitments: Vec<G1Projective> = izip!(
        to_be_issued_serial_numbers_openings.iter(),
        to_be_issued_hm_s.iter()
    )
    .map(|(opening, hm)| params.gen1() * opening + hm * binding_number)
    .collect();

    let to_be_issued_values_commitments: Vec<G1Projective> = izip!(
        to_be_issued_values_openings.iter(),
        to_be_issued_hm_s.iter(),
        to_be_issued_values_decompositions.iter(),
    )
    .map(|(opening, hm, value_decompositions)| {
        params.gen1() * opening
            + value_decompositions
                .iter()
                .enumerate()
                .map(|(index, value_decomposition)| {
                    hm * value_decomposition
                        + hm * (Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                })
                .sum::<G1Projective>()
    })
    .collect();

    let to_be_issued_serial_numbers_commitments: Vec<G1Projective> = izip!(
        to_be_issued_serial_numbers_openings.iter(),
        to_be_issued_hm_s.iter(),
        to_be_issued_serial_numbers.iter(),
    )
    .map(|(opening, hm, serial_number)| params.gen1() * opening + hm * serial_number)
    .collect();

    let to_be_spent_attributes_commitments: Vec<G2Projective> = izip!(
        to_be_spent_values.iter(),
        to_be_spent_serial_numbers.iter(),
        to_be_spent_blinders.iter()
    )
    .map(|(value, serial_number, blinder)| {
        verification_key.alpha()
            + verification_key.beta_g2()[0] * binding_number
            + verification_key.beta_g2()[1] * value
            + verification_key.beta_g2()[2] * serial_number
            + params.gen2() * blinder
    })
    .collect();

    let to_be_spent_serial_numbers_commitments: Vec<G2Projective> = to_be_spent_serial_numbers
        .iter()
        .map(|serial_number| params.gen2() * serial_number)
        .collect();

    let blinded_pay: G2Projective = to_be_issued_values_decompositions
        .iter()
        .map(|value_decompositions| {
            value_decompositions
                .iter()
                .enumerate()
                .map(|(index, value_decomposition)| {
                    params.hs2()[1] * value_decomposition
                        + params.hs2()[1]
                            * (Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                })
                .sum::<G2Projective>()
        })
        .sum::<G2Projective>()
        - to_be_spent_values
            .iter()
            .map(|value| params.hs2()[1] * value)
            .sum::<G2Projective>();

    let range_proof_decompositions_commitments: Vec<Vec<G2Projective>> = izip!(
        to_be_issued_values_decompositions.iter(),
        range_proof_blinders.iter()
    )
    .map(|(value_decompositions, blinders)| {
        izip!(value_decompositions.iter(), blinders.iter())
            .map(|(value_decomposition, blinder)| {
                range_proof_verification_key.alpha()
                    + range_proof_verification_key.beta_g2()[0] * value_decomposition
                    + params.gen2() * blinder
            })
            .collect()
    })
    .collect();

    let proof = ProofRequestPhase::construct(
        &params,
        &verification_key,
        &range_proof_verification_key,
        number_of_to_be_issued_vouchers,
        number_of_to_be_spent_vouchers,
        range_proof_base_u,
        range_proof_number_of_elements_l,
        &binding_number,
        &to_be_issued_values_decompositions,
        &to_be_issued_serial_numbers,
        &to_be_issued_commitments_openings,
        &to_be_issued_binding_numbers_openings,
        &to_be_issued_values_openings,
        &to_be_issued_serial_numbers_openings,
        &to_be_spent_values,
        &to_be_spent_serial_numbers,
        &to_be_spent_blinders,
        &range_proof_blinders,
        &to_be_issued_commitments,
        &to_be_issued_binding_number_commitments,
        &to_be_issued_values_commitments,
        &to_be_issued_serial_numbers_commitments,
        &to_be_spent_attributes_commitments,
        &to_be_spent_serial_numbers_commitments,
        &blinded_pay,
        &range_proof_decompositions_commitments,
    );

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
        range_proof_decompositions_signatures,
        proof,
    })
}

pub fn verify_request_vouchers(
    params: &Parameters,
    verification_key: &VerificationKey,
    range_proof_verification_key: &VerificationKey,
    theta: &ThetaRequestPhase,
    infos: &[Scalar],
) -> bool {
    if verification_key.beta_g2.len() < 4 {
        return false;
    }

    // TODO debug proof later
    // if !theta.verify_proof(params, verification_key, range_proof_verification_key) {
    //     return false;
    // }

    let to_be_spent_attributes_commitments: Vec<G2Projective> = theta
        .to_be_spent_attributes_commitments
        .iter()
        .zip(infos.iter())
        .map(|(to_be_spent_attributes_commitment, info)| {
            to_be_spent_attributes_commitment + verification_key.beta_g2()[3] * info
        })
        .collect();

    for (to_be_spent_signature, to_be_spent_attributes_commitment) in izip!(
        theta.to_be_spent_signatures.iter(),
        to_be_spent_attributes_commitments.iter()
    ) {
        if !check_bilinear_pairing(
            &to_be_spent_signature.0.to_affine(),
            &G2Prepared::from(to_be_spent_attributes_commitment.to_affine()),
            &to_be_spent_signature.1.to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }

        if bool::from(to_be_spent_signature.0.is_identity()) {
            return false;
        }
    }

    for (range_proof_decomposition_signature, range_proof_decomposition_commitment) in izip!(
        theta.range_proof_decompositions_signatures.iter().flatten(),
        theta
            .range_proof_decompositions_commitments
            .iter()
            .flatten()
    ) {
        if !check_bilinear_pairing(
            &range_proof_decomposition_signature.0.to_affine(),
            &G2Prepared::from(range_proof_decomposition_commitment.to_affine()),
            &range_proof_decomposition_signature.1.to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }

        if bool::from(range_proof_decomposition_signature.0.is_identity()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;

    use super::*;

    #[test]
    fn theta_request_phase_bytes_roundtrip() {
        let params = setup(4).unwrap();

        let keypair = keygen(&params);
        let verification_key = keypair.verification_key();
        let range_proof_keypair = keygen(&params);
        let range_proof_verification_key = range_proof_keypair.verification_key();
        let range_proof_secret_key = range_proof_keypair.secret_key();

        let number_of_to_be_issued_vouchers: u8 = 3;
        let number_of_to_be_spent_vouchers: u8 = 5;
        let range_proof_base_u: u8 = 8;
        let range_proof_number_of_elements_l: u8 = 4;

        let range_proof_h = params.gen1() * params.random_scalar();
        let range_proof_signatures = issue_range_signatures(
            &range_proof_h,
            &range_proof_secret_key,
            range_proof_base_u as usize,
        );

        let binding_number = params.random_scalar();

        let to_be_issued_values = [Scalar::from(10), Scalar::from(10), Scalar::from(5)];
        let to_be_issued_serial_numbers =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);

        let to_be_spent_values = [
            Scalar::from(6),
            Scalar::from(6),
            Scalar::from(6),
            Scalar::from(6),
            Scalar::from(6),
        ];

        let to_be_spent_serial_numbers =
            params.n_random_scalars(number_of_to_be_spent_vouchers as usize);

        let to_be_spent_signatures = [
            Signature(
                params.gen1() * params.random_scalar(),
                params.gen1() * params.random_scalar(),
            ),
            Signature(
                params.gen1() * params.random_scalar(),
                params.gen1() * params.random_scalar(),
            ),
            Signature(
                params.gen1() * params.random_scalar(),
                params.gen1() * params.random_scalar(),
            ),
            Signature(
                params.gen1() * params.random_scalar(),
                params.gen1() * params.random_scalar(),
            ),
            Signature(
                params.gen1() * params.random_scalar(),
                params.gen1() * params.random_scalar(),
            ),
        ];

        let theta = randomise_and_request_vouchers(
            &params,
            &verification_key,
            &range_proof_verification_key,
            &range_proof_signatures,
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            range_proof_base_u,
            range_proof_number_of_elements_l,
            &binding_number,
            &to_be_issued_values,
            &to_be_issued_serial_numbers,
            &to_be_spent_values,
            &to_be_spent_serial_numbers,
            &to_be_spent_signatures,
        )
        .unwrap();

        let theta_bytes = theta.to_bytes();
        let theta_from_bytes = ThetaRequestPhase::try_from(theta_bytes.as_slice()).unwrap();

        assert_eq!(theta_from_bytes, theta);
    }

    #[test]
    fn scalar_fits_in_u64_tests() {
        let zero = Scalar::from(0);
        let middle_value = Scalar::from(35065);
        let max = Scalar::from(u64::MAX);
        let overflow = max + Scalar::from(1);

        assert!(scalar_fits_in_u64(&zero));
        assert!(scalar_fits_in_u64(&middle_value));
        assert!(scalar_fits_in_u64(&max));
        assert!(!scalar_fits_in_u64(&overflow));
    }

    #[test]
    fn scalar_to_u64_tests() {
        let zero = 0;
        let middle_value = 35065;
        let max = u64::MAX;

        assert_eq!(scalar_to_u64(&Scalar::from(zero)), zero);
        assert_eq!(scalar_to_u64(&Scalar::from(middle_value)), middle_value);
        assert_eq!(scalar_to_u64(&Scalar::from(max)), max);
    }
}
