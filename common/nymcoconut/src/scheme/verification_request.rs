// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use itertools::izip;
use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G2Prepared, G2Projective, Scalar};
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

impl TryFrom<&[u8]> for ThetaSpend {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<ThetaSpend> {
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
            let to_be_spent_attributes_commitment = try_deserialize_g1_projective(
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
            let to_be_spent_serial_numbers_commitment = try_deserialize_g1_projective(
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
                let range_proof_decomposition_commitment = try_deserialize_g1_projective(
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

// impl ThetaSpend {
//     fn verify_proof(&self, params: &Parameters, verification_key: &VerificationKey) -> bool {
//         self.pi_v.verify(
//             params,
//             verification_key,
//             &self.blinded_messages,
//             &self.blinded_serial_numbers,
//             &self.blinded_spent_amount,
//         )
//     }

//     // number of vouchers spent || blinded messages (kappa) || blinded serial numbers (zeta) || vouchers signatures || total amount || pi_v
//     pub fn to_bytes(&self) -> Vec<u8> {
//         let number_of_vouchers_spent_bytes = self.number_of_vouchers_spent.to_be_bytes();
//         let blinded_message_bytes = self
//             .blinded_messages
//             .iter()
//             .map(|m| m.to_affine().to_compressed())
//             .flatten()
//             .collect::<Vec<u8>>();
//         let blinded_serial_number_bytes = self
//             .blinded_serial_numbers
//             .iter()
//             .map(|sn| sn.to_affine().to_compressed())
//             .flatten()
//             .collect::<Vec<u8>>();
//         let blinded_spent_amount_bytes = self.blinded_spent_amount.to_affine().to_compressed();
//         let vouchers_signatures_bytes = self
//             .vouchers_signatures
//             .iter()
//             .map(|s| s.to_bytes())
//             .flatten()
//             .collect::<Vec<u8>>();
//         let pi_v_bytes = self.pi_v.to_bytes();

//         let mut bytes = Vec::with_capacity(
//             4 + self.number_of_vouchers_spent as usize * (96 + 96 + 96) + 96 + pi_v_bytes.len(),
//         );

//         bytes.extend(number_of_vouchers_spent_bytes);
//         bytes.extend(blinded_message_bytes);
//         bytes.extend(blinded_serial_number_bytes);
//         bytes.extend(blinded_spent_amount_bytes);
//         bytes.extend(vouchers_signatures_bytes);
//         bytes.extend(pi_v_bytes);

//         bytes
//     }

//     pub fn from_bytes(bytes: &[u8]) -> Result<ThetaSpend> {
//         ThetaSpend::try_from(bytes)
//     }
// }

// impl Bytable for ThetaSpend {
//     fn to_byte_vec(&self) -> Vec<u8> {
//         self.to_bytes()
//     }

//     fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
//         ThetaSpend::try_from(slice)
//     }
// }

// impl Base58 for ThetaSpend {}

// pub fn randomise_and_prove_vouchers(
//     params: &Parameters,
//     verification_key: &VerificationKey,
//     binding_number: &Scalar,
//     values: &[Scalar],
//     serial_numbers: &[Scalar],
//     signatures: &[Signature],
// ) -> Result<ThetaSpend> {
//     if verification_key.beta_g2.len() < 3 {
//         return Err(
//             CoconutError::Verification(
//                 format!("Tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: 3)",
//                         verification_key.beta_g2.len()
//                 )));
//     }

//     // Randomize the signature
//     let (signatures_prime, signatures_blinding_factors): (Vec<Signature>, Vec<Scalar>) =
//         signatures.iter().map(|s| s.randomise(&params)).unzip();

//     // blinded_message : kappa in the paper.
//     // Value kappa is needed since we want to show a signature sigma'.
//     // In order to verify sigma' we need both the verification key vk and the message m.
//     // However, we do not want to reveal m to whomever we are showing the signature.
//     // Thus, we need kappa which allows us to verify sigma'. In particular,
//     // kappa is computed on m as input, but thanks to the use or random value r,
//     // it does not reveal any information about m.
//     let blinded_messages: Vec<_> = izip!(
//         values.iter(),
//         serial_numbers.iter(),
//         signatures_blinding_factors.iter()
//     )
//     .map(|(v, sn, sbf)| {
//         let private_attributes = vec![*binding_number, *v, *sn];
//         compute_kappa(&params, &verification_key, &private_attributes, *sbf)
//     })
//     .collect();

//     // zeta is a commitment to the serial number (i.e., a public value associated with the serial number)
//     let blinded_serial_numbers: Vec<_> = serial_numbers
//         .iter()
//         .map(|sn| compute_zeta(&params, *sn))
//         .collect();

//     let blinded_spent_amount = values.iter().map(|v| params.gen2() * v).sum();

//     let number_of_vouchers_spent = values.len() as u32;
//     let pi_v = ProofSpend::construct(
//         &params,
//         &verification_key,
//         number_of_vouchers_spent,
//         &binding_number,
//         &values,
//         &serial_numbers,
//         &signatures_blinding_factors,
//         &blinded_messages,
//         &blinded_serial_numbers,
//         &blinded_spent_amount,
//     );

//     Ok(ThetaSpend {
//         number_of_vouchers_spent,
//         blinded_messages,
//         blinded_serial_numbers,
//         blinded_spent_amount,
//         vouchers_signatures: signatures_prime,
//         pi_v,
//     })
// }

// pub fn verify_vouchers(
//     params: &Parameters,
//     verification_key: &VerificationKey,
//     theta: &ThetaSpend,
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
//         assert_eq!(ThetaSpend::try_from(bytes.as_slice()).unwrap(), theta);

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
//         assert_eq!(ThetaSpend::try_from(bytes.as_slice()).unwrap(), theta);
//     }
// }
