// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::ProofSpend;
use crate::scheme::check_bilinear_pairing;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::{compute_kappa, compute_zeta};
use crate::scheme::{Signature, VerificationKey};
use crate::traits::{Base58, Bytable};
use crate::utils::{try_deserialize_g2_projective, try_deserialize_scalar};
use crate::Attribute;

// TODO NAMING: this whole thing
// ThetaSpend
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ThetaSpend {
    pub number_of_vouchers_spent: u32,
    // blinded messages (kappas)
    pub blinded_messages: Vec<G2Projective>,
    // blinded serial numbers (zetas)
    pub blinded_serial_numbers: Vec<G2Projective>,
    // sigma
    pub vouchers_signatures: Vec<Signature>,
    // total amount spent
    pub total_amount: Scalar,
    // pi_v
    pub pi_v: ProofSpend,
}

impl TryFrom<&[u8]> for ThetaSpend {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<ThetaSpend> {
        // 4 + 96 + 96 + 96 + 32 + ? >= 324
        if bytes.len() < 324 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize ThetaSpend with insufficient number of bytes, expected >= 324, got {}", bytes.len()),
                ));
        }

        let mut p = 0;
        let mut p_prime = 4;
        let number_of_vouchers_spent = u32::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        let mut blinded_messages = Vec::with_capacity(number_of_vouchers_spent as usize);
        for i in 0..number_of_vouchers_spent {
            p = p_prime;
            p_prime += 96;

            let blinded_message_bytes = bytes[p..p_prime].try_into().unwrap();
            let blinded_message = try_deserialize_g2_projective(
                &blinded_message_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the blinded message (kappa) at index {}",
                    i
                )),
            )?;

            blinded_messages.push(blinded_message);
        }

        let mut blinded_serial_numbers = Vec::with_capacity(number_of_vouchers_spent as usize);
        for i in 0..number_of_vouchers_spent {
            p = p_prime;
            p_prime += 96;

            let blinded_serial_number_bytes = bytes[p..p_prime].try_into().unwrap();
            let blinded_serial_number = try_deserialize_g2_projective(
                &blinded_serial_number_bytes,
                CoconutError::Deserialization(format!(
                    "failed to deserialize the blinded serial number (zeta) at index {}",
                    i
                )),
            )?;

            blinded_serial_numbers.push(blinded_serial_number);
        }

        let mut vouchers_signatures = Vec::with_capacity(number_of_vouchers_spent as usize);
        for i in 0..number_of_vouchers_spent {
            p = p_prime;
            p_prime += 96;

            let voucher_signature = Signature::try_from(&bytes[p..p_prime])?;

            vouchers_signatures.push(voucher_signature);
        }

        p = p_prime;
        p_prime += 32;
        let total_amount_bytes = bytes[p..p_prime].try_into().unwrap();
        let total_amount = try_deserialize_scalar(
            &total_amount_bytes,
            CoconutError::Deserialization("failed to deserialize total amount".to_string()),
        )?;

        p = p_prime;
        let pi_v = ProofSpend::from_bytes(&bytes[p..])?;

        Ok(ThetaSpend {
            number_of_vouchers_spent,
            blinded_messages,
            blinded_serial_numbers,
            vouchers_signatures,
            total_amount,
            pi_v,
        })
    }
}

impl ThetaSpend {
    fn verify_proof(&self, params: &Parameters, verification_key: &VerificationKey) -> bool {
        self.pi_v.verify(
            params,
            verification_key,
            &self.blinded_messages,
            &self.blinded_serial_numbers,
            &self.total_amount,
        )
    }

    // number of vouchers spent || blinded messages (kappa) || blinded serial numbers (zeta) || vouchers signatures || total amount || pi_v
    pub fn to_bytes(&self) -> Vec<u8> {
        let number_of_vouchers_spent_bytes = self.number_of_vouchers_spent.to_be_bytes();
        let blinded_message_bytes = self
            .blinded_messages
            .iter()
            .map(|m| m.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();
        let blinded_serial_number_bytes = self
            .blinded_serial_numbers
            .iter()
            .map(|sn| sn.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();
        let vouchers_signatures_bytes = self
            .vouchers_signatures
            .iter()
            .map(|s| s.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let total_amount_bytes = self.total_amount.to_bytes();
        let pi_v_bytes = self.pi_v.to_bytes();

        let mut bytes = Vec::with_capacity(
            4 + self.number_of_vouchers_spent as usize * (96 + 96 + 96 + 32) + pi_v_bytes.len(),
        );

        bytes.extend(number_of_vouchers_spent_bytes);
        bytes.extend(blinded_message_bytes);
        bytes.extend(blinded_serial_number_bytes);
        bytes.extend(total_amount_bytes);
        bytes.extend(total_amount_bytes);
        bytes.extend(pi_v_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ThetaSpend> {
        ThetaSpend::try_from(bytes)
    }
}

impl Bytable for ThetaSpend {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        ThetaSpend::try_from(slice)
    }
}

impl Base58 for ThetaSpend {}

pub fn prove_bandwidth_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    signature: &Signature,
    serial_number: Attribute,
    binding_number: Attribute,
) -> Result<ThetaSpend> {
    if verification_key.beta_g2.len() < 2 {
        return Err(
            CoconutError::Verification(
                format!("Tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: 2)",
                        verification_key.beta_g2.len()
                )));
    }

    // Randomize the signature
    let (signature_prime, sign_blinding_factor) = signature.randomise(params);

    // blinded_message : kappa in the paper.
    // Value kappa is needed since we want to show a signature sigma'.
    // In order to verify sigma' we need both the verification key vk and the message m.
    // However, we do not want to reveal m to whomever we are showing the signature.
    // Thus, we need kappa which allows us to verify sigma'. In particular,
    // kappa is computed on m as input, but thanks to the use or random value r,
    // it does not reveal any information about m.
    let private_attributes = vec![serial_number, binding_number];
    let blinded_message = compute_kappa(
        params,
        verification_key,
        &private_attributes,
        sign_blinding_factor,
    );

    // zeta is a commitment to the serial number (i.e., a public value associated with the serial number)
    let blinded_serial_number = compute_zeta(params, serial_number);

    let pi_v = ProofSpend::construct(
        params,
        verification_key,
        &serial_number,
        &binding_number,
        &sign_blinding_factor,
        &blinded_message,
        &blinded_serial_number,
    );

    Ok(ThetaSpend {
        blinded_message,
        blinded_serial_number,
        credential: signature_prime,
        pi_v,
    })
}

pub fn verify_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    theta: &ThetaSpend,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.pi_v.private_attributes_len()
        > verification_key.beta_g2.len()
    {
        return false;
    }

    if !theta.verify_proof(params, verification_key) {
        return false;
    }

    let kappa = if public_attributes.is_empty() {
        theta.blinded_message
    } else {
        let signed_public_attributes = public_attributes
            .iter()
            .zip(
                verification_key
                    .beta_g2
                    .iter()
                    .skip(theta.pi_v.private_attributes_len()),
            )
            .map(|(pub_attr, beta_i)| beta_i * pub_attr)
            .sum::<G2Projective>();

        theta.blinded_message + signed_public_attributes
    };

    check_bilinear_pairing(
        &theta.credential.0.to_affine(),
        &G2Prepared::from(kappa.to_affine()),
        &(theta.credential.1).to_affine(),
        params.prepared_miller_g2(),
    ) && !bool::from(theta.credential.0.is_identity())
}

#[cfg(test)]
mod tests {
    // use crate::scheme::keygen::keygen;
    // use crate::scheme::setup::setup;

    // use super::*;

    // #[test]
    // fn theta_bytes_roundtrip() {
    //     let mut params = setup(2).unwrap();

    //     let keypair = keygen(&mut params);
    //     let r = params.random_scalar();
    //     let s = params.random_scalar();

    //     let signature = Signature(params.gen1() * r, params.gen1() * s);
    //     let serial_number = params.random_scalar();
    //     let binding_number = params.random_scalar();

    //     let theta = prove_bandwidth_credential(
    //         &mut params,
    //         &keypair.verification_key(),
    //         &signature,
    //         serial_number,
    //         binding_number,
    //     )
    //     .unwrap();

    //     let bytes = theta.to_bytes();
    //     assert_eq!(Theta::try_from(bytes.as_slice()).unwrap(), theta);
    // }
}
