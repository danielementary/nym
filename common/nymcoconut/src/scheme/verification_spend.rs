// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use itertools::izip;
use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::ProofSpend;
use crate::scheme::check_bilinear_pairing;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::compute_kappa;
use crate::scheme::{Signature, VerificationKey};
use crate::traits::{Base58, Bytable};
use crate::utils::try_deserialize_g2_projective;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ThetaSpendPhase {
    pub number_of_vouchers_spent: u32,
    // blinded messages (kappas)
    pub blinded_messages: Vec<G2Projective>,
    // total amount spent
    pub blinded_spent_amount: G2Projective,
    // sigma
    pub vouchers_signatures: Vec<Signature>,
    // pi_v
    pub pi_v: ProofSpend,
}

impl TryFrom<&[u8]> for ThetaSpendPhase {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<ThetaSpendPhase> {
        // 4 + 96 + 96 + 96 + ? >= 292
        if bytes.len() < 292 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize ThetaSpendPhase with insufficient number of bytes, expected >= 292, got {}", bytes.len()),
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

        p = p_prime;
        p_prime += 96;
        let blinded_spent_amount_bytes = bytes[p..p_prime].try_into().unwrap();
        let blinded_spent_amount = try_deserialize_g2_projective(
            &blinded_spent_amount_bytes,
            CoconutError::Deserialization("failed to deserialize blinded spent amount".to_string()),
        )?;

        let mut vouchers_signatures = Vec::with_capacity(number_of_vouchers_spent as usize);
        for _ in 0..number_of_vouchers_spent {
            p = p_prime;
            p_prime += 96;

            let voucher_signature = Signature::try_from(&bytes[p..p_prime])?;

            vouchers_signatures.push(voucher_signature);
        }

        p = p_prime;
        let pi_v = ProofSpend::from_bytes(&bytes[p..])?;

        Ok(ThetaSpendPhase {
            number_of_vouchers_spent,
            blinded_messages,
            blinded_spent_amount,
            vouchers_signatures,
            pi_v,
        })
    }
}

impl ThetaSpendPhase {
    fn verify_proof(&self, params: &Parameters, verification_key: &VerificationKey) -> bool {
        self.pi_v.verify(
            params,
            verification_key,
            &self.blinded_messages,
            &self.blinded_spent_amount,
        )
    }

    // number of vouchers spent || blinded messages (kappa) ||  vouchers signatures || total amount || pi_v
    pub fn to_bytes(&self) -> Vec<u8> {
        let number_of_vouchers_spent_bytes = self.number_of_vouchers_spent.to_be_bytes();
        let blinded_message_bytes = self
            .blinded_messages
            .iter()
            .map(|m| m.to_affine().to_compressed())
            .flatten()
            .collect::<Vec<u8>>();
        let blinded_spent_amount_bytes = self.blinded_spent_amount.to_affine().to_compressed();
        let vouchers_signatures_bytes = self
            .vouchers_signatures
            .iter()
            .map(|s| s.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let pi_v_bytes = self.pi_v.to_bytes();

        let mut bytes = Vec::with_capacity(
            4 + self.number_of_vouchers_spent as usize * (96 + 96) + 96 + pi_v_bytes.len(),
        );

        bytes.extend(number_of_vouchers_spent_bytes);
        bytes.extend(blinded_message_bytes);
        bytes.extend(blinded_spent_amount_bytes);
        bytes.extend(vouchers_signatures_bytes);
        bytes.extend(pi_v_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ThetaSpendPhase> {
        ThetaSpendPhase::try_from(bytes)
    }
}

impl Bytable for ThetaSpendPhase {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        ThetaSpendPhase::try_from(slice)
    }
}

impl Base58 for ThetaSpendPhase {}

pub fn randomise_and_spend_vouchers(
    params: &Parameters,
    verification_key: &VerificationKey,
    binding_number: &Scalar,
    values: &[Scalar],
    signatures: &[Signature],
) -> Result<ThetaSpendPhase> {
    if verification_key.beta_g2.len() < 3 {
        return Err(
            CoconutError::Verification(
                format!("Tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: 3)",
                        verification_key.beta_g2.len()
                )));
    }

    // Randomize the signature
    let (signatures_prime, signatures_blinding_factors): (Vec<Signature>, Vec<Scalar>) =
        signatures.iter().map(|s| s.randomise(&params)).unzip();

    let blinded_messages: Vec<_> = izip!(values.iter(), signatures_blinding_factors.iter())
        .map(|(v, sbf)| {
            let private_attributes = vec![*binding_number, *v];
            compute_kappa(&params, &verification_key, &private_attributes, *sbf)
        })
        .collect();

    let blinded_spent_amount = values.iter().map(|v| params.gen2() * v).sum();

    let number_of_vouchers_spent = values.len() as u32;
    let pi_v = ProofSpend::construct(
        &params,
        &verification_key,
        number_of_vouchers_spent,
        &binding_number,
        &values,
        &signatures_blinding_factors,
        &blinded_messages,
        &blinded_spent_amount,
    );

    Ok(ThetaSpendPhase {
        number_of_vouchers_spent,
        blinded_messages,
        blinded_spent_amount,
        vouchers_signatures: signatures_prime,
        pi_v,
    })
}

pub fn verify_spent_vouchers(
    params: &Parameters,
    verification_key: &VerificationKey,
    theta: &ThetaSpendPhase,
    serial_numbers: &[Scalar],
    infos: &[Scalar],
) -> bool {
    if verification_key.beta_g2.len() < 4 {
        return false;
    }

    if !theta.verify_proof(params, verification_key) {
        return false;
    }

    let blinded_messages: Vec<_> = izip!(
        theta.blinded_messages.iter(),
        serial_numbers.iter(),
        infos.iter()
    )
    .map(|(bm, sn, i)| bm + verification_key.beta_g2()[2] * sn + verification_key.beta_g2()[3] * i)
    .collect();

    for (vs, bm) in izip!(theta.vouchers_signatures.iter(), blinded_messages.iter()) {
        if !check_bilinear_pairing(
            &vs.0.to_affine(),
            &G2Prepared::from(bm.to_affine()),
            &vs.1.to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }

        if bool::from(vs.0.is_identity()) {
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
    fn theta_bytes_roundtrip() {
        let params = setup(4).unwrap();

        let keypair = keygen(&params);
        let verification_key = keypair.verification_key();

        let binding_number = params.random_scalar();

        // test one voucher
        let values = [Scalar::from(10)];
        let signatures = [Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        )];

        let theta = randomise_and_spend_vouchers(
            &params,
            &verification_key,
            &binding_number,
            &values,
            &signatures,
        )
        .unwrap();

        let bytes = theta.to_bytes();
        assert_eq!(ThetaSpendPhase::try_from(bytes.as_slice()).unwrap(), theta);

        // test three vouchers
        let values = [Scalar::from(10), Scalar::from(10), Scalar::from(10)];
        let signatures = [
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

        let theta = randomise_and_spend_vouchers(
            &params,
            &verification_key,
            &binding_number,
            &values,
            &signatures,
        )
        .unwrap();

        let bytes = theta.to_bytes();
        assert_eq!(ThetaSpendPhase::try_from(bytes.as_slice()).unwrap(), theta);
    }
}
