// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

// TODO: look at https://crates.io/crates/merlin to perhaps use it instead?

use std::borrow::Borrow;
use std::convert::TryInto;

use bls12_381::{G1Projective, G2Projective, Scalar};
use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use group::GroupEncoding;
use itertools::izip;
use sha2::Sha256;

use crate::error::{CoconutError, Result};
use crate::scheme::setup::Parameters;
use crate::scheme::VerificationKey;
use crate::utils::{hash_g1, try_deserialize_scalar, try_deserialize_scalar_vec};
use crate::Attribute;

// as per the reference python implementation
type ChallengeDigest = Sha256;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofCmCs {
    challenge: Scalar,
    response_opening: Scalar,
    response_openings: Vec<Scalar>,
    response_attributes: Vec<Scalar>,
}

// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library all elements are using big-endian form
/// Generates a Scalar [or Fp] challenge by hashing a number of elliptic curve points.  
fn compute_challenge<D, I, B>(iter: I) -> Scalar
where
    D: Digest,
    I: Iterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut h = D::new();
    for point_representation in iter {
        h.update(point_representation);
    }
    let digest = h.finalize();

    // TODO: I don't like the 0 padding here (though it's what we've been using before,
    // but we never had a security audit anyway...)
    // instead we could maybe use the `from_bytes` variant and adding some suffix
    // when computing the digest until we produce a valid scalar.
    let mut bytes = [0u8; 64];
    let pad_size = 64usize
        .checked_sub(D::OutputSize::to_usize())
        .unwrap_or_default();

    bytes[pad_size..].copy_from_slice(&digest);

    Scalar::from_bytes_wide(&bytes)
}

fn produce_response(witness: &Scalar, challenge: &Scalar, secret: &Scalar) -> Scalar {
    witness - challenge * secret
}

// note: it's caller's responsibility to ensure witnesses.len() = secrets.len()
fn produce_responses<S>(witnesses: &[Scalar], challenge: &Scalar, secrets: &[S]) -> Vec<Scalar>
where
    S: Borrow<Scalar>,
{
    debug_assert_eq!(witnesses.len(), secrets.len());

    witnesses
        .iter()
        .zip(secrets.iter())
        .map(|(w, x)| produce_response(w, challenge, x.borrow()))
        .collect()
}

impl ProofCmCs {
    /// Construct non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment
    /// using the Fiat-Shamir heuristic.
    pub(crate) fn construct(
        params: &Parameters,
        commitment: &G1Projective,
        commitment_opening: &Scalar,
        commitments: &[G1Projective],
        pedersen_commitments_openings: &[Scalar],
        private_attributes: &[Attribute],
    ) -> Self {
        // note: this is only called from `prepare_blind_sign` that already checks
        // whether private attributes are non-empty and whether we don't have too many
        // attributes in total to sign.
        // we also know, due to the single call place, that ephemeral_keys.len() == private_attributes.len()

        // witness creation
        let witness_commitment_opening = params.random_scalar();
        let witness_pedersen_commitments_openings =
            params.n_random_scalars(pedersen_commitments_openings.len());
        let witness_attributes = params.n_random_scalars(private_attributes.len());

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let hs_bytes = params
            .hs1()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        let g1 = params.gen1();

        // compute commitments

        // zkp commitment for the attributes commitment cm
        // Ccm = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_commitment_opening
            + witness_attributes
                .iter()
                .zip(params.hs1().iter())
                .map(|(wm_i, hs_i)| hs_i * wm_i)
                .sum::<G1Projective>();

        // zkp commitments for the individual attributes
        let commitments_attributes = witness_pedersen_commitments_openings
            .iter()
            .zip(witness_attributes.iter())
            .map(|(o_j, m_j)| g1 * o_j + h * m_j)
            .collect::<Vec<_>>();

        let commitments_bytes = commitments
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        let commitments_attributes_bytes = commitments_attributes
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        // compute challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(commitments_bytes.iter().map(|cm| cm.as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(commitments_attributes_bytes.iter().map(|cm| cm.as_ref())),
        );

        // Responses
        let response_opening =
            produce_response(&witness_commitment_opening, &challenge, commitment_opening);
        let response_openings = produce_responses(
            &witness_pedersen_commitments_openings,
            &challenge,
            &pedersen_commitments_openings.iter().collect::<Vec<_>>(),
        );
        let response_attributes = produce_responses(
            &witness_attributes,
            &challenge,
            &private_attributes.iter().collect::<Vec<_>>(),
        );

        ProofCmCs {
            challenge,
            response_opening,
            response_openings,
            response_attributes,
        }
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        commitment: &G1Projective,
        commitments: &[G1Projective],
    ) -> bool {
        if self.response_attributes.len() != commitments.len() {
            return false;
        }

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let g1 = params.gen1();

        let hs_bytes = params
            .hs1()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // recompute witnesses commitments
        // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[n] * hs[n])
        let commitment_attributes = commitment * self.challenge
            + g1 * self.response_opening
            + self
                .response_attributes
                .iter()
                .zip(params.hs1().iter())
                .map(|(res_attr, hs)| hs * res_attr)
                .sum::<G1Projective>();

        let commitments_attributes = izip!(
            commitments.iter(),
            self.response_openings.iter(),
            self.response_attributes.iter()
        )
        .map(|(cm_j, r_o_j, r_m_j)| cm_j * self.challenge + g1 * r_o_j + h * r_m_j)
        .collect::<Vec<_>>();

        let commitments_bytes = commitments
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        let commitments_attributes_bytes = commitments_attributes
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        // re-compute the challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(commitments_bytes.iter().map(|cm| cm.as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(commitments_attributes_bytes.iter().map(|cm| cm.as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || response opening || response private elgamal key || keys len || response keys || attributes len || response attributes
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let openings_len = self.response_openings.len() as u64;
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(16 + (2 + openings_len + attributes_len) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_opening.to_bytes());

        bytes.extend_from_slice(&openings_len.to_le_bytes());
        for ro in &self.response_openings {
            bytes.extend_from_slice(&ro.to_bytes());
        }

        bytes.extend_from_slice(&attributes_len.to_le_bytes());
        for rm in &self.response_attributes {
            bytes.extend_from_slice(&rm.to_bytes());
        }

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 4 + 16 || (bytes.len() - 16) % 32 != 0 {
            return Err(CoconutError::Deserialization(
                "tried to deserialize proof of commitments with bytes of invalid length"
                    .to_string(),
            ));
        }

        let mut idx = 0;
        let challenge_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;
        let response_opening_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;

        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;

        let response_opening = try_deserialize_scalar(
            &response_opening_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize the response to the random".to_string(),
            ),
        )?;

        let ro_len = u64::from_le_bytes(bytes[idx..idx + 8].try_into().unwrap());
        idx += 8;
        if bytes[idx..].len() < ro_len as usize * 32 + 8 {
            return Err(
                CoconutError::Deserialization(
                    "tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided".to_string()),
            );
        }

        let ro_end = idx + ro_len as usize * 32;
        let response_openings = try_deserialize_scalar_vec(
            ro_len,
            &bytes[idx..ro_end],
            CoconutError::Deserialization("Failed to deserialize openings response".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[ro_end..ro_end + 8].try_into().unwrap());
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[ro_end + 8..],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        Ok(ProofCmCs {
            challenge,
            response_opening,
            response_openings,
            response_attributes,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofKappaZeta {
    // c
    challenge: Scalar,

    // responses
    response_serial_number: Scalar,
    response_binding_number: Scalar,
    response_blinder: Scalar,
}

impl ProofKappaZeta {
    pub(crate) fn construct(
        params: &Parameters,
        verification_key: &VerificationKey,
        serial_number: &Attribute,
        binding_number: &Attribute,
        blinding_factor: &Scalar,
        blinded_message: &G2Projective,
        blinded_serial_number: &G2Projective,
    ) -> Self {
        // create the witnesses
        let witness_blinder = params.random_scalar();
        let witness_serial_number = params.random_scalar();
        let witness_binding_number = params.random_scalar();
        let witness_attributes = vec![witness_serial_number, witness_binding_number];

        let beta_bytes = verification_key
            .beta_g2
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // witnesses commitments
        // Aw = g2 * wt + alpha + beta[0] * wm[0] + ... + beta[i] * wm[i]
        let commitment_kappa = params.gen2() * witness_blinder
            + verification_key.alpha
            + witness_attributes
                .iter()
                .zip(verification_key.beta_g2.iter())
                .map(|(wm_i, beta_i)| beta_i * wm_i)
                .sum::<G2Projective>();

        // zeta is the public value associated with the serial number
        let commitment_zeta = params.gen2() * witness_serial_number;

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen2().to_bytes().as_ref())
                .chain(std::iter::once(blinded_message.to_bytes().as_ref()))
                .chain(std::iter::once(blinded_serial_number.to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_zeta.to_bytes().as_ref())),
        );

        // responses
        let response_blinder = produce_response(&witness_blinder, &challenge, blinding_factor);
        let response_serial_number =
            produce_response(&witness_serial_number, &challenge, serial_number);
        let response_binding_number =
            produce_response(&witness_binding_number, &challenge, binding_number);

        ProofKappaZeta {
            challenge,
            response_serial_number,
            response_binding_number,
            response_blinder,
        }
    }

    pub(crate) fn private_attributes_len(&self) -> usize {
        2
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        kappa: &G2Projective,
        zeta: &G2Projective,
    ) -> bool {
        let beta_bytes = verification_key
            .beta_g2
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        let response_attributes = vec![self.response_serial_number, self.response_binding_number];
        // re-compute witnesses commitments
        // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
        let commitment_kappa = kappa * self.challenge
            + params.gen2() * self.response_blinder
            + verification_key.alpha * (Scalar::one() - self.challenge)
            + response_attributes
                .iter()
                .zip(verification_key.beta_g2.iter())
                .map(|(priv_attr, beta_i)| beta_i * priv_attr)
                .sum::<G2Projective>();

        // zeta is the public value associated with the serial number
        let commitment_zeta = zeta * self.challenge + params.gen2() * self.response_serial_number;

        // compute the challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen2().to_bytes().as_ref())
                .chain(std::iter::once(kappa.to_bytes().as_ref()))
                .chain(std::iter::once(zeta.to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_zeta.to_bytes().as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || response serial number || response binding number || repose blinder
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let attributes_len = 2; // because we have serial number and the binding number
        let mut bytes = Vec::with_capacity((1 + attributes_len + 1) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_serial_number.to_bytes());
        bytes.extend_from_slice(&self.response_binding_number.to_bytes());

        bytes.extend_from_slice(&self.response_blinder.to_bytes());

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 4 || (bytes.len()) % 32 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len(),
                modulus: 32,
                object: "kappa and zeta".to_string(),
                target: 32 * 4,
            });
        }

        let challenge_bytes = bytes[..32].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;

        let serial_number_bytes = &bytes[32..64].try_into().unwrap();
        let response_serial_number = try_deserialize_scalar(
            serial_number_bytes,
            CoconutError::Deserialization("failed to deserialize the serial number".to_string()),
        )?;

        let binding_number_bytes = &bytes[64..96].try_into().unwrap();
        let response_binding_number = try_deserialize_scalar(
            binding_number_bytes,
            CoconutError::Deserialization("failed to deserialize the binding number".to_string()),
        )?;

        let blinder_bytes = bytes[96..].try_into().unwrap();
        let response_blinder = try_deserialize_scalar(
            &blinder_bytes,
            CoconutError::Deserialization("failed to deserialize the blinder".to_string()),
        )?;

        Ok(ProofKappaZeta {
            challenge,
            response_serial_number,
            response_binding_number,
            response_blinder,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofSpend {
    number_of_vouchers_spent: u32,
    // c
    challenge: Scalar,
    // responses
    response_binding_number: Scalar,
    responses_values: Vec<Scalar>,
    responses_serial_numbers: Vec<Scalar>,
    responses_blinders: Vec<Scalar>,
}

impl ProofSpend {
    pub(crate) fn construct(
        params: &Parameters,
        verification_key: &VerificationKey,
        number_of_vouchers_spent: u32,
        binding_number: &Scalar,
        values: &[Scalar],
        serial_numbers: &[Scalar],
        signatures_blinding_factors: &[Scalar],
        blinded_messages_kappa: &[G2Projective],
        blinded_serial_numbers_zeta: &[G2Projective],
        blinded_sum_c: &G2Projective,
    ) -> Self {
        // create the witnesses
        let witness_binding_number = params.random_scalar();
        let witnesses_values = params.n_random_scalars(values.len());
        let witnesses_serial_numbers = params.n_random_scalars(serial_numbers.len());
        let witnesses_signatures_blinding_factors =
            params.n_random_scalars(signatures_blinding_factors.len());

        // witnesses commitments
        let commitments_kappa: Vec<G2Projective> = izip!(
            witnesses_values.iter(),
            witnesses_serial_numbers.iter(),
            witnesses_signatures_blinding_factors.iter()
        )
        .map(|(v, sn, b)| {
            verification_key.alpha()
                + verification_key.beta_g2()[0] * witness_binding_number
                + verification_key.beta_g2()[1] * v
                + verification_key.beta_g2()[2] * sn
                + params.gen2() * b
        })
        .collect();

        let commitments_zeta: Vec<G2Projective> = witnesses_serial_numbers
            .iter()
            .map(|sn| params.gen2() * sn)
            .collect();

        let commitment_c: G2Projective = witnesses_values.iter().map(|v| params.gen2() * v).sum();

        let blinded_messages_kappa_bytes: Vec<_> = blinded_messages_kappa
            .iter()
            .map(|bmk| bmk.to_bytes())
            .collect();
        let blinded_serial_numbers_zeta_bytes: Vec<_> = blinded_serial_numbers_zeta
            .iter()
            .map(|bsnz| bsnz.to_bytes())
            .collect();

        let betas_g2_bytes: Vec<_> = verification_key
            .beta_g2()
            .iter()
            .map(|b| b.to_bytes())
            .collect();

        let commitments_kappa_bytes: Vec<_> =
            commitments_kappa.iter().map(|ck| ck.to_bytes()).collect();
        let commitments_zeta_bytes: Vec<_> =
            commitments_zeta.iter().map(|cz| cz.to_bytes()).collect();

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            blinded_messages_kappa_bytes
                .iter()
                .map(|b| b.as_ref())
                .chain(blinded_serial_numbers_zeta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(blinded_sum_c.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    verification_key.alpha().to_bytes().as_ref(),
                ))
                .chain(betas_g2_bytes.iter().map(|b| b.as_ref()))
                .chain(commitments_kappa_bytes.iter().map(|b| b.as_ref()))
                .chain(commitments_zeta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_c.to_bytes().as_ref())),
        );

        // responses
        let response_binding_number =
            produce_response(&witness_binding_number, &challenge, &binding_number);
        let responses_values = produce_responses(&witnesses_values, &challenge, &values);
        let responses_serial_numbers =
            produce_responses(&witnesses_serial_numbers, &challenge, &serial_numbers);
        let responses_blinders = produce_responses(
            &witnesses_signatures_blinding_factors,
            &challenge,
            &signatures_blinding_factors,
        );

        ProofSpend {
            number_of_vouchers_spent,
            challenge,
            response_binding_number,
            responses_values,
            responses_serial_numbers,
            responses_blinders,
        }
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        blinded_messages_kappa: &[G2Projective],
        blinded_serial_numbers_zeta: &[G2Projective],
        blinded_sum_c: &G2Projective,
    ) -> bool {
        // re-compute witnesses commitments
        // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
        let commitments_kappa: Vec<_> = izip!(
            blinded_messages_kappa.iter(),
            self.responses_values.iter(),
            self.responses_serial_numbers.iter(),
            self.responses_blinders.iter(),
        )
        .map(|(k, v, sn, b)| {
            k * self.challenge
                + verification_key.alpha() * (Scalar::one() - self.challenge)
                + verification_key.beta_g2()[0] * self.response_binding_number
                + verification_key.beta_g2()[1] * v
                + verification_key.beta_g2()[2] * sn
                + params.gen2() * b
        })
        .collect();

        // zeta is the public value associated with the serial number
        let commitments_zeta: Vec<_> = izip!(
            blinded_serial_numbers_zeta.iter(),
            self.responses_serial_numbers.iter()
        )
        .map(|(z, sn)| z * self.challenge + params.gen2() * sn)
        .collect();

        let commitment_c = blinded_sum_c * self.challenge
            + self
                .responses_values
                .iter()
                .map(|v| params.gen2() * v)
                .sum::<G2Projective>();

        let blinded_messages_kappa_bytes: Vec<_> = blinded_messages_kappa
            .iter()
            .map(|bmk| bmk.to_bytes())
            .collect();
        let blinded_serial_numbers_zeta_bytes: Vec<_> = blinded_serial_numbers_zeta
            .iter()
            .map(|bsnz| bsnz.to_bytes())
            .collect();

        let betas_g2_bytes: Vec<_> = verification_key
            .beta_g2()
            .iter()
            .map(|b| b.to_bytes())
            .collect();

        // compute the challenge
        let commitments_kappa_bytes: Vec<_> =
            commitments_kappa.iter().map(|ck| ck.to_bytes()).collect();
        let commitments_zeta_bytes: Vec<_> =
            commitments_zeta.iter().map(|cz| cz.to_bytes()).collect();

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            blinded_messages_kappa_bytes
                .iter()
                .map(|b| b.as_ref())
                .chain(blinded_serial_numbers_zeta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(blinded_sum_c.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    verification_key.alpha().to_bytes().as_ref(),
                ))
                .chain(betas_g2_bytes.iter().map(|b| b.as_ref()))
                .chain(commitments_kappa_bytes.iter().map(|b| b.as_ref()))
                .chain(commitments_zeta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_c.to_bytes().as_ref())),
        );

        challenge == self.challenge
    }

    // number of vouchers spent || challenge || response binding number || responses values ||
    // responses serial numbers || responses blinders
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(4 + 32 + 32 + (3 * self.number_of_vouchers_spent) as usize * 32);

        let responses_values_bytes = self
            .responses_values
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_serial_numbers_bytes = self
            .responses_serial_numbers
            .iter()
            .map(|sn| sn.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_blinders_bytes = self
            .responses_blinders
            .iter()
            .map(|b| b.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        bytes.extend_from_slice(&self.number_of_vouchers_spent.to_be_bytes());
        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_binding_number.to_bytes());
        bytes.extend(responses_values_bytes);
        bytes.extend(responses_serial_numbers_bytes);
        bytes.extend(responses_blinders_bytes);

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 5 + 4 || (bytes.len() - 4) % 32 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len(),
                modulus: 32,
                object: "kappa and zeta and C".to_string(),
                target: 32 * 5,
            });
        }

        let mut p = 0;
        let mut p_prime = 4;
        let number_of_vouchers_spent = u32::from_be_bytes(bytes[p..p_prime].try_into().unwrap());

        p = p_prime;
        p_prime += 32;
        let challenge_bytes = &bytes[p..p_prime].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            challenge_bytes,
            CoconutError::Deserialization("failed to deserialize the challenge".to_string()),
        )?;

        p = p_prime;
        p_prime += 32;
        let response_binding_number_bytes = &bytes[p..p_prime].try_into().unwrap();
        let response_binding_number = try_deserialize_scalar(
            response_binding_number_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the response binding number".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_vouchers_spent as usize;
        let responses_values_bytes = &bytes[p..p_prime];
        let responses_values = try_deserialize_scalar_vec(
            number_of_vouchers_spent as u64,
            &responses_values_bytes,
            CoconutError::Deserialization("failed to deserialize the responses values".to_string()),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_vouchers_spent as usize;
        let responses_serial_numbers_bytes = &bytes[p..p_prime];
        let responses_serial_numbers = try_deserialize_scalar_vec(
            number_of_vouchers_spent as u64,
            &responses_serial_numbers_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses serial numbers".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_vouchers_spent as usize;
        let responses_blinders_bytes = &bytes[p..p_prime];
        let responses_blinders = try_deserialize_scalar_vec(
            number_of_vouchers_spent as u64,
            &responses_blinders_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses blinders".to_string(),
            ),
        )?;

        Ok(ProofSpend {
            number_of_vouchers_spent,
            challenge,
            response_binding_number,
            responses_values,
            responses_serial_numbers,
            responses_blinders,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofRequestPhase {
    number_of_to_be_issued_vouchers: u8,
    number_of_to_be_spent_vouchers: u8,
    range_proof_base_u: u8,
    range_proof_number_of_elements_l: u8,
    // c
    challenge: Scalar,
    // responses
    response_binding_number: Scalar,
    // to be issued
    responses_to_be_issued_values_decompositions: Vec<Vec<Scalar>>,
    responses_to_be_issued_serial_numbers: Vec<Scalar>,
    responses_to_be_issued_commitments_openings: Vec<Scalar>,
    responses_to_be_issued_binding_numbers_openings: Vec<Scalar>,
    responses_to_be_issued_values_openings: Vec<Scalar>,
    responses_to_be_issued_serial_numbers_openings: Vec<Scalar>,
    // to be spent
    responses_to_be_spent_values: Vec<Scalar>,
    responses_to_be_spent_serial_numbers: Vec<Scalar>,
    responses_to_be_spent_blinders: Vec<Scalar>,
    // range proof
    responses_range_proof_blinders: Vec<Vec<Scalar>>,
}

impl ProofRequestPhase {
    pub(crate) fn construct(
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
        to_be_issued_values_decompositions: &[Vec<Scalar>],
        to_be_issued_serial_numbers: &[Scalar],
        to_be_issued_commitments_openings: &[Scalar],
        to_be_issued_binding_numbers_openings: &[Scalar],
        to_be_issued_values_openings: &[Scalar],
        to_be_issued_serial_numbers_openings: &[Scalar],
        // to be spent
        to_be_spent_values: &[Scalar],
        to_be_spent_serial_numbers: &[Scalar],
        to_be_spent_blinders: &[Scalar],
        // range proof
        range_proof_blinders: &[Vec<Scalar>],
        // for challenge
        to_be_issued_commitments: &[G1Projective],
        to_be_issued_binding_number_commitments: &[G1Projective],
        to_be_issued_values_commitments: &[G1Projective],
        to_be_issued_serial_numbers_commitments: &[G1Projective],
        to_be_spent_attributes_commitments: &[G2Projective],
        to_be_spent_serial_numbers_commitments: &[G2Projective],
        blinded_pay: &G2Projective,
        range_proof_decompositions_commitments: &[Vec<G2Projective>],
    ) -> Self {
        let to_be_issued_hm_s: Vec<G1Projective> = to_be_issued_commitments
            .iter()
            .map(|commitment| hash_g1(commitment.to_bytes()))
            .collect();

        // create the witnesses
        let witness_binding_number = params.random_scalar();
        let witnesses_to_be_issued_values_decompositions: Vec<Vec<Scalar>> = (0
            ..number_of_to_be_issued_vouchers)
            .map(|_| params.n_random_scalars(range_proof_number_of_elements_l as usize))
            .collect();
        let witnesses_to_be_issued_serial_numbers =
            params.n_random_scalars(to_be_issued_serial_numbers.len());
        let witnesses_to_be_issued_commitments_openings =
            params.n_random_scalars(to_be_issued_commitments_openings.len());
        let witnesses_to_be_issued_binding_numbers_openings =
            params.n_random_scalars(to_be_issued_binding_numbers_openings.len());
        let witnesses_to_be_issued_values_openings =
            params.n_random_scalars(to_be_issued_values_openings.len());
        let witnesses_to_be_issued_serial_numbers_openings =
            params.n_random_scalars(to_be_issued_serial_numbers_openings.len());
        let witnesses_to_be_spent_values = params.n_random_scalars(to_be_spent_values.len());
        let witnesses_to_be_spent_serial_numbers =
            params.n_random_scalars(to_be_spent_serial_numbers.len());
        let witnesses_to_be_spent_blinders = params.n_random_scalars(to_be_spent_blinders.len());
        let witnesses_range_proof_blinders: Vec<Vec<Scalar>> = (0..number_of_to_be_issued_vouchers)
            .map(|_| params.n_random_scalars(range_proof_number_of_elements_l as usize))
            .collect();

        // witnesses commitments
        let to_be_issued_witnesses_commitments: Vec<G1Projective> = izip!(
            witnesses_to_be_issued_commitments_openings.iter(),
            witnesses_to_be_issued_values_decompositions.iter(),
            witnesses_to_be_issued_serial_numbers.iter()
        )
        .map(
            |(witness_opening, witnesses_values_decomposition, witness_serial_number)| {
                params.gen1() * witness_opening
                    + params.hs1()[0] * witness_binding_number
                    + witnesses_values_decomposition
                        .iter()
                        .enumerate()
                        .map(|(index, witness_value_decomposition)| {
                            params.hs1()[1]
                                * (witness_value_decomposition
                                    * Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                        })
                        .sum::<G1Projective>()
                    + params.hs1()[2] * witness_serial_number
            },
        )
        .collect();

        let to_be_issued_witnesses_binding_numbers_commitments: Vec<G1Projective> = izip!(
            witnesses_to_be_issued_serial_numbers_openings.iter(),
            to_be_issued_hm_s.iter()
        )
        .map(|(witness_opening, hm)| params.gen1() * witness_opening + hm * witness_binding_number)
        .collect();

        let to_be_issued_witnesses_values_commitments: Vec<G1Projective> = izip!(
            witnesses_to_be_issued_values_openings.iter(),
            to_be_issued_hm_s.iter(),
            witnesses_to_be_issued_values_decompositions.iter(),
        )
        .map(|(witness_opening, hm, witnesses_values_decomposition)| {
            params.gen1() * witness_opening
                + witnesses_values_decomposition
                    .iter()
                    .enumerate()
                    .map(|(index, witness_value_decomposition)| {
                        hm * witness_value_decomposition
                            + hm * (Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                    })
                    .sum::<G1Projective>()
        })
        .collect();

        let to_be_issued_witnesses_serial_numbers_commitments: Vec<G1Projective> = izip!(
            witnesses_to_be_issued_serial_numbers_openings.iter(),
            to_be_issued_hm_s.iter(),
            witnesses_to_be_issued_serial_numbers.iter(),
        )
        .map(|(witness_opening, hm, witness_serial_number)| {
            params.gen1() * witness_opening + hm * witness_serial_number
        })
        .collect();

        let to_be_spent_witnesses_attributes_commitments: Vec<G2Projective> = izip!(
            witnesses_to_be_spent_values.iter(),
            witnesses_to_be_spent_serial_numbers.iter(),
            witnesses_to_be_spent_blinders.iter()
        )
        .map(|(witness_value, witness_serial_number, witness_blinder)| {
            verification_key.alpha()
                + verification_key.beta_g2()[0] * witness_binding_number
                + verification_key.beta_g2()[1] * witness_value
                + verification_key.beta_g2()[2] * witness_serial_number
                + params.gen2() * witness_blinder
        })
        .collect();

        let to_be_spent_witnesses_serial_numbers_commitments: Vec<G2Projective> =
            witnesses_to_be_spent_serial_numbers
                .iter()
                .map(|witness_serial_number| params.gen2() * witness_serial_number)
                .collect();

        let witnesses_blinded_pay: G2Projective = witnesses_to_be_issued_values_decompositions
            .iter()
            .map(|witnesses_values_decomposition| {
                witnesses_values_decomposition
                    .iter()
                    .enumerate()
                    .map(|(index, witness_value_decomposition)| {
                        params.hs2()[1]
                            * (witness_value_decomposition
                                * Scalar::from((range_proof_base_u as u64).pow(index as u32)))
                    })
                    .sum::<G2Projective>()
            })
            .sum::<G2Projective>()
            - witnesses_to_be_spent_values
                .iter()
                .map(|value| params.hs2()[1] * value)
                .sum::<G2Projective>();

        let range_proof_witnesses_decomposition_commitments: Vec<Vec<G2Projective>> = izip!(
            witnesses_to_be_issued_values_decompositions.iter(),
            witnesses_range_proof_blinders.iter()
        )
        .map(|(witnesses_values_decomposition, witnesses_blinders)| {
            izip!(
                witnesses_values_decomposition.iter(),
                witnesses_blinders.iter()
            )
            .map(|(witness_value_decomposition, witness_blinder)| {
                range_proof_verification_key.alpha()
                    + range_proof_verification_key.beta_g2()[0] * witness_value_decomposition
                    + params.gen2() * witness_blinder
            })
            .collect()
        })
        .collect();

        // challenge
        let gen1_bytes = vec![params.gen1().to_bytes()];
        let gen2_bytes = vec![params.gen2().to_bytes()];
        let hs1_bytes = params
            .hs1()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let hs2_bytes = params
            .hs2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let mut verification_key_bytes = verification_key
            .beta_g2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        verification_key_bytes.push(verification_key.alpha().to_bytes());
        let mut range_proof_verification_key_bytes = range_proof_verification_key
            .beta_g2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        range_proof_verification_key_bytes.push(range_proof_verification_key.alpha().to_bytes());
        let numbers_of_vouchers_bytes = vec![
            number_of_to_be_issued_vouchers.to_be_bytes(),
            number_of_to_be_spent_vouchers.to_be_bytes(),
        ];
        let range_proof_parameters_bytes = vec![
            range_proof_base_u.to_be_bytes(),
            range_proof_number_of_elements_l.to_be_bytes(),
        ];

        let to_be_issued_witnesses_commitments_bytes = to_be_issued_witnesses_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_witnesses_binding_numbers_commitments_bytes =
            to_be_issued_witnesses_binding_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_issued_witnesses_values_commitments_bytes =
            to_be_issued_witnesses_values_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_issued_witnesses_serial_numbers_commitments_bytes =
            to_be_issued_witnesses_serial_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_spent_witnesses_attributes_commitments_bytes =
            to_be_spent_witnesses_attributes_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_spent_witnesses_serial_numbers_commitments_bytes =
            to_be_spent_witnesses_serial_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let witnesses_blinded_pay_bytes = vec![witnesses_blinded_pay.to_bytes()];
        let range_proof_witnesses_decomposition_commitments_bytes =
            range_proof_witnesses_decomposition_commitments
                .iter()
                .flatten()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();

        let to_be_issued_commitments_bytes = to_be_issued_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_hm_s_bytes = to_be_issued_hm_s
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_binding_number_commitments_bytes = to_be_issued_binding_number_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_values_commitments_bytes = to_be_issued_values_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_serial_numbers_commitments_bytes = to_be_issued_serial_numbers_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_spent_attributes_commitments_bytes = to_be_spent_attributes_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_spent_serial_numbers_commitments_bytes = to_be_spent_serial_numbers_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let blinded_pay_bytes = vec![blinded_pay.to_bytes()];
        let range_proof_decompositions_commitments_bytes = range_proof_decompositions_commitments
            .iter()
            .flatten()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            gen1_bytes
                .iter()
                .map(|v| v.as_ref())
                .chain(gen2_bytes.iter().map(|v| v.as_ref()))
                .chain(hs1_bytes.iter().map(|v| v.as_ref()))
                .chain(hs2_bytes.iter().map(|v| v.as_ref()))
                .chain(verification_key_bytes.iter().map(|v| v.as_ref()))
                .chain(
                    range_proof_verification_key_bytes
                        .iter()
                        .map(|v| v.as_ref()),
                )
                .chain(numbers_of_vouchers_bytes.iter().map(|v| v.as_ref()))
                .chain(range_proof_parameters_bytes.iter().map(|v| v.as_ref()))
                .chain(
                    to_be_issued_witnesses_commitments_bytes
                        .iter()
                        .map(|v| v.as_ref()),
                )
                // .chain(
                //     to_be_issued_witnesses_binding_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_witnesses_values_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_witnesses_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_witnesses_attributes_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_witnesses_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(witnesses_blinded_pay_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     range_proof_witnesses_decomposition_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(to_be_issued_commitments_bytes.iter().map(|v| v.as_ref()))
                // .chain(to_be_issued_hm_s_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     to_be_issued_binding_number_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_values_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_attributes_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(blinded_pay_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     range_proof_decompositions_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // ),
        );

        // responses
        let response_binding_number =
            produce_response(&witness_binding_number, &challenge, &binding_number);
        let responses_to_be_issued_values_decompositions = izip!(
            witnesses_to_be_issued_values_decompositions.iter(),
            to_be_issued_values_decompositions.iter()
        )
        .map(
            |(witnesses_to_be_issued_values_decomposition, to_be_issued_values_decomposition)| {
                produce_responses(
                    &witnesses_to_be_issued_values_decomposition,
                    &challenge,
                    &to_be_issued_values_decomposition,
                )
            },
        )
        .collect();
        let responses_to_be_issued_serial_numbers = produce_responses(
            &witnesses_to_be_issued_serial_numbers,
            &challenge,
            &to_be_issued_serial_numbers,
        );
        let responses_to_be_issued_commitments_openings = produce_responses(
            &witnesses_to_be_issued_commitments_openings,
            &challenge,
            &to_be_issued_commitments_openings,
        );
        let responses_to_be_issued_binding_numbers_openings = produce_responses(
            &witnesses_to_be_issued_binding_numbers_openings,
            &challenge,
            &to_be_issued_binding_numbers_openings,
        );
        let responses_to_be_issued_values_openings = produce_responses(
            &witnesses_to_be_issued_values_openings,
            &challenge,
            &to_be_issued_values_openings,
        );
        let responses_to_be_issued_serial_numbers_openings = produce_responses(
            &witnesses_to_be_issued_serial_numbers_openings,
            &challenge,
            &to_be_issued_serial_numbers_openings,
        );
        let responses_to_be_spent_values = produce_responses(
            &witnesses_to_be_spent_values,
            &challenge,
            &to_be_spent_values,
        );
        let responses_to_be_spent_serial_numbers = produce_responses(
            &witnesses_to_be_spent_serial_numbers,
            &challenge,
            &to_be_spent_serial_numbers,
        );
        let responses_to_be_spent_blinders = produce_responses(
            &witnesses_to_be_spent_blinders,
            &challenge,
            &to_be_spent_blinders,
        );
        let responses_range_proof_blinders = izip!(
            witnesses_range_proof_blinders.iter(),
            range_proof_blinders.iter()
        )
        .map(|(witnesses_range_proof_blinder, range_proof_blinder)| {
            produce_responses(
                &witnesses_range_proof_blinder,
                &challenge,
                &range_proof_blinder,
            )
        })
        .collect();

        ProofRequestPhase {
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            range_proof_base_u,
            range_proof_number_of_elements_l,
            challenge,
            response_binding_number,
            responses_to_be_issued_values_decompositions,
            responses_to_be_issued_serial_numbers,
            responses_to_be_issued_commitments_openings,
            responses_to_be_issued_binding_numbers_openings,
            responses_to_be_issued_values_openings,
            responses_to_be_issued_serial_numbers_openings,
            responses_to_be_spent_values,
            responses_to_be_spent_serial_numbers,
            responses_to_be_spent_blinders,
            responses_range_proof_blinders,
        }
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        range_proof_verification_key: &VerificationKey,
        to_be_issued_commitments: &[G1Projective],
        to_be_issued_binding_number_commitments: &[G1Projective],
        to_be_issued_values_commitments: &[G1Projective],
        to_be_issued_serial_numbers_commitments: &[G1Projective],
        to_be_spent_attributes_commitments: &[G2Projective],
        to_be_spent_serial_numbers_commitments: &[G2Projective],
        blinded_pay: &G2Projective,
        range_proof_decompositions_commitments: &[Vec<G2Projective>],
    ) -> bool {
        let to_be_issued_hm_s: Vec<G1Projective> = to_be_issued_commitments
            .iter()
            .map(|commitment| hash_g1(commitment.to_bytes()))
            .collect();

        let to_be_issued_witnesses_commitments: Vec<G1Projective> = izip!(
            to_be_issued_commitments.iter(),
            self.responses_to_be_issued_commitments_openings.iter(),
            self.responses_to_be_issued_values_decompositions.iter(),
            self.responses_to_be_issued_serial_numbers.iter()
        )
        .map(
            |(
                to_be_issued_commitment,
                response_opening,
                responses_values_decomposition,
                response_serial_number,
            )| {
                to_be_issued_commitment * self.challenge
                    + params.gen1() * response_opening
                    + params.hs1()[0] * self.response_binding_number
                    + responses_values_decomposition
                        .iter()
                        .enumerate()
                        .map(|(index, response_value_decomposition)| {
                            params.hs1()[1]
                                * (response_value_decomposition
                                    * Scalar::from(
                                        (self.range_proof_base_u as u64).pow(index as u32),
                                    ))
                        })
                        .sum::<G1Projective>()
                    + params.hs1()[2] * response_serial_number
            },
        )
        .collect();

        let to_be_issued_witnesses_binding_numbers_commitments: Vec<G1Projective> = izip!(
            to_be_issued_binding_number_commitments.iter(),
            self.responses_to_be_issued_binding_numbers_openings.iter(),
            to_be_issued_hm_s.iter()
        )
        .map(
            |(to_be_issued_binding_number_commitment, response_opening, hm)| {
                to_be_issued_binding_number_commitment * self.challenge
                    + params.gen1() * response_opening
                    + hm * self.response_binding_number
            },
        )
        .collect();

        let to_be_issued_witnesses_values_commitments: Vec<G1Projective> = izip!(
            to_be_issued_values_commitments.iter(),
            self.responses_to_be_issued_values_openings.iter(),
            to_be_issued_hm_s.iter(),
            self.responses_to_be_issued_values_decompositions.iter()
        )
        .map(
            |(
                to_be_issued_values_commitment,
                response_opening,
                hm,
                responses_values_decomposition,
            )| {
                to_be_issued_values_commitment * self.challenge
                    + params.gen1() * response_opening
                    + responses_values_decomposition
                        .iter()
                        .enumerate()
                        .map(|(index, response_value_decomposition)| {
                            hm * response_value_decomposition
                                + hm * (Scalar::from(
                                    (self.range_proof_base_u as u64).pow(index as u32),
                                ))
                        })
                        .sum::<G1Projective>()
            },
        )
        .collect();

        let to_be_issued_witnesses_serial_numbers_commitments: Vec<G1Projective> = izip!(
            to_be_issued_serial_numbers_commitments.iter(),
            self.responses_to_be_issued_serial_numbers_openings.iter(),
            to_be_issued_hm_s.iter(),
            self.responses_to_be_issued_serial_numbers.iter()
        )
        .map(
            |(
                to_be_issued_serial_numbers_commitment,
                response_opening,
                hm,
                response_serial_number,
            )| {
                to_be_issued_serial_numbers_commitment * self.challenge
                    + params.gen1() * response_opening
                    + hm * response_serial_number
            },
        )
        .collect();

        let to_be_spent_witnesses_attributes_commitments: Vec<G2Projective> = izip!(
            to_be_spent_attributes_commitments.iter(),
            self.responses_to_be_spent_values.iter(),
            self.responses_to_be_spent_serial_numbers.iter(),
            self.responses_to_be_spent_blinders.iter()
        )
        .map(
            |(
                to_be_spent_attributes_commitment,
                response_value,
                response_serial_number,
                response_blinder,
            )| {
                to_be_spent_attributes_commitment * self.challenge
                    + verification_key.alpha() * (Scalar::one() - self.challenge)
                    + verification_key.beta_g2()[0] * self.response_binding_number
                    + verification_key.beta_g2()[1] * response_value
                    + verification_key.beta_g2()[2] * response_serial_number
                    + params.gen2() * response_blinder
            },
        )
        .collect();

        let to_be_spent_witnesses_serial_numbers_commitments: Vec<G2Projective> = izip!(
            to_be_spent_serial_numbers_commitments.iter(),
            self.responses_to_be_spent_serial_numbers.iter()
        )
        .map(
            |(to_be_spent_serial_numbers_commitment, response_serial_number)| {
                to_be_spent_serial_numbers_commitment * self.challenge
                    + params.gen2() * response_serial_number
            },
        )
        .collect();

        let witnesses_blinded_pay: G2Projective = blinded_pay * self.challenge
            + self
                .responses_to_be_issued_values_decompositions
                .iter()
                .map(|responses_values_decomposition| {
                    responses_values_decomposition
                        .iter()
                        .enumerate()
                        .map(|(index, response_value_decomposition)| {
                            params.hs2()[1]
                                * (response_value_decomposition
                                    * Scalar::from(
                                        (self.range_proof_base_u as u64).pow(index as u32),
                                    ))
                        })
                        .sum::<G2Projective>()
                })
                .sum::<G2Projective>()
            - self
                .responses_to_be_spent_values
                .iter()
                .map(|value| params.hs2()[1] * value)
                .sum::<G2Projective>();

        let range_proof_witnesses_decomposition_commitments: Vec<Vec<G2Projective>> = izip!(
            range_proof_decompositions_commitments.iter(),
            self.responses_to_be_issued_values_decompositions.iter(),
            self.responses_range_proof_blinders.iter()
        )
        .map(
            |(
                range_proof_decomposition_commitments,
                responses_values_decomposition,
                responses_blinders,
            )| {
                izip!(
                    range_proof_decomposition_commitments.iter(),
                    responses_values_decomposition.iter(),
                    responses_blinders.iter()
                )
                .map(
                    |(
                        range_proof_decomposition_commitment,
                        response_value_decomposition,
                        response_blinder,
                    )| {
                        range_proof_decomposition_commitment * self.challenge
                            + range_proof_verification_key.alpha()
                                * (Scalar::one() - self.challenge)
                            + range_proof_verification_key.beta_g2()[0]
                                * response_value_decomposition
                            + params.gen2() * response_blinder
                    },
                )
                .collect()
            },
        )
        .collect();

        // recompute challenge
        let gen1_bytes = vec![params.gen1().to_bytes()];
        let gen2_bytes = vec![params.gen2().to_bytes()];
        let hs1_bytes = params
            .hs1()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let hs2_bytes = params
            .hs2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let mut verification_key_bytes = verification_key
            .beta_g2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        verification_key_bytes.push(verification_key.alpha().to_bytes());
        let mut range_proof_verification_key_bytes = range_proof_verification_key
            .beta_g2()
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        range_proof_verification_key_bytes.push(range_proof_verification_key.alpha().to_bytes());
        let numbers_of_vouchers_bytes = vec![
            self.number_of_to_be_issued_vouchers.to_be_bytes(),
            self.number_of_to_be_spent_vouchers.to_be_bytes(),
        ];
        let range_proof_parameters_bytes = vec![
            self.range_proof_base_u.to_be_bytes(),
            self.range_proof_number_of_elements_l.to_be_bytes(),
        ];

        let to_be_issued_witnesses_commitments_bytes = to_be_issued_witnesses_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_witnesses_binding_numbers_commitments_bytes =
            to_be_issued_witnesses_binding_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_issued_witnesses_values_commitments_bytes =
            to_be_issued_witnesses_values_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_issued_witnesses_serial_numbers_commitments_bytes =
            to_be_issued_witnesses_serial_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_spent_witnesses_attributes_commitments_bytes =
            to_be_spent_witnesses_attributes_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let to_be_spent_witnesses_serial_numbers_commitments_bytes =
            to_be_spent_witnesses_serial_numbers_commitments
                .iter()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();
        let witnesses_blinded_pay_bytes = vec![witnesses_blinded_pay.to_bytes()];
        let range_proof_witnesses_decomposition_commitments_bytes =
            range_proof_witnesses_decomposition_commitments
                .iter()
                .flatten()
                .map(|v| v.to_bytes())
                .collect::<Vec<_>>();

        let to_be_issued_commitments_bytes = to_be_issued_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_hm_s_bytes = to_be_issued_hm_s
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_binding_number_commitments_bytes = to_be_issued_binding_number_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_values_commitments_bytes = to_be_issued_values_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_issued_serial_numbers_commitments_bytes = to_be_issued_serial_numbers_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_spent_attributes_commitments_bytes = to_be_spent_attributes_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let to_be_spent_serial_numbers_commitments_bytes = to_be_spent_serial_numbers_commitments
            .iter()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();
        let blinded_pay_bytes = vec![blinded_pay.to_bytes()];
        let range_proof_decompositions_commitments_bytes = range_proof_decompositions_commitments
            .iter()
            .flatten()
            .map(|v| v.to_bytes())
            .collect::<Vec<_>>();

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            gen1_bytes
                .iter()
                .map(|v| v.as_ref())
                .chain(gen2_bytes.iter().map(|v| v.as_ref()))
                .chain(hs1_bytes.iter().map(|v| v.as_ref()))
                .chain(hs2_bytes.iter().map(|v| v.as_ref()))
                .chain(verification_key_bytes.iter().map(|v| v.as_ref()))
                .chain(
                    range_proof_verification_key_bytes
                        .iter()
                        .map(|v| v.as_ref()),
                )
                .chain(numbers_of_vouchers_bytes.iter().map(|v| v.as_ref()))
                .chain(range_proof_parameters_bytes.iter().map(|v| v.as_ref()))
                .chain(
                    to_be_issued_witnesses_commitments_bytes
                        .iter()
                        .map(|v| v.as_ref()),
                )
                // .chain(
                //     to_be_issued_witnesses_binding_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_witnesses_values_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_witnesses_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_witnesses_attributes_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_witnesses_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(witnesses_blinded_pay_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     range_proof_witnesses_decomposition_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(to_be_issued_commitments_bytes.iter().map(|v| v.as_ref()))
                // .chain(to_be_issued_hm_s_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     to_be_issued_binding_number_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_values_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_issued_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_attributes_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(
                //     to_be_spent_serial_numbers_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // )
                // .chain(blinded_pay_bytes.iter().map(|v| v.as_ref()))
                // .chain(
                //     range_proof_decompositions_commitments_bytes
                //         .iter()
                //         .map(|v| v.as_ref()),
                // ),
        );

        challenge == self.challenge
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let number_of_to_be_issued_vouchers_bytes =
            self.number_of_to_be_issued_vouchers.to_be_bytes();
        let number_of_to_be_spent_vouchers_bytes =
            self.number_of_to_be_spent_vouchers.to_be_bytes();
        let range_proof_base_u_bytes = self.range_proof_base_u.to_be_bytes();
        let range_proof_number_of_elements_l_bytes =
            self.range_proof_number_of_elements_l.to_be_bytes();

        let challenge_bytes = self.challenge.to_bytes();

        let response_binding_number_bytes = self.response_binding_number.to_bytes();

        let responses_to_be_issued_values_decompositions_bytes = self
            .responses_to_be_issued_values_decompositions
            .iter()
            .flatten()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_issued_serial_numbers_bytes = self
            .responses_to_be_issued_serial_numbers
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_issued_commitments_openings_bytes = self
            .responses_to_be_issued_commitments_openings
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_issued_binding_numbers_openings_bytes = self
            .responses_to_be_issued_binding_numbers_openings
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_issued_values_openings_bytes = self
            .responses_to_be_issued_values_openings
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_issued_serial_numbers_openings_bytes = self
            .responses_to_be_issued_serial_numbers_openings
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        let responses_to_be_spent_values_bytes = self
            .responses_to_be_spent_values
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_spent_serial_numbers_bytes = self
            .responses_to_be_spent_serial_numbers
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let responses_to_be_spent_blinders_bytes = self
            .responses_to_be_spent_blinders
            .iter()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        let responses_range_proof_blinders_bytes = self
            .responses_range_proof_blinders
            .iter()
            .flatten()
            .map(|v| v.to_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        let mut bytes = Vec::with_capacity(
            number_of_to_be_issued_vouchers_bytes.len()
                + number_of_to_be_spent_vouchers_bytes.len()
                + range_proof_base_u_bytes.len()
                + range_proof_number_of_elements_l_bytes.len()
                + challenge_bytes.len()
                + response_binding_number_bytes.len()
                + responses_to_be_issued_values_decompositions_bytes.len()
                + responses_to_be_issued_serial_numbers_bytes.len()
                + responses_to_be_issued_commitments_openings_bytes.len()
                + responses_to_be_issued_binding_numbers_openings_bytes.len()
                + responses_to_be_issued_values_openings_bytes.len()
                + responses_to_be_issued_serial_numbers_openings_bytes.len()
                + responses_to_be_spent_values_bytes.len()
                + responses_to_be_spent_serial_numbers_bytes.len()
                + responses_to_be_spent_blinders_bytes.len()
                + responses_range_proof_blinders_bytes.len(),
        );

        bytes.extend(number_of_to_be_issued_vouchers_bytes);
        bytes.extend(number_of_to_be_spent_vouchers_bytes);
        bytes.extend(range_proof_base_u_bytes);
        bytes.extend(range_proof_number_of_elements_l_bytes);
        bytes.extend(challenge_bytes);
        bytes.extend(response_binding_number_bytes);
        bytes.extend(responses_to_be_issued_values_decompositions_bytes);
        bytes.extend(responses_to_be_issued_serial_numbers_bytes);
        bytes.extend(responses_to_be_issued_commitments_openings_bytes);
        bytes.extend(responses_to_be_issued_binding_numbers_openings_bytes);
        bytes.extend(responses_to_be_issued_values_openings_bytes);
        bytes.extend(responses_to_be_issued_serial_numbers_openings_bytes);
        bytes.extend(responses_to_be_spent_values_bytes);
        bytes.extend(responses_to_be_spent_serial_numbers_bytes);
        bytes.extend(responses_to_be_spent_blinders_bytes);
        bytes.extend(responses_range_proof_blinders_bytes);

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

        p = p_prime;
        p_prime += 32;
        let challenge_bytes = &bytes[p..p_prime].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            challenge_bytes,
            CoconutError::Deserialization("failed to deserialize the challenge".to_string()),
        )?;

        p = p_prime;
        p_prime += 32;
        let response_binding_number_bytes = &bytes[p..p_prime].try_into().unwrap();
        let response_binding_number = try_deserialize_scalar(
            response_binding_number_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the response binding number".to_string(),
            ),
        )?;

        let mut responses_to_be_issued_values_decompositions =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for _ in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 32 * range_proof_number_of_elements_l as usize;

            let responses_to_be_issued_values_decompositions_temp_bytes = &bytes[p..p_prime];
            let responses_to_be_issued_values_decompositions_temp = try_deserialize_scalar_vec(
                range_proof_number_of_elements_l as u64,
                &responses_to_be_issued_values_decompositions_temp_bytes,
                CoconutError::Deserialization(
                    "failed to deserialize the responses to be issued values decompositions"
                        .to_string(),
                ),
            )?;

            responses_to_be_issued_values_decompositions
                .push(responses_to_be_issued_values_decompositions_temp);
        }

        p = p_prime;
        p_prime += 32 * number_of_to_be_issued_vouchers as usize;
        let responses_to_be_issued_serial_numbers_bytes = &bytes[p..p_prime];
        let responses_to_be_issued_serial_numbers = try_deserialize_scalar_vec(
            number_of_to_be_issued_vouchers as u64,
            &responses_to_be_issued_serial_numbers_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be issued serial numbers".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_issued_vouchers as usize;
        let responses_to_be_issued_commitments_openings_bytes = &bytes[p..p_prime];
        let responses_to_be_issued_commitments_openings = try_deserialize_scalar_vec(
            number_of_to_be_issued_vouchers as u64,
            &responses_to_be_issued_commitments_openings_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be issued commitments openings".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_issued_vouchers as usize;
        let responses_to_be_issued_binding_numbers_openings_bytes = &bytes[p..p_prime];
        let responses_to_be_issued_binding_numbers_openings = try_deserialize_scalar_vec(
            number_of_to_be_issued_vouchers as u64,
            &responses_to_be_issued_binding_numbers_openings_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be issued binding numbers openings"
                    .to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_issued_vouchers as usize;
        let responses_to_be_issued_values_openings_bytes = &bytes[p..p_prime];
        let responses_to_be_issued_values_openings = try_deserialize_scalar_vec(
            number_of_to_be_issued_vouchers as u64,
            &responses_to_be_issued_values_openings_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be issued values openings".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_issued_vouchers as usize;
        let responses_to_be_issued_serial_numbers_openings_bytes = &bytes[p..p_prime];
        let responses_to_be_issued_serial_numbers_openings = try_deserialize_scalar_vec(
            number_of_to_be_issued_vouchers as u64,
            &responses_to_be_issued_serial_numbers_openings_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be issued serial numbers openings"
                    .to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_spent_vouchers as usize;
        let responses_to_be_spent_values_bytes = &bytes[p..p_prime];
        let responses_to_be_spent_values = try_deserialize_scalar_vec(
            number_of_to_be_spent_vouchers as u64,
            &responses_to_be_spent_values_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be spent values".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_spent_vouchers as usize;
        let responses_to_be_spent_serial_numbers_bytes = &bytes[p..p_prime];
        let responses_to_be_spent_serial_numbers = try_deserialize_scalar_vec(
            number_of_to_be_spent_vouchers as u64,
            &responses_to_be_spent_serial_numbers_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be spent serial numbers".to_string(),
            ),
        )?;

        p = p_prime;
        p_prime += 32 * number_of_to_be_spent_vouchers as usize;
        let responses_to_be_spent_blinders_bytes = &bytes[p..p_prime];
        let responses_to_be_spent_blinders = try_deserialize_scalar_vec(
            number_of_to_be_spent_vouchers as u64,
            &responses_to_be_spent_blinders_bytes,
            CoconutError::Deserialization(
                "failed to deserialize the responses to be spent blinders".to_string(),
            ),
        )?;

        let mut responses_range_proof_blinders =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for _ in 0..number_of_to_be_issued_vouchers {
            p = p_prime;
            p_prime += 32 * range_proof_number_of_elements_l as usize;

            let responses_to_be_issued_blinders_temp_bytes = &bytes[p..p_prime];
            let responses_to_be_issued_blinders_temp = try_deserialize_scalar_vec(
                range_proof_number_of_elements_l as u64,
                &responses_to_be_issued_blinders_temp_bytes,
                CoconutError::Deserialization(
                    "failed to deserialize the responses to be issued range proof blinders"
                        .to_string(),
                ),
            )?;

            responses_range_proof_blinders.push(responses_to_be_issued_blinders_temp);
        }

        Ok(ProofRequestPhase {
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            range_proof_base_u,
            range_proof_number_of_elements_l,
            challenge,
            response_binding_number,
            responses_to_be_issued_values_decompositions,
            responses_to_be_issued_serial_numbers,
            responses_to_be_issued_commitments_openings,
            responses_to_be_issued_binding_numbers_openings,
            responses_to_be_issued_values_openings,
            responses_to_be_issued_serial_numbers_openings,
            responses_to_be_spent_values,
            responses_to_be_spent_serial_numbers,
            responses_to_be_spent_blinders,
            responses_range_proof_blinders,
        })
    }
}

// proof builder:
// - commitment
// - challenge
// - responses

#[cfg(test)]
mod tests {
    use group::Group;
    use rand::thread_rng;

    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;
    use crate::scheme::verification::{compute_kappa, compute_zeta};

    use super::*;

    #[test]
    fn proof_cm_cs_bytes_roundtrip() {
        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes

        let mut rng = thread_rng();

        let mut params = setup(1).unwrap();
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();
        let cms: [G1Projective; 1] = [G1Projective::random(&mut rng)];
        let rs = params.n_random_scalars(1);
        let private_attributes = params.n_random_scalars(1);

        // 0 public 1 private
        let pi_s = ProofCmCs::construct(&mut params, &cm, &r, &cms, &rs, &private_attributes);

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);

        let mut params = setup(2).unwrap();
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();
        let cms: [G1Projective; 2] = [
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
        ];
        let rs = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);

        // 0 public 2 privates
        let pi_s = ProofCmCs::construct(&mut params, &cm, &r, &cms, &rs, &private_attributes);

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);
    }

    #[test]
    fn proof_kappa_zeta_bytes_roundtrip() {
        let mut params = setup(4).unwrap();

        let keypair = keygen(&mut params);

        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
        let serial_number = params.random_scalar();
        let binding_number = params.random_scalar();
        let private_attributes = vec![serial_number, binding_number];

        let r = params.random_scalar();
        let kappa = compute_kappa(&params, &keypair.verification_key(), &private_attributes, r);
        let zeta = compute_zeta(&params, serial_number);

        // 0 public 2 private
        let pi_v = ProofKappaZeta::construct(
            &mut params,
            &keypair.verification_key(),
            &serial_number,
            &binding_number,
            &r,
            &kappa,
            &zeta,
        );

        let proof_bytes = pi_v.to_bytes();

        let proof_from_bytes = ProofKappaZeta::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof_from_bytes, pi_v);

        // 2 public 2 private
        let mut params = setup(4).unwrap();
        let keypair = keygen(&mut params);

        let pi_v = ProofKappaZeta::construct(
            &mut params,
            &keypair.verification_key(),
            &serial_number,
            &binding_number,
            &r,
            &kappa,
            &zeta,
        );

        let proof_bytes = pi_v.to_bytes();

        let proof_from_bytes = ProofKappaZeta::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof_from_bytes, pi_v);
    }

    #[test]
    fn proof_spend_bytes_roundtrip() {
        let params = setup(4).unwrap();

        let keypair = keygen(&params);
        let verification_key = keypair.verification_key();

        // 1 voucher
        let number_of_vouchers_spent = 1;
        let binding_number = params.random_scalar();
        let values = [Scalar::from(10)];
        let serial_numbers = params.n_random_scalars(1);
        let signatures_blinding_factors = params.n_random_scalars(1);
        let blinded_messages_kappa = [params.gen2() * params.random_scalar()];
        let blinded_serial_numbers_zeta = [params.gen2() * params.random_scalar()];
        let blinded_sum_c = params.gen2() * params.random_scalar();

        let pi_v = ProofSpend::construct(
            &params,
            &verification_key,
            number_of_vouchers_spent,
            &binding_number,
            &values,
            &serial_numbers,
            &signatures_blinding_factors,
            &blinded_messages_kappa,
            &blinded_serial_numbers_zeta,
            &blinded_sum_c,
        );

        let proof_bytes = pi_v.to_bytes();
        let proof_from_bytes = ProofSpend::from_bytes(&proof_bytes).unwrap();

        assert_eq!(proof_from_bytes, pi_v);

        // 3 vouchers
        let number_of_vouchers_spent = 3;
        let binding_number = params.random_scalar();
        let values = [Scalar::from(10), Scalar::from(10), Scalar::from(10)];
        let serial_numbers = params.n_random_scalars(3);
        let signatures_blinding_factors = params.n_random_scalars(3);
        let blinded_messages_kappa = [
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
        ];
        let blinded_serial_numbers_zeta = [
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
        ];
        let blinded_sum_c = params.gen2() * params.random_scalar();

        let pi_v = ProofSpend::construct(
            &params,
            &verification_key,
            number_of_vouchers_spent,
            &binding_number,
            &values,
            &serial_numbers,
            &signatures_blinding_factors,
            &blinded_messages_kappa,
            &blinded_serial_numbers_zeta,
            &blinded_sum_c,
        );

        let proof_bytes = pi_v.to_bytes();
        let proof_from_bytes = ProofSpend::from_bytes(&proof_bytes).unwrap();

        assert_eq!(proof_from_bytes, pi_v);
    }

    #[test]
    fn proof_request_phase_bytes_roundtrip() {
        let params = setup(4).unwrap();

        let keypair = keygen(&params);
        let verification_key = keypair.verification_key();
        let range_proof_keypair = keygen(&params);
        let range_proof_verification_key = range_proof_keypair.verification_key();

        let number_of_to_be_issued_vouchers: u8 = 3;
        let number_of_to_be_spent_vouchers: u8 = 5;
        let range_proof_base_u: u8 = 8;
        let range_proof_number_of_elements_l: u8 = 4;

        let binding_number = params.random_scalar();

        let mut to_be_issued_values_decompositions =
            Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for _ in 0..number_of_to_be_issued_vouchers {
            let temp = params.n_random_scalars(range_proof_number_of_elements_l as usize);
            to_be_issued_values_decompositions.push(temp);
        }
        let to_be_issued_serial_numbers =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
        let to_be_issued_commitments_openings =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
        let to_be_issued_binding_numbers_openings =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
        let to_be_issued_values_openings =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);
        let to_be_issued_serial_numbers_openings =
            params.n_random_scalars(number_of_to_be_issued_vouchers as usize);

        let to_be_spent_values = params.n_random_scalars(number_of_to_be_spent_vouchers as usize);
        let to_be_spent_serial_numbers =
            params.n_random_scalars(number_of_to_be_spent_vouchers as usize);
        let to_be_spent_blinders = params.n_random_scalars(number_of_to_be_spent_vouchers as usize);

        let mut range_proof_blinders = Vec::with_capacity(number_of_to_be_issued_vouchers as usize);
        for _ in 0..number_of_to_be_issued_vouchers {
            let temp = params.n_random_scalars(range_proof_number_of_elements_l as usize);
            range_proof_blinders.push(temp);
        }

        let to_be_issued_commitments = [
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        ];
        let to_be_issued_binding_number_commitments = [
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        ];

        let to_be_issued_values_commitments = [
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        ];

        let to_be_issued_serial_numbers_commitments = [
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        ];

        let to_be_spent_attributes_commitments = [
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
        ];

        let to_be_spent_serial_numbers_commitments = [
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
            params.gen2() * params.random_scalar(),
        ];

        let blinded_pay = params.gen2() * params.random_scalar();
        let range_proof_decompositions_commitments = [
            vec![
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
            ],
            vec![
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
            ],
            vec![
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
                params.gen2() * params.random_scalar(),
            ],
        ];

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

        let proof_bytes = proof.to_bytes();
        let proof_from_bytes = ProofRequestPhase::from_bytes(&proof_bytes).unwrap();

        assert_eq!(proof_from_bytes, proof);
    }
}
