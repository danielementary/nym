use bls12_381::Scalar;
use nymcoconut::{CoconutError, Parameters, Signature};

pub struct ECashParams {
    pub coconut_params: Parameters,
    pub pay_max: Scalar,
    pub voucher_max: Scalar,
}

impl ECashParams {
    pub fn new(
        num_attributes: u32,
        pay_max: Scalar,
        voucher_max: Scalar,
    ) -> Result<ECashParams, CoconutError> {
        Ok(ECashParams {
            coconut_params: Parameters::new(num_attributes)?,
            pay_max,
            voucher_max,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Voucher {
    pub binding_number: Scalar,
    pub value: Scalar,
    pub serial_number: Scalar,
    pub info: Scalar,
}

impl Voucher {
    pub fn new(coconut_params: &Parameters, binding_number: Scalar, value: Scalar) -> Voucher {
        Voucher {
            binding_number,
            value,
            serial_number: coconut_params.random_scalar(),
            info: Scalar::from(0),
        }
    }

    pub fn new_many(
        coconut_params: &Parameters,
        binding_number: Scalar,
        values: &[Scalar],
    ) -> Vec<Voucher> {
        values
            .iter()
            .map(|v| Voucher::new(coconut_params, binding_number, *v))
            .collect()
    }

    pub fn private_attributes(&self) -> Vec<Scalar> {
        vec![self.binding_number, self.value, self.serial_number]
    }

    pub fn public_attributes(&self) -> Vec<Scalar> {
        vec![self.info]
    }

    pub fn attributes(&self) -> Vec<Scalar> {
        vec![
            self.binding_number,
            self.value,
            self.serial_number,
            self.info,
        ]
    }
}

// struct that carries all the information concerning a given list of vouchers
pub struct VouchersList {
    pub vouchers: Vec<Voucher>,
    pub used: Vec<bool>,
    pub commitment_openings: Vec<Scalar>,
    pub commitments_openings: Vec<Vec<Scalar>>,
    pub signatures: Vec<Signature>,
}

// returns the list of indices from a VouchersList for vouchers to be spend for given values
impl VouchersList {
    pub fn find(&self, values: &Vec<Scalar>) -> Option<Vec<usize>> {
        let mut vouchers_indices = Vec::new();

        for val in values {
            for (i, v) in self.vouchers.iter().enumerate() {
                if v.value == *val && !self.used[i] && !vouchers_indices.contains(&i) {
                    vouchers_indices.push(i);
                    break;
                }
            }
        }

        if vouchers_indices.len() == values.len() {
            Some(vouchers_indices)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{G1Projective, Scalar};
    use itertools::izip;
    use nymcoconut::{
        aggregate_signature_shares, aggregate_verification_keys, blind_sign, prepare_blind_sign,
        ttp_keygen, BlindSignRequest, BlindedSignature, Signature, SignatureShare, VerificationKey,
    };

    #[test]
    fn main() -> Result<(), CoconutError> {
        // define e-cash parameters
        let num_attributes = 4;
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max)?;

        // generate authorities key pairs
        let coconut_keypairs = ttp_keygen(&params.coconut_params, 3, 5)?;
        let betas_g1: Vec<Vec<G1Projective>> = coconut_keypairs
            .iter()
            .map(|keypair| keypair.secret_key().betas_g1(&params.coconut_params))
            .collect();
        let verification_keys: Vec<VerificationKey> = coconut_keypairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();

        // create vouchers
        let binding_number = params.coconut_params.random_scalar();
        const NUMBER_OF_VOUCHERS: usize = 5;
        let values = [voucher_max; NUMBER_OF_VOUCHERS];

        let vouchers = Voucher::new_many(&params.coconut_params, binding_number, &values);

        // issue signatures for initial vouchers like coconut
        // generate commitments openings
        let vouchers_commitment_opening = vouchers
            .iter()
            .map(|_| params.coconut_params.random_scalar())
            .collect::<Vec<Scalar>>();
        let vouchers_commitments_openings = vouchers
            .iter()
            .map(|v| {
                params
                    .coconut_params
                    .n_random_scalars(v.private_attributes().len())
            })
            .collect::<Vec<Vec<Scalar>>>();

        // prepare blind signatures
        let blinded_signatures_shares_requests = izip!(
            vouchers.iter(),
            vouchers_commitment_opening.iter(),
            vouchers_commitments_openings.iter()
        )
        .map(|(v, o, os)| {
            prepare_blind_sign(
                &params.coconut_params,
                &v.private_attributes(),
                &o,
                &os,
                &v.public_attributes(),
            )
            .unwrap()
        })
        .collect::<Vec<BlindSignRequest>>();

        // acquire partial signatures
        let verification_key =
            aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3, 4, 5]))?;
        let blinded_signatures_shares = blinded_signatures_shares_requests
            .iter()
            .zip(vouchers.iter())
            .map(|(r, v)| {
                coconut_keypairs
                    .iter()
                    .map(|keypair| {
                        blind_sign(
                            &params.coconut_params,
                            &keypair.secret_key(),
                            &r,
                            &v.public_attributes(),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<BlindedSignature>>()
            })
            .collect::<Vec<Vec<BlindedSignature>>>();

        // unblind partial signatures
        let signatures_shares = izip!(
            blinded_signatures_shares.iter(),
            vouchers.iter(),
            vouchers_commitments_openings.iter(),
            blinded_signatures_shares_requests.iter()
        )
        .map(|(bss, v, vco, bsr)| {
            izip!(bss.iter(), betas_g1.iter(), verification_keys.iter())
                .map(|(s, b, vk)| {
                    s.unblind(
                        &params.coconut_params,
                        &b,
                        &vk,
                        &v.private_attributes(),
                        &v.public_attributes(),
                        &bsr.get_commitment_hash(),
                        &vco,
                    )
                    .unwrap()
                })
                .enumerate()
                .map(|(idx, s)| SignatureShare::new(s, (idx + 1) as u64))
                .collect::<Vec<SignatureShare>>()
        })
        .collect::<Vec<Vec<SignatureShare>>>();

        // aggregate partial signatures
        let signatures = signatures_shares
            .iter()
            .zip(vouchers.iter())
            .map(|(ss, v)| {
                aggregate_signature_shares(
                    &params.coconut_params,
                    &verification_key,
                    &v.attributes(),
                    &ss,
                )
                .unwrap()
            })
            .collect::<Vec<Signature>>();

        Ok(())
    }
}
