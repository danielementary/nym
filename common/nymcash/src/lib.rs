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

    pub fn number_of_attributes() -> u32 {
        4
    }
}

// struct that carries all the information concerning a given list of vouchers
pub struct VouchersList {
    pub vouchers: Vec<Voucher>,
    pub used: Vec<bool>,
    pub commitments_openings: Vec<Vec<Scalar>>,
    pub signatures: Vec<Signature>,
}

impl VouchersList {
    pub fn new(
        vouchers: Vec<Voucher>,
        commitments_openings: Vec<Vec<Scalar>>,
        signatures: Vec<Signature>,
    ) -> VouchersList {
        let len = vouchers.len();

        VouchersList {
            vouchers,
            used: vec![false; len],
            commitments_openings,
            signatures,
        }
    }

    // returns the list of indices from a VouchersList for vouchers to be spend for given values
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
    use itertools::izip;
    use nymcoconut::{
        aggregate_signature_shares, aggregate_verification_keys, blind_sign, prepare_blind_sign,
        ttp_keygen, BlindSignRequest, BlindedSignature, Signature, SignatureShare, VerificationKey,
    };

    #[test]
    fn main() -> Result<(), CoconutError> {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max)?;

        // generate authorities keypairs
        let authorities_keypairs = ttp_keygen(&params.coconut_params, 2, 3)?;
        let authorities_verification_keys: Vec<VerificationKey> = authorities_keypairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();
        let authorities_verification_key =
            aggregate_verification_keys(&authorities_verification_keys, Some(&[1, 2, 3])).unwrap();

        // create initial vouchers
        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10); 5]; // 5 vouchers of value 10

        let vouchers = Voucher::new_many(&params.coconut_params, binding_number, &values);

        // prepare requests for initial vouchers signatures partial signatures
        let (blinded_signatures_shares_openings, blinded_signatures_shares_requests): (
            Vec<Vec<Scalar>>,
            Vec<BlindSignRequest>,
        ) = vouchers
            .iter()
            .map(|v| {
                prepare_blind_sign(
                    &params.coconut_params,
                    &v.private_attributes(),
                    &v.public_attributes(),
                )
                .unwrap()
            })
            .unzip();

        // issue signatures for initial vouchers partial signatures
        let blinded_signatures_shares: Vec<Vec<BlindedSignature>> =
            blinded_signatures_shares_requests
                .iter()
                .zip(vouchers.iter())
                .map(|(r, v)| {
                    authorities_keypairs
                        .iter()
                        .map(|kp| {
                            blind_sign(
                                &params.coconut_params,
                                &kp.secret_key(),
                                &r,
                                &v.public_attributes(),
                            )
                            .unwrap()
                        })
                        .collect::<Vec<BlindedSignature>>()
                })
                .collect();

        // unblind partial signatures
        let signatures_shares: Vec<Vec<SignatureShare>> = izip!(
            blinded_signatures_shares.iter(),
            vouchers.iter(),
            blinded_signatures_shares_openings.iter(),
            blinded_signatures_shares_requests.iter()
        )
        .map(|(bss, v, bss_openings, bss_request)| {
            izip!(bss.iter(), authorities_verification_keys.iter())
                .map(|(s, vk)| {
                    s.unblind(
                        &params.coconut_params,
                        &vk,
                        &v.private_attributes(),
                        &v.public_attributes(),
                        &bss_request.get_commitment_hash(),
                        &bss_openings,
                    )
                    .unwrap()
                })
                .enumerate()
                .map(|(idx, s)| SignatureShare::new(s, (idx + 1) as u64))
                .collect::<Vec<SignatureShare>>()
        })
        .collect();

        // aggregate partial signatures
        let signatures: Vec<Signature> = signatures_shares
            .iter()
            .zip(vouchers.iter())
            .map(|(ss, v)| {
                aggregate_signature_shares(
                    &params.coconut_params,
                    &authorities_verification_key,
                    &v.attributes(),
                    &ss,
                )
                .unwrap()
            })
            .collect();

        // bring together vouchers and corresponding signatures
        let vouchers_list =
            VouchersList::new(vouchers, blinded_signatures_shares_openings, signatures);

        // values to be spent
        let values = vec![Scalar::from(10), Scalar::from(10)];

        // find indices of vouchers that can be used
        let vouchers_list_indices = vouchers_list.find(&values);

        Ok(())
    }
}
