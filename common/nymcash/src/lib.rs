use bls12_381::Scalar;
use itertools::izip;
use nymcoconut::{
    aggregate_signature_shares, blind_sign, prepare_blind_sign, BlindSignRequest, BlindedSignature,
    CoconutError, KeyPair, Parameters, Signature, SignatureShare, VerificationKey,
};
use std::error::Error;

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

// structs that carry all the information concerning a given list of signed vouchers
pub struct SignedVoucher {
    pub voucher: Voucher,
    pub signature: Signature,
    pub used: bool,
}

impl SignedVoucher {
    pub fn set_spent(&mut self) {
        self.used = true;
    }
}

pub struct SignedVouchersList {
    pub signed_vouchers: Vec<SignedVoucher>,
}

impl VouchersList {
    pub fn new(vouchers: Vec<Voucher>, signatures: Vec<Signature>) -> VouchersList {
        let signed_vouchers = izip!(vouchers.iter(), signatures.iter())
            .map(|(v, s)| SignedVoucher {
                voucher: v,
                signature: s,
                used: false,
            })
            .collect();

        SignedVouchersList { signed_vouchers }
    }

    // returns a list of references to signed vouchers to be spend for given values
    pub fn find(&self, values: &[Scalar]) -> Result<Vec<&mut SignedVoucher>, Error> {
        let mut signed_vouchers = Vec::new();

        for val in values {
            for sv in self.signed_vouchers.iter() {
                if sv.voucher.value == *val && !sv.voucher.used && !signed_vouchers.contains(&sv) {
                    vouchers_indices.push(sv);
                    break;
                }
            }
        }

        if signed_vouchers.len() == values.len() {
            Ok(signed_vouchers)
        } else {
            Err(Error)
        }
    }
}

// returns a tuple with blind signatures requests and corresponding openings
fn prepare_vouchers_blind_sign(
    params: &Parameters,
    vouchers: &[Voucher],
) -> (Vec<Vec<Scalar>>, Vec<BlindSignRequest>) {
    vouchers
        .iter()
        .map(|v| {
            prepare_blind_sign(&params, &v.private_attributes(), &v.public_attributes()).unwrap()
        })
        .unzip()
}

// returns the list of blinded signatures shares
fn vouchers_blind_sign(
    params: &Parameters,
    blinded_signatures_shares_requests: &[BlindSignRequest],
    public_attributes: &[Vec<Scalar>],
    authorities_keypairs: &[KeyPair],
) -> Vec<Vec<BlindedSignature>> {
    blinded_signatures_shares_requests
        .iter()
        .zip(public_attributes.iter())
        .map(|(r, pa)| {
            authorities_keypairs
                .iter()
                .map(|kp| blind_sign(&params, &kp.secret_key(), &r, &pa).unwrap())
                .collect::<Vec<BlindedSignature>>()
        })
        .collect()
}

// return the list of unblinded signatures shares
fn unblind_vouchers_signatures_shares(
    params: &Parameters,
    blinded_signatures_shares: &[Vec<BlindedSignature>],
    vouchers: &[Voucher],
    blinded_signatures_shares_openings: &[Vec<Scalar>],
    blinded_signatures_shares_requests: &[BlindSignRequest],
    authorities_verification_keys: &[VerificationKey],
) -> Vec<Vec<SignatureShare>> {
    izip!(
        blinded_signatures_shares.iter(),
        vouchers.iter(),
        blinded_signatures_shares_openings.iter(),
        blinded_signatures_shares_requests.iter()
    )
    .map(|(bss, v, bss_openings, bss_request)| {
        izip!(bss.iter(), authorities_verification_keys.iter())
            .map(|(s, vk)| {
                s.unblind(
                    &params,
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
    .collect()
}

// return vouchers signatures
fn aggregate_vouchers_signatures_shares(
    params: &Parameters,
    signatures_shares: &[Vec<SignatureShare>],
    vouchers: &[Voucher],
    authorities_verification_key: &VerificationKey,
) -> Vec<Signature> {
    izip!(signatures_shares.iter(), vouchers.iter())
        .map(|(ss, v)| {
            aggregate_signature_shares(&params, &authorities_verification_key, &v.attributes(), &ss)
                .unwrap()
        })
        .collect()
}

fn prepare_vouchers_to_be_spent(
    params: &Parameters,
    authorities_verification_key: &VerificationKey,
    vouchers_to_be_spent: &[&mut SignedVoucher],
) -> Result<ThetaSpend, Error> {
    //TODO
    Err(Error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nymcoconut::{aggregate_verification_keys, ttp_keygen};

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
        let vouchers_public_attributes: Vec<Vec<Scalar>> =
            vouchers.iter().map(|v| v.public_attributes()).collect();

        // prepare requests for initial vouchers signatures partial signatures
        let (blinded_signatures_shares_openings, blinded_signatures_shares_requests) =
            prepare_vouchers_blind_sign(&params.coconut_params, &vouchers);

        // issue signatures for initial vouchers partial signatures
        let blinded_signatures_shares = vouchers_blind_sign(
            &params.coconut_params,
            &blinded_signatures_shares_requests,
            &vouchers_public_attributes,
            &authorities_keypairs,
        );

        // unblind partial signatures
        let signatures_shares = unblind_vouchers_signatures_shares(
            &params.coconut_params,
            &blinded_signatures_shares,
            &vouchers,
            &blinded_signatures_shares_openings,
            &blinded_signatures_shares_requests,
            &authorities_verification_keys,
        );

        // aggregate partial signatures
        let signatures = aggregate_vouchers_signatures_shares(
            &params.coconut_params,
            &signatures_shares,
            &vouchers,
            &authorities_verification_key,
        );

        // bring together vouchers and corresponding signatures
        let signed_vouchers_list = SignedVouchersList::new(vouchers, signatures);

        // values to be spent
        let values = vec![Scalar::from(10), Scalar::from(10)];

        // find indices of vouchers that can be used
        let vouchers_to_be_spent = vouchers_list.find(&values).unwrap();

        let theta = prepare_vouchers_to_be_spent(
            &params.coconut_params,
            &authorities_verification_key,
            &mut vouchers_to_be_spent,
        );

        Ok(())
    }
}
