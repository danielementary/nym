use bls12_381::Scalar;
use itertools::izip;
use nymcoconut::{
    aggregate_signature_shares, blind_sign, prepare_blind_sign, randomise_and_prove_vouchers,
    verify_vouchers, BlindSignRequest, BlindedSignature, CoconutError, KeyPair, Parameters,
    Signature, SignatureShare, ThetaSpend, VerificationKey,
}; // TODO add EcashError and review every ? and .unwrap()

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
        //TODO add ECashError to substitute CocoNutError
        Ok(ECashParams {
            coconut_params: Parameters::new(num_attributes)?,
            pay_max,
            voucher_max,
        })
    }
}

type Attribute = Scalar;

#[derive(Debug, Copy, Clone)]
struct Voucher {
    binding_number: Attribute,
    value: Attribute,
    serial_number: Attribute,
    info: Attribute,
}

type Attributes = Vec<Attribute>;

impl Voucher {
    fn new(coconut_params: &Parameters, binding_number: Attribute, value: Attribute) -> Voucher {
        Voucher {
            binding_number,
            value,
            serial_number: coconut_params.random_scalar(),
            info: Scalar::from(0),
        }
    }

    fn new_many(
        coconut_params: &Parameters,
        binding_number: Attribute,
        values: &[Attribute],
    ) -> Vec<Voucher> {
        values
            .iter()
            .map(|v| Voucher::new(coconut_params, binding_number, *v))
            .collect()
    }

    fn private_attributes(&self) -> Attributes {
        vec![self.binding_number, self.value, self.serial_number]
    }

    fn public_attributes(&self) -> Attributes {
        vec![self.info]
    }

    fn attributes(&self) -> Attributes {
        vec![
            self.binding_number,
            self.value,
            self.serial_number,
            self.info,
        ]
    }

    fn number_of_attributes() -> u32 {
        4
    }
}

#[derive(Debug, Copy, Clone)]
struct SignedVoucher {
    voucher: Voucher,
    signature: Signature,
}

struct SignedVouchersList {
    unspent_vouchers: Vec<SignedVoucher>, // vouchers that have not yet been spent
    spent_vouchers: Vec<SignedVoucher>,   // voucher that have already been spent
    to_be_spent_vouchers: Vec<SignedVoucher>, // temporary place for voucher before they are spent
}

struct ThetaAndInfos {
    theta: ThetaSpend,
    infos: Attributes,
}

impl SignedVouchersList {
    fn new(vouchers: &[Voucher], signatures: &[Signature]) -> Self {
        //TODO add ECashError and throw one if vouchers.len() != signatures.len()
        let unspent_vouchers = izip!(vouchers.into_iter(), signatures.into_iter())
            .map(|(voucher, signature)| SignedVoucher {
                voucher: *voucher,
                signature: *signature,
            })
            .collect();

        let spent_vouchers = vec![];
        let to_be_spent_vouchers = vec![];

        SignedVouchersList {
            unspent_vouchers,
            spent_vouchers,
            to_be_spent_vouchers,
        }
    }

    // returns a list of indices of the vouchers to be spend for given values
    // TODO add ECashError and throw one if there is not enough vouchers
    fn find(&self, values: &[Attribute]) -> Vec<usize> {
        let mut indices = Vec::new();

        for value in values {
            for (index, signed_voucher) in self.unspent_vouchers.iter().enumerate() {
                if signed_voucher.voucher.value == *value && !indices.contains(&index) {
                    indices.push(index);
                    break;
                }
            }
        }

        indices
    }

    fn move_vouchers_from_unspent_to_to_be_spent(&mut self, indices: &[usize]) {
        let mut unspent_vouchers = Vec::new();
        let mut to_be_spent_vouchers = Vec::new();

        for (index, voucher) in self.unspent_vouchers.iter().enumerate() {
            if indices.contains(&index) {
                to_be_spent_vouchers.push(*voucher);
            } else {
                unspent_vouchers.push(*voucher);
            }
        }

        self.unspent_vouchers = unspent_vouchers;
        self.to_be_spent_vouchers = to_be_spent_vouchers;
    }

    fn randomise_and_prove_to_be_spent_vouchers(
        &mut self,
        coconut_params: &Parameters,
        validator_verification_key: &VerificationKey,
        values: &[Attribute],
    ) -> ThetaAndInfos {
        // find vouchers to be spent
        let to_be_spent_vouchers_indices = self.find(&values);

        // move vouchers from unspent to to be spent
        self.move_vouchers_from_unspent_to_to_be_spent(&to_be_spent_vouchers_indices);

        let binding_number = self.to_be_spent_vouchers[0].voucher.binding_number;
        let (values, serial_numbers): (Attributes, Attributes) = self
            .to_be_spent_vouchers
            .iter()
            .map(|signed_voucher| {
                (
                    signed_voucher.voucher.value,
                    signed_voucher.voucher.serial_number,
                )
            })
            .unzip();
        let signatures: Vec<Signature> = self
            .to_be_spent_vouchers
            .iter()
            .map(|signed_voucher| signed_voucher.signature)
            .collect();

        let theta = randomise_and_prove_vouchers(
            coconut_params,
            validator_verification_key,
            &binding_number,
            &values,
            &serial_numbers,
            &signatures,
        )
        .unwrap();
        let infos: Attributes = self
            .to_be_spent_vouchers
            .iter()
            .map(|signed_voucher| signed_voucher.voucher.info)
            .collect();

        ThetaAndInfos { theta, infos }
    }

    fn confirm_vouchers_spent(&mut self) {
        for voucher in self.to_be_spent_vouchers.iter() {
            self.spent_vouchers.push(*voucher);
        }

        self.to_be_spent_vouchers.clear();
    }
}

impl ThetaAndInfos {
    // return true if the vouchers are accepted, false otherwise
    fn verify(
        &self,
        coconut_params: &Parameters,
        validators_verification_key: &VerificationKey,
    ) -> bool {
        verify_vouchers(
            coconut_params,
            validators_verification_key,
            &self.theta,
            &self.infos,
        )
    }
}

type Openings = Vec<Scalar>;

// returns a tuple with blind signatures requests and corresponding openings
fn prepare_vouchers_blind_sign(
    params: &Parameters,
    vouchers: &[Voucher],
) -> (Vec<Openings>, Vec<BlindSignRequest>) {
    vouchers
        .iter()
        .map(|voucher| {
            prepare_blind_sign(
                &params,
                &voucher.private_attributes(),
                &voucher.public_attributes(),
            )
            .unwrap()
        })
        .unzip()
}

type BlindedSignatureShares = Vec<BlindedSignature>;

// returns the list of blinded signatures shares
fn vouchers_blind_sign(
    params: &Parameters,
    blinded_signatures_shares_requests: &[BlindSignRequest],
    vouchers_public_attributes: &[Attributes],
    validators_key_pairs: &[KeyPair],
) -> Vec<BlindedSignatureShares> {
    izip!(
        blinded_signatures_shares_requests.iter(),
        vouchers_public_attributes.iter()
    )
    .map(|(request, public_attributes)| {
        validators_key_pairs
            .iter() // each validator issue blinded signatures for every signature share
            .map(|key_pair| {
                blind_sign(
                    &params,
                    &key_pair.secret_key(),
                    &request,
                    &public_attributes,
                )
                .unwrap()
            })
            .collect::<BlindedSignatureShares>()
    })
    .collect()
}

type SignatureShares = Vec<SignatureShare>;

// return the list of unblinded signatures shares
fn unblind_vouchers_signatures_shares(
    params: &Parameters,
    blinded_signatures_shares: &[BlindedSignatureShares],
    vouchers: &[Voucher],
    blinded_signatures_shares_openings: &[Openings],
    blinded_signatures_shares_requests: &[BlindSignRequest],
    validators_verification_keys: &[VerificationKey],
) -> Vec<SignatureShares> {
    izip!(
        blinded_signatures_shares.iter(),
        vouchers.iter(),
        blinded_signatures_shares_openings.iter(),
        blinded_signatures_shares_requests.iter()
    )
    .map(|(blinded_signature_shares, voucher, openings, request)| {
        izip!(
            blinded_signature_shares.iter(),
            validators_verification_keys.iter()
        )
        .map(|(blinded_signature_share, validator_verification_key)| {
            blinded_signature_share // unblind each signature share issued by each validator
                .unblind(
                    &params,
                    &validator_verification_key,
                    &voucher.private_attributes(),
                    &voucher.public_attributes(),
                    &request.get_commitment_hash(),
                    &openings,
                )
                .unwrap()
        })
        .enumerate()
        .map(|(index, signature_share)| SignatureShare::new(signature_share, (index + 1) as u64))
        .collect::<SignatureShares>()
    })
    .collect()
}

// return aggregated vouchers signatures
fn aggregate_vouchers_signatures_shares(
    params: &Parameters,
    signatures_shares: &[SignatureShares],
    vouchers: &[Voucher],
    validators_verification_key: &VerificationKey,
) -> Vec<Signature> {
    izip!(signatures_shares.iter(), vouchers.iter())
        .map(|(signature_share, voucher)| {
            aggregate_signature_shares(
                &params,
                &validators_verification_key,
                &voucher.attributes(),
                &signature_share,
            )
            .unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nymcoconut::{aggregate_verification_keys, ttp_keygen};

    #[test]
    fn e2e() -> Result<(), CoconutError> {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max)?;

        // generate validators keypairs
        let validators_key_pairs = ttp_keygen(&params.coconut_params, 2, 3)?;
        let validators_verification_keys: Vec<VerificationKey> = validators_key_pairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();
        let validators_verification_key =
            aggregate_verification_keys(&validators_verification_keys, Some(&[1, 2, 3])).unwrap();

        // create initial vouchers
        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10); 5]; // 5 vouchers of value 10

        let vouchers = Voucher::new_many(&params.coconut_params, binding_number, &values);
        let vouchers_public_attributes: Vec<Attributes> =
            vouchers.iter().map(|v| v.public_attributes()).collect();

        // prepare requests for initial vouchers signatures partial signatures
        let (blinded_signatures_shares_openings, blinded_signatures_shares_requests) =
            prepare_vouchers_blind_sign(&params.coconut_params, &vouchers);

        // issue signatures for initial vouchers partial signatures
        let blinded_signatures_shares = vouchers_blind_sign(
            &params.coconut_params,
            &blinded_signatures_shares_requests,
            &vouchers_public_attributes,
            &validators_key_pairs,
        );

        // unblind partial signatures
        let signatures_shares = unblind_vouchers_signatures_shares(
            &params.coconut_params,
            &blinded_signatures_shares,
            &vouchers,
            &blinded_signatures_shares_openings,
            &blinded_signatures_shares_requests,
            &validators_verification_keys,
        );

        // aggregate partial signatures
        let signatures = aggregate_vouchers_signatures_shares(
            &params.coconut_params,
            &signatures_shares,
            &vouchers,
            &validators_verification_key,
        );

        // bring together vouchers and corresponding signatures
        let mut signed_vouchers_list = SignedVouchersList::new(&vouchers, &signatures);

        // values to be spent
        let values = vec![Scalar::from(10), Scalar::from(10)];

        // user randomises her vouchers and generates the proof to spend them
        let proof_to_spend = signed_vouchers_list.randomise_and_prove_to_be_spent_vouchers(
            &params.coconut_params,
            &validators_verification_key,
            &values,
        );

        // entity a with the validators verification key accepts the proof if valid
        let proof_accepted =
            proof_to_spend.verify(&params.coconut_params, &validators_verification_key);

        // user mark her vouchers as spent if accepted by entity a
        if proof_accepted {
            signed_vouchers_list.confirm_vouchers_spent();
        }

        Ok(())
    }
}
