use bls12_381::{G2Projective, Scalar};
use itertools::izip;
use nymcoconut::{
    aggregate_signature_shares, blind_sign, issue_range_signatures, keygen, prepare_blind_sign,
    randomise_and_request_vouchers, randomise_and_spend_vouchers, verify_request_vouchers,
    verify_spent_vouchers, BlindSignRequest, BlindedSignature, KeyPair, Parameters, Signature,
    SignatureShare, ThetaSpendPhase, VerificationKey,
};

type Attribute = Scalar;
type Attributes = Vec<Attribute>;

type Openings = Vec<Scalar>;

type BlindedSignatureShares = Vec<BlindedSignature>;
type SignatureShares = Vec<SignatureShare>;

pub struct ECashParams {
    pub coconut_params: Parameters,
    pub pay_max: Scalar,
    pub voucher_max: Scalar,
}

impl ECashParams {
    pub fn new(num_attributes: u32, pay_max: Scalar, voucher_max: Scalar) -> ECashParams {
        ECashParams {
            coconut_params: Parameters::new(num_attributes).unwrap(),
            pay_max,
            voucher_max,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Voucher {
    binding_number: Attribute,
    value: Attribute,
    serial_number: Attribute,
    info: Attribute,
}

impl Voucher {
    fn new(coconut_params: &Parameters, binding_number: Attribute, value: Attribute) -> Voucher {
        Self {
            binding_number,
            value,
            serial_number: coconut_params.random_scalar(),
            info: Scalar::from(0),
        }
    }

    fn new_many(
        coconut_params: &Parameters,
        binding_number: &Attribute,
        values: &[Attribute],
    ) -> Vec<Self> {
        values
            .iter()
            .map(|v| Voucher::new(coconut_params, *binding_number, *v))
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

struct ThetaSpendAndInfos {
    theta: ThetaSpendPhase,
    infos: Attributes,
}

impl SignedVouchersList {
    fn new(vouchers: &[Voucher], signatures: &[Signature]) -> Self {
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

        // if we have not find vouchers for every value, return an empty vec
        if indices.len() == values.len() {
            indices
        } else {
            vec![]
        }
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
    ) -> ThetaSpendAndInfos {
        assert!(self.to_be_spent_vouchers.len() == 0);

        // find vouchers to be spent
        let to_be_spent_vouchers_indices = self.find(&values);

        // move vouchers from unspent to to be spent
        self.move_vouchers_from_unspent_to_to_be_spent(&to_be_spent_vouchers_indices);

        assert!(self.to_be_spent_vouchers.len() > 0);

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

        let theta = randomise_and_spend_vouchers(
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

        ThetaSpendAndInfos { theta, infos }
    }

    // // TODO: return openings and blindsignrequests
    // fn prepare_request_vouchers_blind_sign(
    //     &mut self,
    //     coconut_params: &Parameters,
    //     validator_verification_key: &VerificationKey,
    //     pay: &Scalar,
    //     to_be_spent_values: &[Attribute],
    //     to_be_issued_values: &[Attribute],
    // ) {
    //     // find vouchers to be spent
    //     let to_be_spent_vouchers_indices = self.find(&to_be_spent_values);

    //     // move vouchers from unspent to to be spent
    //     self.move_vouchers_from_unspent_to_to_be_spent(&to_be_spent_vouchers_indices);

    //     assert!(self.to_be_spent_vouchers.len() > 0);

    //     let binding_number = self.to_be_spent_vouchers[0].voucher.binding_number;
    //     let (values, serial_numbers): (Attributes, Attributes) = self
    //         .to_be_spent_vouchers
    //         .iter()
    //         .map(|signed_voucher| {
    //             (
    //                 signed_voucher.voucher.value,
    //                 signed_voucher.voucher.serial_number,
    //             )
    //         })
    //         .unzip();
    //     let signatures: Vec<Signature> = self
    //         .to_be_spent_vouchers
    //         .iter()
    //         .map(|signed_voucher| signed_voucher.signature)
    //         .collect();

    //     let to_be_issued_vouchers =
    //         Voucher::new_many(&coconut_params, &binding_number, &to_be_issued_values);
    //     let to_be_issued_vouchers_public_attributes: Vec<Attributes> = to_be_issued_vouchers
    //         .iter()
    //         .map(|v| v.public_attributes())
    //         .collect();
    //     // let (blinded_signatures_shares_openings, blinded_signatures_shares_requests) =
    //     //     prepare_vouchers_blind_sign(&coconut_params, &to_be_issued_vouchers);
    // }

    fn confirm_vouchers_spent(&mut self) {
        for voucher in self.to_be_spent_vouchers.iter() {
            self.spent_vouchers.push(*voucher);
        }

        self.to_be_spent_vouchers.clear();
    }
}

impl ThetaSpendAndInfos {
    // return true if the vouchers are accepted, false otherwise
    fn verify(
        &self,
        coconut_params: &Parameters,
        validators_verification_key: &VerificationKey,
        bulletin_board: &mut BulletinBoard,
        values: &[Scalar],
    ) -> bool {
        // check double spending
        let double_spending_tags = &self.theta.blinded_serial_numbers;
        if !bulletin_board.check_valid_double_spending_tags(&double_spending_tags) {
            return false;
        }

        // check committed amount
        let c: G2Projective = values
            .iter()
            .map(|value| coconut_params.gen2() * value)
            .sum();
        if c != self.theta.blinded_spent_amount {
            return false;
        }

        // check vouchers
        if !verify_spent_vouchers(
            coconut_params,
            validators_verification_key,
            &self.theta,
            &self.infos,
        ) {
            return false;
        }

        // add double_spending_tags to bulletin board
        bulletin_board.add_tags(&double_spending_tags);

        true
    }
}

struct BulletinBoard {
    double_spending_tags: Vec<G2Projective>,
}

impl BulletinBoard {
    fn new() -> Self {
        BulletinBoard {
            double_spending_tags: vec![],
        }
    }

    fn check_valid_double_spending_tag(&self, tag: &G2Projective) -> bool {
        !self.double_spending_tags.contains(tag)
    }

    fn check_valid_double_spending_tags(&self, tags: &[G2Projective]) -> bool {
        for tag in tags {
            if !self.check_valid_double_spending_tag(&tag) {
                return false;
            }
        }

        true
    }

    fn add_tag(&mut self, tag: &G2Projective) {
        self.double_spending_tags.push(*tag);
    }

    fn add_tags(&mut self, tags: &[G2Projective]) {
        for tag in tags {
            self.add_tag(tag);
        }
    }
}

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
    fn e2e_spend() {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max);
        let mut bulletin_board = BulletinBoard::new();

        // generate validators keypairs
        let validators_key_pairs = ttp_keygen(&params.coconut_params, 2, 3).unwrap();
        let validators_verification_keys: Vec<VerificationKey> = validators_key_pairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();
        let validators_verification_key =
            aggregate_verification_keys(&validators_verification_keys, Some(&[1, 2, 3])).unwrap();

        // create initial vouchers
        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10); 5]; // 5 vouchers of value 10

        let vouchers = Voucher::new_many(&params.coconut_params, &binding_number, &values);
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

        // check we actually have 5 unspent vouchers
        assert!(
            signed_vouchers_list.unspent_vouchers.len() == 5
                && signed_vouchers_list.to_be_spent_vouchers.len() == 0
                && signed_vouchers_list.spent_vouchers.len() == 0
        );

        // values to be spent
        let values_30 = vec![Scalar::from(10); 3];

        // user randomises her vouchers and generates the proof to spend them
        let proof_to_spend_30 = signed_vouchers_list.randomise_and_prove_to_be_spent_vouchers(
            &params.coconut_params,
            &validators_verification_key,
            &values_30,
        );

        // check 3 vouchers are move to be spent
        assert!(
            signed_vouchers_list.unspent_vouchers.len() == 2
                && signed_vouchers_list.to_be_spent_vouchers.len() == 3
                && signed_vouchers_list.spent_vouchers.len() == 0
        );

        // entity a with the validators verification key accepts the proof if valid
        let proof_to_spend_30_accepted = proof_to_spend_30.verify(
            &params.coconut_params,
            &validators_verification_key,
            &mut bulletin_board,
            &values_30,
        );

        // user mark her vouchers as spent if accepted by entity a
        if proof_to_spend_30_accepted {
            signed_vouchers_list.confirm_vouchers_spent();
        }

        // check the proof is accepted and vouchers are moved to spent
        assert!(
            proof_to_spend_30_accepted
                && signed_vouchers_list.unspent_vouchers.len() == 2
                && signed_vouchers_list.to_be_spent_vouchers.len() == 0
                && signed_vouchers_list.spent_vouchers.len() == 3
        );

        // reuse a proof
        let reused_proof_to_spend_30_accepted = proof_to_spend_30.verify(
            &params.coconut_params,
            &validators_verification_key,
            &mut bulletin_board,
            &values_30,
        );

        // check this is not accepted
        assert!(!reused_proof_to_spend_30_accepted);

        // values to be spent
        let values_20 = vec![Scalar::from(10); 2];

        // user randomises her vouchers and generates the proof to spend them
        let proof_to_spend_20 = signed_vouchers_list.randomise_and_prove_to_be_spent_vouchers(
            &params.coconut_params,
            &validators_verification_key,
            &values_20,
        );

        // check 2 vouchers are move to be spent
        assert!(
            signed_vouchers_list.unspent_vouchers.len() == 0
                && signed_vouchers_list.to_be_spent_vouchers.len() == 2
                && signed_vouchers_list.spent_vouchers.len() == 3
        );

        // use proof to spend 20 to spend 30
        let proof_to_spend_20_accepted_for_30 = proof_to_spend_20.verify(
            &params.coconut_params,
            &validators_verification_key,
            &mut bulletin_board,
            &values_30,
        );

        // check this is not accpeted
        assert!(!proof_to_spend_20_accepted_for_30);

        // entity a with the validators verification key accepts the proof if valid
        let proof_to_spend_20_accepted = proof_to_spend_20.verify(
            &params.coconut_params,
            &validators_verification_key,
            &mut bulletin_board,
            &values_20,
        );

        // user mark her vouchers as spent if accepted by entity a
        if proof_to_spend_20_accepted {
            signed_vouchers_list.confirm_vouchers_spent();
        }

        // check the proof is accepted and vouchers are moved to spent
        assert!(
            proof_to_spend_20_accepted
                && signed_vouchers_list.unspent_vouchers.len() == 0
                && signed_vouchers_list.to_be_spent_vouchers.len() == 0
                && signed_vouchers_list.spent_vouchers.len() == 5
        );
    }

    #[test]
    fn e2e_request() {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max);
        let mut bulletin_board = BulletinBoard::new();

        // generate validators keypairs
        let validators_key_pairs = ttp_keygen(&params.coconut_params, 2, 3).unwrap();
        let validators_verification_keys: Vec<VerificationKey> = validators_key_pairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();
        let validators_verification_key =
            aggregate_verification_keys(&validators_verification_keys, Some(&[1, 2, 3])).unwrap();

        // generate range proof signatures
        let range_proof_keypair = keygen(&params.coconut_params);
        let range_proof_verification_key = range_proof_keypair.verification_key();
        let range_proof_secret_key = range_proof_keypair.secret_key();

        let range_proof_base_u: u8 = 4;
        let range_proof_number_of_elements_l: u8 = 8;

        let range_proof_h = params.coconut_params.gen1() * params.coconut_params.random_scalar();
        let range_proof_signatures = issue_range_signatures(
            &range_proof_h,
            &range_proof_secret_key,
            range_proof_base_u as usize,
        );

        // create initial vouchers
        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10); 5]; // 5 vouchers of value 10

        let vouchers = Voucher::new_many(&params.coconut_params, &binding_number, &values);
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

        // check we actually have 5 unspent vouchers
        assert!(
            signed_vouchers_list.unspent_vouchers.len() == 5
                && signed_vouchers_list.to_be_spent_vouchers.len() == 0
                && signed_vouchers_list.spent_vouchers.len() == 0
        );

        let pay = 5;

        let to_be_issued_values = [Scalar::from(3), Scalar::from(2)];
        let to_be_spent_values = [Scalar::from(10)];

        // TODO complete e2e test for request
        assert!(signed_vouchers_list.to_be_spent_vouchers.len() == 0);

        let to_be_spent_vouchers_indices = signed_vouchers_list.find(&to_be_spent_values);

        signed_vouchers_list
            .move_vouchers_from_unspent_to_to_be_spent(&to_be_spent_vouchers_indices);

        assert!(signed_vouchers_list.to_be_spent_vouchers.len() > 0);

        let number_of_to_be_issued_vouchers = to_be_issued_values.len() as u8;
        let number_of_to_be_spent_vouchers = to_be_spent_values.len() as u8;

        let binding_number = signed_vouchers_list.to_be_spent_vouchers[0]
            .voucher
            .binding_number;

        let to_be_issued_vouchers = Voucher::new_many(
            &params.coconut_params,
            &binding_number,
            &to_be_issued_values,
        );

        let to_be_issued_vouchers_public_attributes: Vec<Attributes> = to_be_issued_vouchers
            .iter()
            .map(|v| v.public_attributes())
            .collect();

        let (to_be_issued_values, to_be_issued_serial_numbers): (Attributes, Attributes) =
            to_be_issued_vouchers
                .iter()
                .map(|voucher| (voucher.value, voucher.serial_number))
                .unzip();

        let (to_be_spent_values, to_be_spent_serial_numbers): (Attributes, Attributes) =
            signed_vouchers_list
                .to_be_spent_vouchers
                .iter()
                .map(|signed_voucher| {
                    (
                        signed_voucher.voucher.value,
                        signed_voucher.voucher.serial_number,
                    )
                })
                .unzip();

        let to_be_spent_signatures: Vec<Signature> = signed_vouchers_list
            .to_be_spent_vouchers
            .iter()
            .map(|signed_voucher| signed_voucher.signature)
            .collect();

        let proof_to_request = randomise_and_request_vouchers(
            &params.coconut_params,
            &validators_verification_key,
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

        let to_be_spent_vouchers_public_attributes: Attributes = signed_vouchers_list
            .to_be_spent_vouchers
            .iter()
            .map(|signed_voucher| signed_voucher.voucher.info)
            .collect();

        assert!(verify_request_vouchers(
            &params.coconut_params,
            &validators_verification_key,
            &range_proof_verification_key,
            &proof_to_request,
            &to_be_spent_vouchers_public_attributes
        ));
    }

    #[test]
    fn test_signed_vouchers_list_find_empty_vouchers() {
        let vouchers = vec![];
        let signatures = vec![];

        let signed_vouchers_list = SignedVouchersList::new(&vouchers, &signatures);

        let values = vec![];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);
    }

    #[test]
    fn test_signed_vouchers_list_find_one_voucher() {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max);

        let number_of_vouchers = 1;

        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10)];

        let vouchers = Voucher::new_many(&params.coconut_params, &binding_number, &values);
        let signatures: Vec<Signature> = (0..number_of_vouchers)
            .map(|_| {
                Signature(
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                )
            })
            .collect();

        let signed_vouchers_list = SignedVouchersList::new(&vouchers, &signatures);

        let values = vec![];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0]);

        let values = vec![Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);
    }

    #[test]
    fn test_signed_vouchers_list_find_three_equal_vouchers() {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max);

        let number_of_vouchers = 3;

        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10), Scalar::from(10), Scalar::from(10)];

        let vouchers = Voucher::new_many(&params.coconut_params, &binding_number, &values);
        let signatures: Vec<Signature> = (0..number_of_vouchers)
            .map(|_| {
                Signature(
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                )
            })
            .collect();

        let signed_vouchers_list = SignedVouchersList::new(&vouchers, &signatures);

        let values = vec![];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0]);

        let values = vec![Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0, 1]);

        let values = vec![Scalar::from(5), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(5), Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0, 1, 2]);

        let values = vec![Scalar::from(5), Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(5), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10), Scalar::from(10), Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![
            Scalar::from(10),
            Scalar::from(10),
            Scalar::from(10),
            Scalar::from(10),
        ];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);
    }

    #[test]
    fn test_signed_vouchers_list_find_three_vouchers() {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max);

        let number_of_vouchers = 3;

        let binding_number = params.coconut_params.random_scalar();
        let values = [Scalar::from(10), Scalar::from(5), Scalar::from(10)];

        let vouchers = Voucher::new_many(&params.coconut_params, &binding_number, &values);
        let signatures: Vec<Signature> = (0..number_of_vouchers)
            .map(|_| {
                Signature(
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                    params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                )
            })
            .collect();

        let signed_vouchers_list = SignedVouchersList::new(&vouchers, &signatures);

        let values = vec![];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);

        let values = vec![Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0]);

        let values = vec![Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![1]);

        let values = vec![Scalar::from(10), Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0, 1]);

        let values = vec![Scalar::from(5), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![1, 0]);

        let values = vec![Scalar::from(10), Scalar::from(5), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0, 1, 2]);

        let values = vec![Scalar::from(5), Scalar::from(10), Scalar::from(10)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![1, 0, 2]);

        let values = vec![Scalar::from(10), Scalar::from(10), Scalar::from(5)];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices, vec![0, 2, 1]);

        let values = vec![
            Scalar::from(10),
            Scalar::from(5),
            Scalar::from(10),
            Scalar::from(5),
        ];
        let indices = signed_vouchers_list.find(&values);
        assert_eq!(indices.len(), 0);
    }
}
