use bls12_381::{G2Projective, Scalar};
use itertools::izip;
use nymcoconut::{
    aggregate_signature_shares, blind_sign, prepare_blind_sign, randomise_and_request_vouchers,
    randomise_and_spend_vouchers, verify_request_vouchers, verify_spent_vouchers, BlindSignRequest,
    BlindedSignature, KeyPair, Parameters, RangeProofSignatures, Signature, SignatureShare,
    ThetaRequestPhase, ThetaSpendPhase, VerificationKey,
};

// define new types for clarity
type Attribute = Scalar;
type Attributes = Vec<Attribute>;

type Opening = Scalar;
type Openings = Vec<Opening>;

type BlindedSignatureShare = BlindedSignature;
type BlindedSignatureShares = Vec<BlindedSignatureShare>;

type SignatureShares = Vec<SignatureShare>;

// define e-cash parameters with Coconut parameters and maxmimum values
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
    fn new(coconut_params: &Parameters, binding_number: Attribute, value: Attribute) -> Self {
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
            .map(|value| Voucher::new(coconut_params, *binding_number, *value))
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

// store a given voucher with its corresponding signature
#[derive(Debug, Copy, Clone)]
struct VoucherAndSignature {
    voucher: Voucher,
    signature: Signature,
}

// store all the vouchers and signatures of a given user
struct VouchersAndSignatures {
    unspent_vouchers: Vec<VoucherAndSignature>, // signed vouchers that have not yet been spent
    to_be_issued_vouchers: Vec<Voucher>,        // temporary place for vouchers before being issued
    to_be_spent_vouchers: Vec<VoucherAndSignature>, // temporary place for signed voucher before they are spent
    spent_vouchers: Vec<VoucherAndSignature>,       // signed vouchers that have already been spent
}

// used to return a proof theta and the corresponding (public) infos to verify it
struct ThetaSpendAndInfos {
    theta: ThetaSpendPhase,
    infos: Attributes,
}

// used to return a proof theta and the corresponding (public) infos to verify it
// as well as the requests to get the to_be_issued_vouchers signed
struct ThetaRequestAndInfos {
    theta: ThetaRequestPhase,
    to_be_issued_blinded_signatures_shares_requests: Vec<BlindSignRequest>,
    to_be_issued_infos: Vec<Attributes>,
    to_be_spent_infos: Vec<Attributes>,
}

impl VouchersAndSignatures {
    fn new(vouchers: &[Voucher], signatures: &[Signature]) -> Self {
        if vouchers.len() != signatures.len() {
            panic!("vouchers and signatures must have the same length")
        }

        // start with some unspent vouchers
        let unspent_vouchers = izip!(vouchers.iter(), signatures.iter())
            .map(|(voucher, signature)| VoucherAndSignature {
                voucher: *voucher,
                signature: *signature,
            })
            .collect();

        let to_be_spent_vouchers = vec![];
        let to_be_issued_vouchers = vec![];
        let spent_vouchers = vec![];

        Self {
            unspent_vouchers,
            to_be_spent_vouchers,
            to_be_issued_vouchers,
            spent_vouchers,
        }
    }

    // find unspent vouchers and move them to be spend for given values
    fn find(&mut self, values: &[Attribute]) {
        if values.is_empty() {
            panic!("values must not be empty");
        }

        let mut indices = Vec::new();

        for value in values {
            for (index, voucher_and_signature) in self.unspent_vouchers.iter().enumerate() {
                if voucher_and_signature.voucher.value == *value && !indices.contains(&index) {
                    indices.push(index);
                    break;
                }
            }
        }

        // if we have not find vouchers for every value, return an empty vec
        if indices.len() != values.len() {
            panic!("could not find unspent vouchers for the given values");
        }

        self.move_unspent_vouchers_to_to_be_spent(&indices);
    }

    // moves unspent vouchers according to provided indices to to be spent vouchers
    fn move_unspent_vouchers_to_to_be_spent(&mut self, indices: &[usize]) {
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

    // move to be issued vouchers to unspent vouchers with their corresponding signatures
    fn move_to_be_issued_vouchers_to_unspent(&mut self, signatures: &[Signature]) {
        if self.to_be_issued_vouchers.len() != signatures.len() {
            panic!("to be issued vouchers and signatures must have same length.");
        }

        for (voucher, signature) in izip!(self.to_be_issued_vouchers.iter(), signatures.iter()) {
            let new_unspent_voucher = VoucherAndSignature {
                voucher: *voucher,
                signature: *signature,
            };

            self.unspent_vouchers.push(new_unspent_voucher);
        }

        self.to_be_issued_vouchers = vec![];
    }

    // move to be spent vouchers to spent with their corresponding signatures
    fn move_to_be_spent_vouchers_to_spent(&mut self) {
        for voucher in self.to_be_spent_vouchers.iter() {
            self.spent_vouchers.push(*voucher);
        }

        self.to_be_spent_vouchers.clear();
    }

    // prepare proof and material to verify it for spending amount _pay_
    // spending _to_be_spent_values_ and being issued _to_be_issued_values_ vouchers
    fn randomise_and_prove_to_request_vouchers(
        &mut self,
        coconut_params: &Parameters,
        validators_verification_key: &VerificationKey,
        range_proof_verification_key: &VerificationKey,
        range_proof_base_u: u8,
        range_proof_number_of_elements_l: u8,
        range_proof_signatures: &RangeProofSignatures,
        pay: &Scalar,
        to_be_issued_values: &[Scalar],
        to_be_spent_values: &[Scalar],
    ) -> (ThetaRequestAndInfos, Vec<Openings>) {
        if !self.to_be_issued_vouchers.is_empty() {
            panic!("to_be_issued_vouchers must be empty");
        }

        if !self.to_be_spent_vouchers.is_empty() {
            panic!("to_be_spent_vouchers must be empty");
        }

        if to_be_issued_values.is_empty() {
            panic!("to_be_issued_values must not be empty");
        }

        if to_be_spent_values.is_empty() {
            panic!("to_be_spent_values must not be empty");
        }

        // find vouchers to be spent
        self.find(&to_be_spent_values);

        if self.to_be_spent_vouchers.len() != to_be_spent_values.len() {
            panic!("to_be_spent_vouchers must have same length as to_be_spent_values");
        }

        let number_of_to_be_issued_vouchers = to_be_issued_values.len() as u8;
        let number_of_to_be_spent_vouchers = to_be_spent_values.len() as u8;

        let binding_number = self.to_be_spent_vouchers[0].voucher.binding_number;

        // create new vouchers to be issued
        let to_be_issued_vouchers =
            Voucher::new_many(&coconut_params, &binding_number, &to_be_issued_values);

        // prepare blind signatures for new vouchers
        let (
            to_be_issued_blinded_signatures_shares_openings,
            to_be_issued_blinded_signatures_shares_requests,
        ) = prepare_vouchers_blind_sign(&coconut_params, &to_be_issued_vouchers);

        // prepare to be issued vouchers attributes
        let to_be_issued_serial_numbers: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.serial_number)
            .collect();

        let to_be_issued_infos: Vec<Attributes> = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.public_attributes())
            .collect();

        // prepare to be spent vouchers attributes and signatures
        let to_be_spent_serial_numbers: Attributes = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.voucher.serial_number)
            .collect();

        let to_be_spent_infos: Vec<Attributes> = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.voucher.public_attributes())
            .collect();

        let to_be_spent_signatures: Vec<Signature> = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.signature)
            .collect();

        // prepare proof
        let theta = randomise_and_request_vouchers(
            &coconut_params,
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

        // add new vouchers to to_be_issued_vouchers
        for to_be_issued_voucher in to_be_issued_vouchers {
            self.to_be_issued_vouchers.push(to_be_issued_voucher);
        }

        (
            ThetaRequestAndInfos {
                theta,
                to_be_issued_blinded_signatures_shares_requests,
                to_be_issued_infos,
                to_be_spent_infos,
            },
            to_be_issued_blinded_signatures_shares_openings,
        )
    }

    fn randomise_and_prove_to_be_spent_vouchers(
        &mut self,
        coconut_params: &Parameters,
        validator_verification_key: &VerificationKey,
        values: &[Attribute],
    ) -> ThetaSpendAndInfos {
        if !self.to_be_spent_vouchers.is_empty() {
            panic!("to_be_spent_vouchers must be empty");
        }

        if values.is_empty() {
            panic!("values must not be empty");
        }

        // find vouchers to be spent
        self.find(&values);

        if self.to_be_spent_vouchers.len() != values.len() {
            panic!("to_be_spent_vouchers must have same length as values");
        }

        // prepare to be issued vouchers attributes and sigantures
        let binding_number = self.to_be_spent_vouchers[0].voucher.binding_number;

        let serial_numbers: Attributes = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.voucher.serial_number)
            .collect();

        let infos: Attributes = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.voucher.info)
            .collect();

        let signatures: Vec<Signature> = self
            .to_be_spent_vouchers
            .iter()
            .map(|voucher_and_signature| voucher_and_signature.signature)
            .collect();

        // prepare proof
        let theta = randomise_and_spend_vouchers(
            coconut_params,
            validator_verification_key,
            &binding_number,
            &values,
            &serial_numbers,
            &signatures,
        )
        .unwrap();

        ThetaSpendAndInfos { theta, infos }
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
        let double_spending_tags = &self.theta.blinded_serial_numbers;
        // check double spending
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

impl ThetaRequestAndInfos {
    fn verify(
        &self,
        coconut_params: &Parameters,
        validator_key_pair: &KeyPair,
        range_proof_verification_key: &VerificationKey,
    ) -> Vec<BlindedSignatureShare> {
        // TODO
        // add double spending tag
        // add check gamma pay

        let infos: Attributes = self
            .to_be_spent_infos
            .iter()
            .map(|infos| infos[0])
            .collect();

        if !verify_request_vouchers(
            &coconut_params,
            &validator_key_pair.verification_key(),
            &self.theta,
            &infos,
        ) {
            panic!("could not verify the vouchers to be spent during request");
        }

        vouchers_blind_sign(
            &coconut_params,
            &self.to_be_issued_blinded_signatures_shares_requests,
            &self.to_be_issued_infos,
            &validator_key_pair,
        )
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
    validator_key_pair: &KeyPair,
) -> Vec<BlindedSignatureShare> {
    izip!(
        blinded_signatures_shares_requests.iter(),
        vouchers_public_attributes.iter()
    )
    .map(|(request, public_attributes)| {
        blind_sign(
            &params,
            &validator_key_pair.secret_key(),
            &request,
            &public_attributes,
        )
        .unwrap()
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
    use nymcoconut::{aggregate_verification_keys, issue_range_signatures, keygen, ttp_keygen};

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
        let blinded_signatures_shares_per_validator: Vec<BlindedSignatureShares> =
            validators_key_pairs
                .iter()
                .map(|validator_key_pair| {
                    vouchers_blind_sign(
                        &params.coconut_params,
                        &blinded_signatures_shares_requests,
                        &vouchers_public_attributes,
                        &validator_key_pair,
                    )
                })
                .collect();

        let blinded_signatures_shares = (0..blinded_signatures_shares_per_validator[0].len())
            .map(|blinded_signatures_shares_index| {
                blinded_signatures_shares_per_validator
                    .iter()
                    .map(|blinded_signatures_shares_of_one_validator| {
                        blinded_signatures_shares_of_one_validator[blinded_signatures_shares_index]
                            .clone()
                    })
                    .collect::<BlindedSignatureShares>()
            })
            .collect::<Vec<BlindedSignatureShares>>();

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
        let mut signed_vouchers_list = VouchersAndSignatures::new(&vouchers, &signatures);

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
            signed_vouchers_list.move_to_be_spent_vouchers_to_spent();
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
            signed_vouchers_list.move_to_be_spent_vouchers_to_spent();
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

        // validators
        // issue signatures for initial vouchers partial signatures
        let blinded_signatures_shares_per_validator: Vec<BlindedSignatureShares> =
            validators_key_pairs
                .iter()
                .map(|validator_key_pair| {
                    vouchers_blind_sign(
                        &params.coconut_params,
                        &blinded_signatures_shares_requests,
                        &vouchers_public_attributes,
                        &validator_key_pair,
                    )
                })
                .collect();

        // transpose shares signed by validators into all share for the same voucher
        let blinded_signatures_shares = (0..blinded_signatures_shares_per_validator[0].len())
            .map(|blinded_signatures_shares_index| {
                blinded_signatures_shares_per_validator
                    .iter()
                    .map(|blinded_signatures_shares_of_one_validator| {
                        blinded_signatures_shares_of_one_validator[blinded_signatures_shares_index]
                            .clone()
                    })
                    .collect::<BlindedSignatureShares>()
            })
            .collect::<Vec<BlindedSignatureShares>>();

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
        let mut signed_vouchers_list = VouchersAndSignatures::new(&vouchers, &signatures);

        // check we actually have 5 unspent vouchers
        assert!(
            signed_vouchers_list.unspent_vouchers.len() == 5
                && signed_vouchers_list.to_be_spent_vouchers.len() == 0
                && signed_vouchers_list.spent_vouchers.len() == 0
        );

        // define amount to pay and values to be issued/spent
        let pay = Scalar::from(5);
        let to_be_issued_values = [Scalar::from(3), Scalar::from(2)];
        let to_be_spent_values = [Scalar::from(10)];

        // generate proof pay and spend vouchers and request new vouchers
        let (proof_to_pay_5_and_request_3_and_2, to_be_issued_blinded_signatures_shares_openings) =
            signed_vouchers_list.randomise_and_prove_to_request_vouchers(
                &params.coconut_params,
                &validators_verification_key,
                &range_proof_verification_key,
                range_proof_base_u,
                range_proof_number_of_elements_l,
                &range_proof_signatures,
                &pay,
                &to_be_issued_values,
                &to_be_spent_values,
            );

        assert_eq!(
            proof_to_pay_5_and_request_3_and_2.theta.blinded_pay,
            params.coconut_params.gen2() * pay
        );

        // validators verify proof and issue signatures for new vouchers
        let blinded_signatures_shares_per_validator: Vec<BlindedSignatureShares> =
            validators_key_pairs
                .iter()
                .map(|validator_key_pair| {
                    proof_to_pay_5_and_request_3_and_2.verify(
                        &params.coconut_params,
                        &validator_key_pair,
                        &range_proof_verification_key,
                    )
                })
                .collect();

        // transpose shares signed by validators into all share for the same voucher
        let to_be_issued_blinded_signatures_shares = (0..blinded_signatures_shares_per_validator
            [0]
        .len())
            .map(|blinded_signatures_shares_index| {
                blinded_signatures_shares_per_validator
                    .iter()
                    .map(|blinded_signatures_shares_of_one_validator| {
                        blinded_signatures_shares_of_one_validator[blinded_signatures_shares_index]
                            .clone()
                    })
                    .collect::<BlindedSignatureShares>()
            })
            .collect::<Vec<BlindedSignatureShares>>();

        // user unblinds new vouchers signatures
        let to_be_issued_signatures_shares = unblind_vouchers_signatures_shares(
            &params.coconut_params,
            &to_be_issued_blinded_signatures_shares,
            &signed_vouchers_list.to_be_issued_vouchers,
            &to_be_issued_blinded_signatures_shares_openings,
            &proof_to_pay_5_and_request_3_and_2.to_be_issued_blinded_signatures_shares_requests,
            &validators_verification_keys,
        );

        // user aggregates new vouchers signatures
        let to_be_issued_signatures = aggregate_vouchers_signatures_shares(
            &params.coconut_params,
            &to_be_issued_signatures_shares,
            &signed_vouchers_list.to_be_issued_vouchers,
            &validators_verification_key,
        );

        // user mark vouchers as spent and add new ones
        signed_vouchers_list.move_to_be_spent_vouchers_to_spent();

        // check voucher is marked as spent
        assert_eq!(signed_vouchers_list.unspent_vouchers.len(), 4);
        assert_eq!(signed_vouchers_list.spent_vouchers.len(), 1);
        assert_eq!(signed_vouchers_list.to_be_spent_vouchers.len(), 0);
        assert_eq!(signed_vouchers_list.to_be_issued_vouchers.len(), 2);

        // user add new vouchers to her list of unspent voucher
        signed_vouchers_list.move_to_be_issued_vouchers_to_unspent(&to_be_issued_signatures);

        // check vouchers are added to unspent
        assert_eq!(signed_vouchers_list.unspent_vouchers.len(), 6);
        assert_eq!(signed_vouchers_list.spent_vouchers.len(), 1);
        assert_eq!(signed_vouchers_list.to_be_spent_vouchers.len(), 0);
        assert_eq!(signed_vouchers_list.to_be_issued_vouchers.len(), 0);
    }
}
