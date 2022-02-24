use criterion::{criterion_group, criterion_main, Criterion};

use bls12_381::{G2Projective, Scalar};
use group::Curve;
use itertools::izip;
use nymcash::{BlindedSignatureShares, BulletinBoard, ECashParams, Voucher, VouchersAndSignatures};
use nymcoconut::{
    aggregate_signature_shares, aggregate_verification_keys, hash_g1, issue_range_signatures,
    keygen, randomise_and_request_vouchers, randomise_and_spend_vouchers, scalar_to_u64,
    ttp_keygen, verify_request_vouchers, verify_spent_vouchers, BlindedSignature, KeyPair,
    Parameters, RangeProofSignatures, Signature, SignatureShare, ThetaRequestPhase,
    ThetaSpendPhase, VerificationKey,
};

pub fn bench_e2e_e_cash(c: &mut Criterion) {
    let mut c = c.benchmark_group("sample_size");
    c.sample_size(10);

    // define e-cash parameters
    let num_attributes = Voucher::number_of_attributes();
    let pay_max = Scalar::from(1000);

    let range_proof_base_u: u8 = 2;
    let range_proof_number_of_elements_l: u8 = 10;

    let voucher_max =
        Scalar::from((range_proof_base_u as u64).pow(range_proof_number_of_elements_l as u32));

    let params = ECashParams::new(num_attributes, pay_max, voucher_max);

    // generate validators keypairs
    let number_of_validators = 10;
    let threshold_of_validators = 7;
    let validators_key_pairs = ttp_keygen(
        &params.coconut_params,
        threshold_of_validators as u64,
        number_of_validators as u64,
    )
    .unwrap();
    let validators_verification_keys: Vec<VerificationKey> = validators_key_pairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();
    let validators_verification_key = aggregate_verification_keys(
        &validators_verification_keys,
        Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    )
    .unwrap();

    // generate range proof signatures
    let range_proof_keypair = keygen(&params.coconut_params);
    let range_proof_verification_key = range_proof_keypair.verification_key();
    let range_proof_secret_key = range_proof_keypair.secret_key();
    let range_proof_h = params.coconut_params.gen1() * params.coconut_params.random_scalar();

    let range_proof_signatures = issue_range_signatures(
        &range_proof_h,
        &range_proof_secret_key,
        range_proof_base_u as usize,
    );

    let binding_number = params.coconut_params.random_scalar();

    for i in 1..=10 {
        println!("Request {} 0", i);

        let number_of_to_be_issued_vouchers = i as u8;
        let number_of_to_be_spent_vouchers = 0 as u8;

        let mut to_be_issued_values = vec![];
        for j in 0..i {
            to_be_issued_values.push(Scalar::from(10));
        }
        let to_be_issued_serial_numbers = params.coconut_params.n_random_scalars(i);

        let to_be_spent_values = [];
        let to_be_spent_signatures = [];

        c.bench_function(format!("Proof {} 0", i), |b| {
            b.iter(|| {
                randomise_and_request_vouchers(
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
                    &to_be_spent_signatures,
                )
            });
        });

        let (theta, _) = randomise_and_request_vouchers(
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
            &to_be_spent_signatures,
        )
        .unwrap();

        println!("theta length {} bytes", theta.to_bytes().len());

        let serial_numbers = [];
        let infos = [];

        c.bench_function(format!("Verification {} 0", i), |b| {
            b.iter(|| {
                verify_request_vouchers(
                    &params.coconut_params,
                    &validators_verification_key,
                    &range_proof_verification_key,
                    &theta,
                    &serial_numbers,
                    &infos,
                )
            });
        });
    }

    for i in 1..=10 {
        println!("Request 1 {}", i);

        let number_of_to_be_issued_vouchers = 1 as u8;
        let number_of_to_be_spent_vouchers = i as u8;

        let mut to_be_issued_values = vec![Scalar::from(i * 10)];
        let to_be_issued_serial_numbers = params.coconut_params.n_random_scalars(1);

        let mut to_be_spent_values = vec![];
        for j in 0..i {
            to_be_spent_values.push(Scalar::from(10));
        }
        let mut to_be_spent_signatures = vec![];
        to_be_spent_signatures.push(Signature(
            params.coconut_params.gen1() * params.coconut_params.random_scalar(),
            params.coconut_params.gen1() * params.coconut_params.random_scalar(),
        ));

        c.bench_function(format!("Proof 1 {}", i), |b| {
            b.iter(|| {
                randomise_and_request_vouchers(
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
                    &to_be_spent_signatures,
                )
            });
        });

        let (theta, _) = randomise_and_request_vouchers(
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
            &to_be_spent_signatures,
        )
        .unwrap();

        println!("theta length {} bytes", theta.to_bytes().len());

        let serial_numbers = params.coconut_params.n_random_scalars(i as usize);
        let infos = params.coconut_params.n_random_scalars(i as usize);

        c.bench_function(format!("Verification 1 {}", i as usize), |b| {
            b.iter(|| {
                verify_request_vouchers(
                    &params.coconut_params,
                    &validators_verification_key,
                    &range_proof_verification_key,
                    &theta,
                    &serial_numbers,
                    &infos,
                )
            });
        });
    }

    for i in 1..=10 {
        println!("Spend {}", i);

        let mut values = vec![];
        for j in 0..i {
            values.push(Scalar::from(10));
        }
        let mut signatures = vec![];
        for j in 0..i {
            signatures.push(Signature(
                params.coconut_params.gen1() * params.coconut_params.random_scalar(),
                params.coconut_params.gen1() * params.coconut_params.random_scalar(),
            ));
        }

        c.bench_function(format!("Proof {}", i), |b| {
            b.iter(|| {
                randomise_and_spend_vouchers(
                    &params.coconut_params,
                    &validators_verification_key,
                    &binding_number,
                    &values,
                    &signatures,
                )
            });
        });

        let theta = randomise_and_spend_vouchers(
            &params.coconut_params,
            &validators_verification_key,
            &binding_number,
            &values,
            &signatures,
        )
        .unwrap();

        println!("theta length {} bytes", theta.to_bytes().len());

        let serial_numbers = params.coconut_params.n_random_scalars(i as usize);
        let infos = params.coconut_params.n_random_scalars(i as usize);

        c.bench_function(format!("Verification {}", i as usize), |b| {
            b.iter(|| {
                verify_spent_vouchers(
                    &params.coconut_params,
                    &validators_verification_key,
                    &theta,
                    &serial_numbers,
                    &infos,
                )
            });
        });
    }

    c.finish();
}

criterion_group!(benches_e2e, bench_e2e_e_cash);
criterion_main!(benches_e2e);
