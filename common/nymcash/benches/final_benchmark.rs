use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bls12_381::Scalar;
use nymcash::{
    aggregate_vouchers_signatures_shares, transpose_shares_per_validators_into_shares_per_vouchers,
    unblind_vouchers_signatures_shares, Attributes, ECashParams, ThetaRequestAndInfos,
    ThetaSpendAndInfos, Voucher,
};
use nymcoconut::{
    aggregate_verification_keys, issue_range_signatures, keygen, randomise_and_request_vouchers,
    randomise_and_spend_vouchers, ttp_keygen, verify_request_vouchers, verify_spent_vouchers,
    VerificationKey,
};

pub fn bench_e2e_e_cash(c: &mut Criterion) {
    let mut c = c.benchmark_group("sample_size");
    c.sample_size(10);
    c.measurement_time(Duration::from_secs(25));

    // define e-cash parameters
    let num_attributes = Voucher::number_of_attributes();
    let pay_max = Scalar::from(1000);

    let range_proof_base_u: u8 = 2;
    let range_proof_number_of_elements_l: u8 = 10;

    let voucher_max =
        Scalar::from((range_proof_base_u as u64).pow(range_proof_number_of_elements_l as u32));

    let params = ECashParams::new(num_attributes, pay_max, voucher_max);
    let coconut_params = &params.coconut_params;

    // generate validators keypairs
    let number_of_validators = 10;
    let threshold_of_validators = 7;
    let validators_key_pairs = ttp_keygen(
        &coconut_params,
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
    let range_proof_keypair = keygen(&coconut_params);
    let range_proof_verification_key = range_proof_keypair.verification_key();
    let range_proof_secret_key = range_proof_keypair.secret_key();
    let range_proof_h = coconut_params.gen1() * coconut_params.random_scalar();

    let range_proof_signatures = issue_range_signatures(
        &range_proof_h,
        &range_proof_secret_key,
        range_proof_base_u as usize,
    );

    for iteration in 1..=10 {
        let number_of_to_be_issued_vouchers = iteration;
        let number_of_to_be_spent_vouchers = 0;

        // create vouchers to be issued
        let binding_number = coconut_params.random_scalar();

        let mut to_be_issued_values = vec![];
        for _ in 0..number_of_to_be_issued_vouchers {
            to_be_issued_values.push(Scalar::from(10))
        }

        let to_be_issued_vouchers =
            Voucher::new_many(&coconut_params, &binding_number, &to_be_issued_values);
        let to_be_issued_serial_numbers: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.serial_number)
            .collect();
        let to_be_issued_infos: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.info)
            .collect();

        let to_be_spent_values = vec![];
        let to_be_spent_serial_numbers = vec![];
        let to_be_spent_infos = vec![];
        let to_be_spent_signatures = vec![];

        // benchmark request varying issued vouchers
        c.bench_function(
            &format!(
                "[Client] prepare request, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    randomise_and_request_vouchers(
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
                        &to_be_spent_signatures,
                    )
                    .unwrap()
                })
            },
        );

        let (
            theta,
            (
                to_be_issued_binding_numbers_openings,
                to_be_issued_values_openings,
                to_be_issued_serial_numbers_openings,
            ),
        ) = randomise_and_request_vouchers(
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
            &to_be_spent_signatures,
        )
        .unwrap();

        let theta_request = ThetaRequestAndInfos {
            theta,
            to_be_issued_infos,
            to_be_spent_serial_numbers,
            to_be_spent_infos,
        };

        // communication cost from client to authority for request
        // one attribute is 32 bytes long
        println!(
            "request communication cost, issued: {} spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            theta_request.theta.to_bytes().len()
                + number_of_to_be_issued_vouchers as usize * 32
                + 2 * number_of_to_be_spent_vouchers as usize * 32
        );

        // benchmark issuance varying issued vouchers
        c.bench_function(
            &format!(
                "[Validator] verify request and blind sign, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    assert!(verify_request_vouchers(
                        &coconut_params,
                        &validators_verification_key,
                        &range_proof_verification_key,
                        &theta_request.theta,
                        &theta_request.to_be_spent_serial_numbers,
                        &theta_request.to_be_spent_infos,
                    ));
                    theta_request.vouchers_blind_sign(&validators_key_pairs[0])
                })
            },
        );

        // communication cost from authority to client for blind signatures
        // one blind signature is 96 bytes long
        println!(
            "issuance communication cost, issued: {} spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            number_of_to_be_issued_vouchers * 96
        );

        let blinded_signatures_shares_per_validator = validators_key_pairs
            .iter()
            .map(|validator_key_pair| theta_request.vouchers_blind_sign(&validator_key_pair))
            .collect::<Vec<_>>();

        // benchmark unblind and aggregate varying issued vouchers
        c.bench_function(
            &format!(
                "[Client] unblind and aggregate, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    let blinded_signatures_shares =
                        transpose_shares_per_validators_into_shares_per_vouchers(
                            &blinded_signatures_shares_per_validator[..threshold_of_validators],
                        );

                    let signatures_shares = unblind_vouchers_signatures_shares(
                        &blinded_signatures_shares,
                        &to_be_issued_binding_numbers_openings,
                        &to_be_issued_values_openings,
                        &to_be_issued_serial_numbers_openings,
                        &validators_verification_keys,
                    );

                    aggregate_vouchers_signatures_shares(
                        &coconut_params,
                        &signatures_shares,
                        &to_be_issued_vouchers,
                        &validators_verification_key,
                    )
                })
            },
        );

        let blinded_signatures_shares = transpose_shares_per_validators_into_shares_per_vouchers(
            &blinded_signatures_shares_per_validator[..threshold_of_validators],
        );

        let signatures_shares = unblind_vouchers_signatures_shares(
            &blinded_signatures_shares,
            &to_be_issued_binding_numbers_openings,
            &to_be_issued_values_openings,
            &to_be_issued_serial_numbers_openings,
            &validators_verification_keys,
        );

        let signatures = aggregate_vouchers_signatures_shares(
            &coconut_params,
            &signatures_shares,
            &to_be_issued_vouchers,
            &validators_verification_key,
        );

        // use the previously issued vouchers to benchmark
        // - request protocol with vouchers to be spent
        // - spend protocol
        let number_of_to_be_spent_vouchers = number_of_to_be_issued_vouchers;

        let to_be_spent_values = to_be_issued_values;
        let to_be_spent_serial_numbers = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.serial_number)
            .collect();
        let to_be_spent_infos = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.info)
            .collect();
        let to_be_spent_signatures = signatures;

        // exchange n vouchers of 10 against one voucher of n * 10
        let number_of_to_be_issued_vouchers = 1;
        let to_be_issued_values = vec![Scalar::from(number_of_to_be_spent_vouchers as u64 * 10)];
        let to_be_issued_vouchers =
            Voucher::new_many(&coconut_params, &binding_number, &to_be_issued_values);
        let to_be_issued_serial_numbers: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.serial_number)
            .collect();
        let to_be_issued_infos: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.info)
            .collect();

        // benchmark request varying spent vouchers
        c.bench_function(
            &format!(
                "[Client] prepare request, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
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
                    .unwrap()
                })
            },
        );

        let (
            theta,
            (
                to_be_issued_binding_numbers_openings,
                to_be_issued_values_openings,
                to_be_issued_serial_numbers_openings,
            ),
        ) = randomise_and_request_vouchers(
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
            &to_be_spent_signatures,
        )
        .unwrap();

        let theta_request = ThetaRequestAndInfos {
            theta,
            to_be_issued_infos,
            to_be_spent_serial_numbers,
            to_be_spent_infos,
        };

        // communication cost from client to authority for request
        // one attribute is 32 bytes long
        println!(
            "request communication cost, issued: {} spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            theta_request.theta.to_bytes().len()
                + number_of_to_be_issued_vouchers as usize * 32
                + 2 * number_of_to_be_spent_vouchers as usize * 32
        );

        // benchmark issuance varying spent vouchers
        c.bench_function(
            &format!(
                "[Validator] verify request and blind sign, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    assert!(verify_request_vouchers(
                        &coconut_params,
                        &validators_verification_key,
                        &range_proof_verification_key,
                        &theta_request.theta,
                        &theta_request.to_be_spent_serial_numbers,
                        &theta_request.to_be_spent_infos,
                    ));
                    theta_request.vouchers_blind_sign(&validators_key_pairs[0])
                })
            },
        );

        // communication cost from authority to client for blind signatures
        // one blind signature is 96 bytes long
        println!(
            "issuance communication cost, issued: {} spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            number_of_to_be_issued_vouchers * 96
        );

        let blinded_signatures_shares_per_validator = validators_key_pairs
            .iter()
            .map(|validator_key_pair| theta_request.vouchers_blind_sign(&validator_key_pair))
            .collect::<Vec<_>>();

        // benchmark unblind and aggregate varying spent vouchers
        c.bench_function(
            &format!(
                "[Client] unblind and aggregate, issued: {} spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    let blinded_signatures_shares =
                        transpose_shares_per_validators_into_shares_per_vouchers(
                            &blinded_signatures_shares_per_validator[..threshold_of_validators],
                        );

                    let signatures_shares = unblind_vouchers_signatures_shares(
                        &blinded_signatures_shares,
                        &to_be_issued_binding_numbers_openings,
                        &to_be_issued_values_openings,
                        &to_be_issued_serial_numbers_openings,
                        &validators_verification_keys,
                    );

                    aggregate_vouchers_signatures_shares(
                        &coconut_params,
                        &signatures_shares,
                        &to_be_issued_vouchers,
                        &validators_verification_key,
                    )
                })
            },
        );

        let to_be_spent_serial_numbers = theta_request
            .to_be_spent_serial_numbers
            .iter()
            .map(|sn| sn.clone())
            .collect();
        let to_be_spent_infos = theta_request
            .to_be_spent_infos
            .iter()
            .map(|i| i.clone())
            .collect();

        // exchange n vouchers of 10 against n voucher of 10
        let number_of_to_be_issued_vouchers = number_of_to_be_spent_vouchers;
        let mut to_be_issued_values = vec![];
        for _ in 0..number_of_to_be_issued_vouchers {
            to_be_issued_values.push(Scalar::from(10));
        }
        let to_be_issued_vouchers =
            Voucher::new_many(&coconut_params, &binding_number, &to_be_issued_values);
        let to_be_issued_serial_numbers: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.serial_number)
            .collect();
        let to_be_issued_infos: Attributes = to_be_issued_vouchers
            .iter()
            .map(|voucher| voucher.info)
            .collect();

        // benchmark request varying issued and spent vouchers
        c.bench_function(
            &format!(
                "[Client] prepare request, issued: {} = spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
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
                    .unwrap()
                })
            },
        );

        let (
            theta,
            (
                to_be_issued_binding_numbers_openings,
                to_be_issued_values_openings,
                to_be_issued_serial_numbers_openings,
            ),
        ) = randomise_and_request_vouchers(
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
            &to_be_spent_signatures,
        )
        .unwrap();

        let theta_request = ThetaRequestAndInfos {
            theta,
            to_be_issued_infos,
            to_be_spent_serial_numbers,
            to_be_spent_infos,
        };

        // communication cost from client to authority for request
        // one attribute is 32 bytes long
        println!(
            "request communication cost, issued: {} = spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            theta_request.theta.to_bytes().len()
                + number_of_to_be_issued_vouchers as usize * 32
                + 2 * number_of_to_be_spent_vouchers as usize * 32
        );

        // benchmark issuance varying spent vouchers
        c.bench_function(
            &format!(
                "[Validator] verify request and blind sign, issued: {} = spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    assert!(verify_request_vouchers(
                        &coconut_params,
                        &validators_verification_key,
                        &range_proof_verification_key,
                        &theta_request.theta,
                        &theta_request.to_be_spent_serial_numbers,
                        &theta_request.to_be_spent_infos,
                    ));
                    theta_request.vouchers_blind_sign(&validators_key_pairs[0])
                })
            },
        );

        // communication cost from authority to client for blind signatures
        // one blind signature is 96 bytes long
        println!(
            "issuance communication cost, issued: {} = spent: {}, {} bytes",
            number_of_to_be_issued_vouchers,
            number_of_to_be_spent_vouchers,
            number_of_to_be_issued_vouchers * 96
        );

        let blinded_signatures_shares_per_validator = validators_key_pairs
            .iter()
            .map(|validator_key_pair| theta_request.vouchers_blind_sign(&validator_key_pair))
            .collect::<Vec<_>>();

        // benchmark unblind and aggregate varying spent vouchers
        c.bench_function(
            &format!(
                "[Client] unblind and aggregate, issued: {} = spent: {}",
                number_of_to_be_issued_vouchers, number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    let blinded_signatures_shares =
                        transpose_shares_per_validators_into_shares_per_vouchers(
                            &blinded_signatures_shares_per_validator[..threshold_of_validators],
                        );

                    let signatures_shares = unblind_vouchers_signatures_shares(
                        &blinded_signatures_shares,
                        &to_be_issued_binding_numbers_openings,
                        &to_be_issued_values_openings,
                        &to_be_issued_serial_numbers_openings,
                        &validators_verification_keys,
                    );

                    aggregate_vouchers_signatures_shares(
                        &coconut_params,
                        &signatures_shares,
                        &to_be_issued_vouchers,
                        &validators_verification_key,
                    )
                })
            },
        );

        // we don't need to used the issued voucher because we reuse the ones spent
        // when benchmarking the request protocol
        //
        // let blinded_signatures_shares = transpose_shares_per_validators_into_shares_per_vouchers(
        //     &blinded_signatures_shares_per_validator[..threshold_of_validators],
        // );

        // let signatures_shares = unblind_vouchers_signatures_shares(
        //     &blinded_signatures_shares,
        //     &to_be_issued_binding_numbers_openings,
        //     &to_be_issued_values_openings,
        //     &to_be_issued_serial_numbers_openings,
        //     &validators_verification_keys,
        // );

        // let signatures = aggregate_vouchers_signatures_shares(
        //     &coconut_params,
        //     &signatures_shares,
        //     &to_be_issued_vouchers,
        //     &validators_verification_key,
        // );

        let values = to_be_spent_values;

        let serial_numbers = theta_request
            .to_be_spent_serial_numbers
            .iter()
            .map(|sn| sn.clone())
            .collect();
        let infos = theta_request
            .to_be_spent_infos
            .iter()
            .map(|i| i.clone())
            .collect();
        let signatures = to_be_spent_signatures;

        // benchmark spend varying spent vouchers
        c.bench_function(
            &format!(
                "[Client] prepare spend, spent: {}",
                number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    randomise_and_spend_vouchers(
                        &coconut_params,
                        &validators_verification_key,
                        &binding_number,
                        &values,
                        &signatures,
                    )
                    .unwrap()
                })
            },
        );

        let theta = randomise_and_spend_vouchers(
            &coconut_params,
            &validators_verification_key,
            &binding_number,
            &values,
            &signatures,
        )
        .unwrap();

        let theta_spend = ThetaSpendAndInfos {
            theta,
            serial_numbers,
            infos,
        };

        // communication cost from client to authority for spend
        // one attribute is 32 bytes long
        println!(
            "spend communication cost, spent: {}, {} bytes",
            number_of_to_be_spent_vouchers,
            theta_spend.theta.to_bytes().len() + 2 * number_of_to_be_spent_vouchers as usize * 32
        );

        // benchmark spend verification varying spent vouchers
        c.bench_function(
            &format!(
                "[Validator] verify spend, spent: {}",
                number_of_to_be_spent_vouchers,
            ),
            |b| {
                b.iter(|| {
                    assert!(verify_spent_vouchers(
                        &coconut_params,
                        &validators_verification_key,
                        &theta_spend.theta,
                        &theta_spend.serial_numbers,
                        &theta_spend.infos,
                    ))
                })
            },
        );
    }

    c.finish();
}

criterion_group!(benches_e2e, bench_e2e_e_cash);
criterion_main!(benches_e2e);
