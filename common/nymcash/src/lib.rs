use bls12_381::{G1Projective, Scalar};
use nymcoconut::{CoconutError, Parameters};

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

    // pub fn commit(&self, coconut_params: &Parameters, opening: Scalar) -> G1Projective {
    //     let g1 = coconut_params.gen1();
    //     let hs = coconut_params.gen_hs();

    //     g1 * opening + hs[0] * self.binding_number + hs[1] * self.value + hs[2] * self.serial_number
    // }

    // pub fn commit_attributes(
    //     &self,
    //     coconut_params: &Parameters,
    //     openings: &[Scalar; 3],
    //     h_m: G1Projective,
    // ) -> Vec<G1Projective> {
    //     let mut commitments = Vec::new();
    //     let g1 = coconut_params.gen1();

    //     commitments.push(g1 * openings[0] + h_m * self.binding_number);
    //     commitments.push(g1 * openings[1] + h_m * self.value);
    //     commitments.push(g1 * openings[2] + h_m * self.serial_number);

    //     commitments
    // }

    pub fn private_attributes(self) -> Vec<Scalar> {
        vec![self.binding_number, self.value, self.serial_number]
    }

    pub fn public_attributes(self) -> Vec<Scalar> {
        vec![self.info]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective;
    use group::{Curve, GroupEncoding};
    use nymcoconut::{hash_g1, prepare_blind_sign, ttp_keygen, VerificationKey};

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

        let vouchers_openings = params.coconut_params.n_random_scalars(NUMBER_OF_VOUCHERS);
        let vouchers_commitments = vouchers
            .iter()
            .zip(vouchers_openings.iter())
            .map(|(v, o)| v.commit(&params.coconut_params, *o))
            .collect::<Vec<G1Projective>>();

        let blinded_signatures_requests = vouchers
            .iter()
            .zip(vouchers_openings.iter())
            .map(|(v, o)| {
                prepare_blind_sign(
                    &params.coconut_params,
                    &v.private_attributes(),
                    o,
                    &v.private_attributes(),
                )
            })
            .collect();

        // // derive h_m
        // let vouchers_commitments_bytes = vouchers_commitments
        //     .iter()
        //     .map(|c| c.to_affine().to_compressed())
        //     .flatten()
        //     .collect::<Vec<u8>>();
        // let h_m = hash_g1(vouchers_commitments_bytes);

        // // commit to each attribute of each voucher
        // let vouchers_attributes_openings = vouchers
        //     .iter()
        //     .map(|_| {
        //         params
        //             .coconut_params
        //             .n_random_scalars(3)
        //             .try_into()
        //             .unwrap()
        //     })
        //     .collect::<Vec<[Scalar; 3]>>();
        // let vouchers_attributes_commitments = vouchers
        //     .iter()
        //     .zip(vouchers_attributes_openings.iter())
        //     .map(|(v, o)| v.commit_attributes(&params.coconut_params, o, h_m))
        //     .collect::<Vec<Vec<G1Projective>>>();

        // let private_attributes =
        // let blind_sign_request = prepare_blind_sign(
        //     &params,
        //     &private_attributes,
        //     &commitments_openings,
        //     &public_attributes,
        // )?;

        // // generate blinded signatures
        // let mut blinded_signatures = Vec::new();
        // for keypair in coconut_keypairs {
        //     let blinded_signature = blind_sign(
        //         &params.coconut_params,
        //         &keypair.secret_key(),
        //         &blind_sign_request,
        //         &public_attributes,
        //     )?;
        //     blinded_signatures.push(blinded_signature)
        // }

        Ok(())
    }
}
