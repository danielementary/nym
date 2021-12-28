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

    pub fn commit(&self, coconut_params: &Parameters, opening: Scalar) -> G1Projective {
        let g1 = coconut_params.gen1();
        let hs = coconut_params.gen_hs();

        g1 * opening + hs[0] * self.binding_number + hs[1] * self.value + hs[2] * self.serial_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective;
    use group::Curve;
    use nymcoconut::{ttp_keygen, VerificationKey};

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

        // commit on each voucher values
        let vouchers_openings = params.coconut_params.n_random_scalars(NUMBER_OF_VOUCHERS);
        let vouchers_commitments = vouchers
            .iter()
            .zip(vouchers_openings.iter())
            .map(|(v, o)| v.commit(&params.coconut_params, *o))
            .collect::<Vec<G1Projective>>();

        // derive h_m
        let vouchers_commitments_bytes = vouchers_commitments
            .iter()
            .map(|c| c.to_affine().to_compressed())
            .collect::<Vec<_>>();

        let h_m = hash_g1(std::iter::chain(
            vouchers_commitments_bytes.iter().map(|b| b.as_ref()),
        ));

        Ok(())
    }
}
