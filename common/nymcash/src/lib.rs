use bls12_381::Scalar;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main() -> Result<(), CoconutError> {
        // define e-cash parameters
        let num_attributes = Voucher::number_of_attributes();
        let pay_max = Scalar::from(10);
        let voucher_max = Scalar::from(10);

        let params = ECashParams::new(num_attributes, pay_max, voucher_max)?;

        Ok(())
    }
}
