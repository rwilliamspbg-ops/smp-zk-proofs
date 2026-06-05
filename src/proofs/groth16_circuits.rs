//! R1CS circuits for arkworks/Groth16 integration (compiled under `groth16`).
#![cfg(feature = "groth16")]

use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// LocationR1CS enforces private x,y are within public bounds using UInt32
// comparison gadgets. The circuit intentionally does NOT check the
// coordinate_commitment yet; that will be added in Phase B with a
// Pedersen/Poseidon gadget.
#[derive(Clone)]
pub struct LocationR1CS {
    pub x: u32,
    pub y: u32,
    pub x_min: u32,
    pub x_max: u32,
    pub y_min: u32,
    pub y_max: u32,
}

impl ConstraintSynthesizer<Fr> for LocationR1CS {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.x)))?;
        let y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.y)))?;

        let x_min_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.x_min)))?;
        let x_max_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.x_max)))?;
        let y_min_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.y_min)))?;
        let y_max_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.y_max)))?;

        // Use comparison gadgets. `is_cmp` yields booleans which we combine to
        // allow equality (>= and <=).
        let gt_x_min = x_var.is_cmp(&x_min_var, core::cmp::Ordering::Greater, true)?;
        let eq_x_min = x_var.is_eq(&x_min_var)?;
        let ge_x_min = Boolean::or(&gt_x_min, &eq_x_min)?;
        ge_x_min.enforce_equal(&Boolean::TRUE)?;

        let lt_x_max = x_var.is_cmp(&x_max_var, core::cmp::Ordering::Less, true)?;
        let eq_x_max = x_var.is_eq(&x_max_var)?;
        let le_x_max = Boolean::or(&lt_x_max, &eq_x_max)?;
        le_x_max.enforce_equal(&Boolean::TRUE)?;

        let gt_y_min = y_var.is_cmp(&y_min_var, core::cmp::Ordering::Greater, true)?;
        let eq_y_min = y_var.is_eq(&y_min_var)?;
        let ge_y_min = Boolean::or(&gt_y_min, &eq_y_min)?;
        ge_y_min.enforce_equal(&Boolean::TRUE)?;

        let lt_y_max = y_var.is_cmp(&y_max_var, core::cmp::Ordering::Less, true)?;
        let eq_y_max = y_var.is_eq(&y_max_var)?;
        let le_y_max = Boolean::or(&lt_y_max, &eq_y_max)?;
        le_y_max.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
