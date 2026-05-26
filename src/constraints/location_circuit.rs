use crate::{
    ZkProofError,
    constraints::{Circuit, ConstraintReport},
    proofs::types::{CircuitKind, LocationPrivateWitness, LocationPublicInputs},
    utils,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct LocationCircuit;

impl Circuit for LocationCircuit {
    type PublicInputs = LocationPublicInputs;
    type PrivateWitness = LocationPrivateWitness;

    fn kind(&self) -> CircuitKind {
        CircuitKind::Location
    }

    fn evaluate(
        &self,
        public_inputs: &Self::PublicInputs,
        private_witness: &Self::PrivateWitness,
    ) -> Result<ConstraintReport, ZkProofError> {
        public_inputs.bounding_box.validate()?;

        let expected_commitment = utils::location_commitment(
            private_witness.x,
            private_witness.y,
            &private_witness.blinding,
        )?;
        if expected_commitment != public_inputs.coordinate_commitment {
            return Err(ZkProofError::ConstraintUnsatisfied(
                "coordinate commitment does not match the private witness".to_owned(),
            ));
        }

        if !public_inputs
            .bounding_box
            .contains(private_witness.x, private_witness.y)
        {
            return Err(ZkProofError::ConstraintUnsatisfied(
                "coordinate witness is outside the declared bounding box".to_owned(),
            ));
        }

        Ok(ConstraintReport {
            circuit: self.kind(),
            checks: vec![
                "validated public bounding box shape".to_owned(),
                "matched coordinate commitment to witness".to_owned(),
                "proved witness is within the public bounding box".to_owned(),
            ],
        })
    }
}
