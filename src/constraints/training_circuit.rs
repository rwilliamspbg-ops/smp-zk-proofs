use crate::{
    ZkProofError,
    constraints::{Circuit, ConstraintReport},
    proofs::types::{CircuitKind, TrainingPrivateWitness, TrainingPublicInputs},
    utils,
};

#[derive(Debug, Default, Clone, Copy)]
/// Circuit that checks a private training witness satisfies step-count and loss bounds.
pub struct TrainingCircuit;

impl Circuit for TrainingCircuit {
    type PublicInputs = TrainingPublicInputs;
    type PrivateWitness = TrainingPrivateWitness;

    fn kind(&self) -> CircuitKind {
        CircuitKind::Training
    }

    fn evaluate(
        &self,
        public_inputs: &Self::PublicInputs,
        private_witness: &Self::PrivateWitness,
    ) -> Result<ConstraintReport, ZkProofError> {
        if public_inputs.expected_steps == 0 {
            return Err(ZkProofError::InvalidPublicInputs(
                "expected training steps must be greater than zero".to_owned(),
            ));
        }

        let expected_commitment = utils::training_commitment(
            public_inputs.base_model_digest,
            private_witness.weight_update_digest,
            &private_witness.blinding,
        )?;
        if expected_commitment != public_inputs.update_commitment {
            return Err(ZkProofError::ConstraintUnsatisfied(
                "weight update commitment does not match the private witness".to_owned(),
            ));
        }

        if private_witness.steps_completed != public_inputs.expected_steps {
            return Err(ZkProofError::ConstraintUnsatisfied(
                "training step count does not match the public statement".to_owned(),
            ));
        }

        if private_witness.observed_loss_milli > public_inputs.max_loss_milli {
            return Err(ZkProofError::ConstraintUnsatisfied(
                "observed training loss exceeds the public threshold".to_owned(),
            ));
        }

        Ok(ConstraintReport {
            circuit: self.kind(),
            checks: vec![
                "matched weight update commitment to witness".to_owned(),
                "verified exact local step count".to_owned(),
                "verified loss threshold remained below the declared bound".to_owned(),
            ],
        })
    }
}
