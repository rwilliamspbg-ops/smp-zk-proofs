//! Integration tests for ZK proof backends

#[cfg(test)]
mod tests {
    use smp_zk_proofs::ZkProofError;
    use smp_zk_proofs::constraints::{Circuit, LocationCircuit, TrainingCircuit};
    use smp_zk_proofs::proofs::generator::{self, ProvingContext};
    use smp_zk_proofs::proofs::types::*;
    use smp_zk_proofs::proofs::verifier;

    fn create_location_witness() -> (LocationPublicInputs, LocationPrivateWitness) {
        let bounding_box = BoundingBox {
            x_min: 0,
            x_max: 1000,
            y_min: 0,
            y_max: 1000,
        };

        let private_witness = LocationPrivateWitness {
            x: 500,
            y: 500,
            blinding: [42u8; 32],
        };

        let public_inputs =
            LocationPublicInputs::from_witness(bounding_box, &private_witness).unwrap();

        (public_inputs, private_witness)
    }

    fn create_training_witness() -> (TrainingPublicInputs, TrainingPrivateWitness) {
        let base_model_digest = [1u8; 32];

        let private_witness = TrainingPrivateWitness {
            steps_completed: 1000,
            observed_loss_milli: 5000,
            weight_update_digest: [2u8; 32],
            blinding: [3u8; 32],
        };

        let public_inputs =
            TrainingPublicInputs::from_witness(1000, 10000, base_model_digest, &private_witness)
                .unwrap();

        (public_inputs, private_witness)
    }

    #[test]
    fn test_location_circuit_evaluation() {
        let (public_inputs, private_witness) = create_location_witness();
        let circuit = LocationCircuit;

        let report = circuit.evaluate(&public_inputs, &private_witness);
        assert!(
            report.is_ok(),
            "Location circuit should evaluate successfully"
        );

        let report = report.unwrap();
        assert_eq!(report.checks.len(), 3);
    }

    #[test]
    fn test_location_circuit_outside_bounds() {
        let (mut public_inputs, mut private_witness) = create_location_witness();

        // Move witness outside bounds
        private_witness.x = 1500;

        // Recommit with new coordinates
        public_inputs.coordinate_commitment = smp_zk_proofs::utils::location_commitment(
            private_witness.x,
            private_witness.y,
            &private_witness.blinding,
        )
        .unwrap();

        let circuit = LocationCircuit;
        let result = circuit.evaluate(&public_inputs, &private_witness);

        assert!(result.is_err());
        match result.unwrap_err() {
            ZkProofError::ConstraintUnsatisfied(msg) => {
                assert!(msg.contains("outside the declared bounding box"));
            }
            _ => panic!("Expected ConstraintUnsatisfied error"),
        }
    }

    #[test]
    fn test_training_circuit_evaluation() {
        let (public_inputs, private_witness) = create_training_witness();
        let circuit = TrainingCircuit;

        let report = circuit.evaluate(&public_inputs, &private_witness);
        assert!(
            report.is_ok(),
            "Training circuit should evaluate successfully"
        );
    }

    #[test]
    fn test_training_circuit_exceeded_steps() {
        let (public_inputs, mut private_witness) = create_training_witness();

        // Exceed expected steps
        private_witness.steps_completed = 1500;

        let circuit = TrainingCircuit;
        let result = circuit.evaluate(&public_inputs, &private_witness);

        assert!(result.is_err());
        match result.unwrap_err() {
            ZkProofError::ConstraintUnsatisfied(msg) => {
                assert!(msg.contains("training step count does not match"));
            }
            _ => panic!("Expected ConstraintUnsatisfied error"),
        }
    }

    #[test]
    fn test_proof_generation_and_verification_development() {
        let (public_inputs, private_witness) = create_location_witness();
        let context = ProvingContext::from_seed([7u8; 32]);

        // Generate proof
        let proof = generator::prove_location(&context, &public_inputs, &private_witness);

        assert!(proof.is_ok(), "Proof generation should succeed");
        let proof = proof.unwrap();

        // Verify proof
        let vk = context.verification_key();
        let result = verifier::verify_location_proof(&vk, &public_inputs, &proof);
        assert!(result.is_ok(), "Proof verification should succeed");
    }

    #[test]
    #[cfg(feature = "groth16")]
    fn test_groth16_location_proof() {
        use smp_zk_proofs::proofs::groth16_backend;

        let (public_inputs, private_witness) = create_location_witness();

        // Generate Groth16 proof
        let proof_bytes = groth16_backend::prove_location_groth16(&public_inputs, &private_witness);

        assert!(
            proof_bytes.is_ok(),
            "Groth16 proof generation should succeed"
        );
        let proof_bytes = proof_bytes.unwrap();
        assert!(proof_bytes.len() > 0);

        // Verify Groth16 proof
        let result = groth16_backend::verify_location_groth16(&[], &public_inputs, &proof_bytes);

        assert!(result.is_ok(), "Groth16 proof verification should succeed");
    }

    #[test]
    #[cfg(feature = "halo2")]
    fn test_halo2_location_proof() {
        use smp_zk_proofs::proofs::halo2_backend;

        let (public_inputs, private_witness) = create_location_witness();

        // Generate Halo2 proof
        let proof_bytes = halo2_backend::prove_location_halo2(&public_inputs, &private_witness);

        assert!(proof_bytes.is_ok(), "Halo2 proof generation should succeed");
        let proof_bytes = proof_bytes.unwrap();

        // Verify Halo2 proof
        let result = halo2_backend::verify_location_halo2(&[], &public_inputs, &proof_bytes);

        assert!(result.is_ok(), "Halo2 proof verification should succeed");
    }

    #[test]
    fn test_bounding_box_validation() {
        // Valid bounding box
        let bbox = BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 100,
        };
        assert!(bbox.validate().is_ok());
        assert!(bbox.contains(50, 50));
        assert!(!bbox.contains(150, 50));

        // Invalid bounding box (x_min > x_max)
        let invalid_bbox = BoundingBox {
            x_min: 100,
            x_max: 0,
            y_min: 0,
            y_max: 100,
        };
        assert!(invalid_bbox.validate().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (public_inputs, _) = create_location_witness();

        // Serialize
        let bytes = public_inputs.to_bytes().unwrap();

        // Deserialize
        let recovered = LocationPublicInputs::from_bytes(&bytes).unwrap();

        assert_eq!(public_inputs, recovered);
    }
}
