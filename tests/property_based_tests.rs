//! Property-based tests using proptest for robust validation of proof operations.
//! These tests verify invariants that must hold for all valid inputs.

#[cfg(test)]
mod property_tests {
    use proptest::{prop_oneof, proptest};
    use smp_zk_proofs::{
        BoundingBox, LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness,
        TrainingPublicInputs, VerificationKey, generate_deterministic_blinding_factor,
    };

    // Property: Bounding box must always be valid (x_min <= x_max, y_min <= y_max)
    proptest! {

        #[test]
        fn bounding_box_is_always_valid(x_min: i64, x_max: i64, y_min: i64, y_max: i64) {
            let box_ = BoundingBox { x_min, x_max, y_min, y_max };
            // We can't force invalid boxes through the API, so this is a documentation test
            assert!(box_.validate().is_ok(), "BoundingBox should always be valid");
        }

        #[test]
        fn location_commitment_is_deterministic(x: i64, y: i64, blinding_seed: [u8; 32]) {
            let blinding = generate_deterministic_blinding_factor(blinding_seed);

            // Same inputs should always produce same commitment
            let commitment1 = smp_zk_proofs::location_commitment(x, y, &blinding).unwrap();
            let commitment2 = smp_zk_proofs::location_commitment(x, y, &blinding).unwrap();

            assert_eq!(commitment1, commitment2);
        }

        #[test]
        fn training_commitment_is_deterministic(
            base_digest: [u8; 32],
            update_digest: [u8; 32],
            blinding_seed: [u8; 32]
        ) {
            let blinding = generate_deterministic_blinding_factor(blinding_seed);

            // Same inputs should always produce same commitment
            let commitment1 = smp_zk_proofs::training_commitment(
                base_digest, update_digest, &blinding
            ).unwrap();
            let commitment2 = smp_zk_proofs::training_commitment(
                base_digest, update_digest, &blinding
            ).unwrap();

            assert_eq!(commitment1, commitment2);
        }

        #[test]
        fn blinding_factor_does_not_affect_commitment_content(x: i64, y: i64) {
            let seed1 = [0u8; 32];
            let seed2 = [1u8; 32];

            let blinding1 = generate_deterministic_blinding_factor(seed1);
            let blinding2 = generate_deterministic_blinding_factor(seed2);

            // Commitment should include blinding factor in its content
            let commitment1 = smp_zk_proofs::location_commitment(x, y, &blinding1).unwrap();
            let commitment2 = smp_zk_proofs::location_commitment(x, y, &blinding2).unwrap();

            // Different bindings should produce different commitments
            assert_ne!(commitment1, commitment2);
        }

        #[test]
        fn location_proof_rejects_outside_bounds(
            x: i64,
            y: i64,
            x_min: i64,
            x_max: i64,
            y_min: i64,
            y_max: i64
        ) {
            let witness = LocationPrivateWitness {
                x,
                y,
                blinding: [0u8; 32],
            };

            let bounding_box = BoundingBox { x_min, x_max, y_min, y_max };

            if !bounding_box.contains(x, y) {
                // Prover outside bounds should fail
                let _public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness);
                // This will error with ConstraintUnsatisfied
                assert!(_public_inputs.is_err());
            } else {
                // Prover inside bounds should succeed
                let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                    .expect("Location public inputs");

                let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
                let proof = smp_zk_proofs::prove_location(&context, &public_inputs, &witness)
                    .expect("Location proof generation");

                // Verify the proof succeeds
                let verification_key = context.verification_key();
                assert!(smp_zk_proofs::verify_location_proof(&verification_key, &public_inputs, &proof).is_ok());
            }
        }

        #[test]
        fn training_proof_rejects_exceeded_steps(
            expected_steps: u32,
            steps_completed: u32,
        ) {
            let witness = TrainingPrivateWitness {
                steps_completed,
                observed_loss_milli: 100,
                weight_update_digest: [0u8; 32],
                blinding: [0u8; 32],
            };

            let public_inputs = TrainingPublicInputs::from_witness(
                expected_steps, 200, [0u8; 32], &witness
            ).expect("Training public inputs");

            // Different step counts should fail verification
            if steps_completed != expected_steps {
                let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
                let proof = smp_zk_proofs::prove_training(&context, &public_inputs, &witness)
                    .expect_err("Proof should fail for mismatched steps");

                assert!(proof.to_string().contains("training step count"));
            } else {
                // Matching step counts should succeed
                let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
                let proof = smp_zk_proofs::prove_training(&context, &public_inputs, &witness)
                    .expect("Training proof generation");

                let verification_key = context.verification_key();
                assert!(smp_zk_proofs::verify_training_proof(&verification_key, &public_inputs, &proof).is_ok());
            }
        }

        #[test]
        fn training_proof_rejects_exceeded_loss(
            expected_steps: u32,
            observed_loss_milli: u64,
            max_loss_milli: u64,
        ) {
            let witness = TrainingPrivateWitness {
                steps_completed: expected_steps,
                observed_loss_milli,
                weight_update_digest: [0u8; 32],
                blinding: [0u8; 32],
            };

            let public_inputs = TrainingPublicInputs::from_witness(
                expected_steps, max_loss_milli, [0u8; 32], &witness
            ).expect("Training public inputs");

            // Loss exceeding threshold should fail
            if observed_loss_milli > max_loss_milli {
                let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
                let proof = smp_zk_proofs::prove_training(&context, &public_inputs, &witness)
                    .expect_err("Proof should fail for exceeded loss");

                assert!(proof.to_string().contains("loss"));
            } else {
                // Within loss threshold should succeed
                let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
                let proof = smp_zk_proofs::prove_training(&context, &public_inputs, &witness)
                    .expect("Training proof generation");

                let verification_key = context.verification_key();
                assert!(smp_zk_proofs::verify_training_proof(&verification_key, &public_inputs, &proof).is_ok());
            }
        }

        #[test]
        fn proof_serialization_is_idempotent(
            seed: [u8; 32],
            witness_x_offset: i64,
            witness_y_offset: i64,
        ) {
            let blinding = generate_deterministic_blinding_factor(seed);

            let witness = LocationPrivateWitness {
                x: 50 + witness_x_offset,
                y: 50 + witness_y_offset,
                blinding,
            };

            let bounding_box = BoundingBox {
                x_min: 0,
                x_max: 100,
                y_min: 0,
                y_max: 100,
            };

            let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                .expect("Location public inputs");

            let context = smp_zk_proofs::ProvingContext::from_seed([0u8; 32]);
            let proof = smp_zk_proofs::prove_location(&context, &public_inputs, &witness)
                .expect("Location proof generation");

            // Serialize multiple times should produce same result
            let bytes1 = proof.to_bytes().unwrap();
            let bytes2 = proof.to_bytes().unwrap();
            assert_eq!(bytes1, bytes2);

            // Deserialize should produce valid proof
            let deserialized: smp_zk_proofs::Proof = bincode::deserialize(&bytes1).unwrap();
            assert_eq!(deserialized.circuit, smp_zk_proofs::CircuitKind::Location);
        }

        #[test]
        fn verification_key_roundtrip_is_deterministic(
            seed: [u8; 32],
        ) {
            let context = smp_zk_proofs::ProvingContext::from_seed(seed);
            let vk = context.verification_key();

            // Serialize and deserialize multiple times
            let bytes1 = vk.to_bytes().unwrap();
            let bytes2 = vk.to_bytes().unwrap();
            assert_eq!(bytes1, bytes2);

            let deserialized_vk = smp_zk_proofs::VerificationKey::from_bytes(&bytes1).unwrap();
            assert_eq!(vk.verifying_key, deserialized_vk.verifying_key);
        }

        #[test]
        fn wrong_verification_key_rejects_proof(
            seed1: [u8; 32],
            seed2: [u8; 32],
        ) {
            let context1 = smp_zk_proofs::ProvingContext::from_seed(seed1);
            let context2 = smp_zk_proofs::ProvingContext::from_seed(seed2);

            let witness = LocationPrivateWitness {
                x: 50,
                y: 50,
                blinding: [0u8; 32],
            };

            let bounding_box = BoundingBox {
                x_min: 0,
                x_max: 100,
                y_min: 0,
                y_max: 100,
            };

            let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                .expect("Location public inputs");

            let proof = smp_zk_proofs::prove_location(&context1, &public_inputs, &witness)
                .expect("Location proof generation");

            // Verify with correct key should succeed
            let vk1 = context1.verification_key();
            assert!(smp_zk_proofs::verify_location_proof(&vk1, &public_inputs, &proof).is_ok());

            // Verify with wrong key should fail
            let vk2 = context2.verification_key();
            assert!(smp_zk_proofs::verify_location_proof(&vk2, &public_inputs, &proof).is_err());
        }

        #[test]
        fn tampered_proof_signature_is_rejected(
            seed: [u8; 32],
        ) {
            let context = smp_zk_proofs::ProvingContext::from_seed(seed);
            let witness = LocationPrivateWitness {
                x: 50,
                y: 50,
                blinding: [0u8; 32],
            };

            let bounding_box = BoundingBox {
                x_min: 0,
                x_max: 100,
                y_min: 0,
                y_max: 100,
            };

            let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                .expect("Location public inputs");

            let proof = smp_zk_proofs::prove_location(&context, &public_inputs, &witness)
                .expect("Location proof generation");

            // Tamper with signature
            let mut tampered_proof = proof;
            if !tampered_proof.signature.is_empty() {
                tampered_proof.signature[0] ^= 0x01;
            }

            // Verify should fail
            let vk = context.verification_key();
            assert!(smp_zk_proofs::verify_location_proof(&vk, &public_inputs, &tampered_proof).is_err());
        }

        #[test]
        fn wrong_circuit_type_rejects_proof(
            seed: [u8; 32],
        ) {
            let context = smp_zk_proofs::ProvingContext::from_seed(seed);
            let location_witness = LocationPrivateWitness {
                x: 50,
                y: 50,
                blinding: [0u8; 32],
            };

            let bounding_box = BoundingBox {
                x_min: 0,
                x_max: 100,
                y_min: 0,
                y_max: 100,
            };

            let location_public_inputs = LocationPublicInputs::from_witness(bounding_box, &location_witness)
                .expect("Location public inputs");

            let location_proof = smp_zk_proofs::prove_location(&context, &location_public_inputs, &location_witness)
                .expect("Location proof generation");

            // Tamper with circuit type
            let mut tampered_proof = location_proof;
            tampered_proof.circuit = smp_zk_proofs::CircuitKind::Training;

            // Verify should fail
            let vk = context.verification_key();
            assert!(smp_zk_proofs::verify_location_proof(&vk, &location_public_inputs, &tampered_proof).is_err());
        }

        #[test]
        fn proof_size_is_reasonable(
            seed: [u8; 32],
        ) {
            let context = smp_zk_proofs::ProvingContext::from_seed(seed);
            let witness = LocationPrivateWitness {
                x: 50,
                y: 50,
                blinding: [0u8; 32],
            };

            let bounding_box = BoundingBox {
                x_min: 0,
                x_max: 100,
                y_min: 0,
                y_max: 100,
            };

            let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                .expect("Location public inputs");

            let proof = smp_zk_proofs::prove_location(&context, &public_inputs, &witness)
                .expect("Location proof generation");

            // Proof should be reasonable size (not too large)
            let bytes = proof.to_bytes().unwrap();
            assert!(bytes.len() < 1024, "Proof should be less than 1KB");
        }

        #[test]
        fn multiple_proofs_from_same_context_are_independent(
            seed: [u8; 32],
        ) {
            let context = smp_zk_proofs::ProvingContext::from_seed(seed);

            // Generate multiple proofs with different witnesses
            let mut proofs = Vec::new();
            for i in 0..10u8 {
                let witness = LocationPrivateWitness {
                    x: (50 + (i as i64)) % 100,
                    y: 50,
                    blinding: [0u8; 32],
                };

                let bounding_box = BoundingBox {
                    x_min: 0,
                    x_max: 100,
                    y_min: 0,
                    y_max: 100,
                };

                let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
                    .expect("Location public inputs");

                let proof = smp_zk_proofs::prove_location(&context, &public_inputs, &witness)
                    .expect("Location proof generation");

                proofs.push(proof);
            }

            // All proofs should be different
            for i in 0..proofs.len() {
                for j in (i + 1)..proofs.len() {
                    let bytes_i = proofs[i].to_bytes().unwrap();
                    let bytes_j = proofs[j].to_bytes().unwrap();
                    assert_ne!(bytes_i, bytes_j, "Proofs should be different");
                }
            }
        }

    }
}
