use smp_zk_proofs::{
    prove_location, prove_training, verify_location_proof, verify_training_proof, BoundingBox,
    LocationPrivateWitness, LocationPublicInputs, PlaceholderBackend, PostQuantumBackend,
    PostQuantumBackendStatus, Proof, ProvingContext, TrainingPrivateWitness, TrainingPublicInputs,
};

#[test]
fn location_proof_round_trip_verifies_after_bincode_serialization() {
    let context = ProvingContext::from_seed([21_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 24,
        y: 30,
        blinding: [7_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 10,
            x_max: 50,
            y_min: 20,
            y_max: 40,
        },
        &witness,
    )
    .expect("location public inputs");

    let proof = prove_location(&context, &public_inputs, &witness).expect("location proof");
    let proof_bytes = proof.to_bytes().expect("proof serialization");
    let decoded_proof = Proof::from_bytes(&proof_bytes).expect("proof deserialization");

    verify_location_proof(&context.verification_key(), &public_inputs, &decoded_proof)
        .expect("location verification");
}

#[test]
fn training_proof_round_trip_verifies_after_bincode_serialization() {
    let context = ProvingContext::from_seed([22_u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 4,
        observed_loss_milli: 199,
        weight_update_digest: [12_u8; 32],
        blinding: [13_u8; 32],
    };
    let public_inputs = TrainingPublicInputs::from_witness(4, 250, [2_u8; 32], &witness)
        .expect("training public inputs");

    let proof = prove_training(&context, &public_inputs, &witness).expect("training proof");
    let public_bytes = public_inputs.to_bytes().expect("public serialization");
    let decoded_public = TrainingPublicInputs::from_bytes(&public_bytes).expect("public decode");

    verify_training_proof(&context.verification_key(), &decoded_public, &proof)
        .expect("training verification");
}

#[test]
fn verification_key_round_trip_and_wrong_key_rejects_proof() {
    let context = ProvingContext::from_seed([25_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 18,
        y: 22,
        blinding: [5_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 10,
            x_max: 30,
            y_min: 20,
            y_max: 40,
        },
        &witness,
    )
    .expect("location public inputs");

    let proof = prove_location(&context, &public_inputs, &witness).expect("location proof");
    let verification_key = context.verification_key();
    let verification_key_bytes = verification_key.to_bytes().expect("verification key bytes");
    let decoded_verification_key =
        smp_zk_proofs::VerificationKey::from_bytes(&verification_key_bytes)
            .expect("verification key decode");

    verify_location_proof(&decoded_verification_key, &public_inputs, &proof)
        .expect("location verification");

    let wrong_context = ProvingContext::from_seed([26_u8; 32]);
    let wrong_key = wrong_context.verification_key();
    let error = verify_location_proof(&wrong_key, &public_inputs, &proof)
        .expect_err("wrong verification key should fail");
    assert!(error.to_string().contains("signature verification failed"));
}

#[test]
fn tampered_proof_signature_is_rejected() {
    let context = ProvingContext::from_seed([27_u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 3,
        observed_loss_milli: 80,
        weight_update_digest: [14_u8; 32],
        blinding: [15_u8; 32],
    };
    let public_inputs = TrainingPublicInputs::from_witness(3, 100, [16_u8; 32], &witness)
        .expect("training public inputs");

    let proof = prove_training(&context, &public_inputs, &witness).expect("training proof");
    let mut tampered_proof =
        Proof::from_bytes(&proof.to_bytes().expect("proof bytes")).expect("proof decode");
    tampered_proof.signature[0] ^= 0x01;

    let error = verify_training_proof(&context.verification_key(), &public_inputs, &tampered_proof)
        .expect_err("tampered proof should fail");
    assert!(error.to_string().contains("signature verification failed"));
}

#[test]
fn tampered_proof_circuit_is_rejected() {
    let context = ProvingContext::from_seed([28_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 8,
        y: 9,
        blinding: [17_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 0,
            x_max: 10,
            y_min: 0,
            y_max: 10,
        },
        &witness,
    )
    .expect("location public inputs");

    let proof = prove_location(&context, &public_inputs, &witness).expect("location proof");
    let mut tampered_proof =
        Proof::from_bytes(&proof.to_bytes().expect("proof bytes")).expect("proof decode");
    tampered_proof.circuit = smp_zk_proofs::CircuitKind::Training;

    let error = verify_location_proof(&context.verification_key(), &public_inputs, &tampered_proof)
        .expect_err("wrong circuit should fail");
    assert!(error.to_string().contains("proof circuit"));
}

#[test]
fn placeholder_backend_exposes_migration_plan() {
    let backend = PlaceholderBackend;
    let descriptor = backend.descriptor();

    assert_eq!(descriptor.name, "placeholder-pq-backend");
    assert_eq!(descriptor.status, PostQuantumBackendStatus::Reserved);
    assert!(descriptor.notes.contains("post-quantum proving backend"));
    assert_eq!(descriptor.migration_steps.len(), 3);
    assert!(descriptor
        .migration_steps
        .iter()
        .any(|step| step.contains("public circuit API")));
}

#[test]
fn location_proof_rejects_out_of_bounds_witness() {
    let context = ProvingContext::from_seed([23_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 12,
        y: 14,
        blinding: [9_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 10,
            x_max: 50,
            y_min: 10,
            y_max: 50,
        },
        &witness,
    )
    .expect("location public inputs");
    let invalid_witness = LocationPrivateWitness {
        x: 60,
        y: 14,
        blinding: [9_u8; 32],
    };

    let error = prove_location(&context, &public_inputs, &invalid_witness)
        .expect_err("out-of-bounds witness should fail");
    assert!(error.to_string().contains("coordinate commitment"));
}

#[test]
fn training_proof_rejects_loss_above_threshold() {
    let context = ProvingContext::from_seed([24_u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 6,
        observed_loss_milli: 100,
        weight_update_digest: [10_u8; 32],
        blinding: [3_u8; 32],
    };
    let public_inputs = TrainingPublicInputs::from_witness(6, 150, [6_u8; 32], &witness)
        .expect("training public inputs");
    let invalid_witness = TrainingPrivateWitness {
        observed_loss_milli: 151,
        ..witness
    };

    let error = prove_training(&context, &public_inputs, &invalid_witness)
        .expect_err("high-loss witness should fail");
    assert!(error.to_string().contains("loss"));
}
