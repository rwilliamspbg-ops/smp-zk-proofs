//! Fuzz targets for proof serialization and deserialization
//! Run with: cargo fuzz run prove_proof_serialization

#![no_main]

use libfuzzer_sys::fuzz_target;
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, ProvingContext,
    Proof, TrainingPrivateWitness, TrainingPublicInputs,
};

fn fuzz_location_proof_serialization(data: &[u8]) {
    // Test 1: Decode proof bytes (fuzz deserialization)
    if let Ok(proof) = Proof::from_bytes(data) {
        // Verify the proof structure is valid
        assert_eq!(proof.circuit, smp_zk_proofs::CircuitKind::Location);
        assert_eq!(proof.scheme, smp_zk_proofs::ProofScheme::DevelopmentSignedTranscriptV1);
    }

    // Test 2: Generate and serialize a valid proof
    let context = ProvingContext::from_seed([0u8; 32]);
    let witness = LocationPrivateWitness {
        x: 41,
        y: 12,
        blinding: [3u8; 32],
    };
    
    // Use data to vary bounding box and other parameters
    let x_min = (data[0] % 100) as i64;
    let x_max = ((data[0] + 50) % 100) as i64 + x_min;
    let y_min = (data[1] % 50) as i64;
    let y_max = ((data[1] + 30) % 50) as i64 + y_min;

    let bounding_box = BoundingBox { x_min, x_max, y_min, y_max };
    
    if let Ok(public_inputs) = LocationPublicInputs::from_witness(bounding_box, &witness) {
        if let Ok(proof) = smp_zk_proofs::prove_location(&context, &public_inputs, &witness) {
            // Serialize the proof
            let _bytes = proof.to_bytes().unwrap();
        }
    }
}

fn fuzz_training_proof_serialization(data: &[u8]) {
    // Test 1: Decode training proof bytes
    if let Ok(proof) = Proof::from_bytes(data) {
        assert_eq!(proof.circuit, smp_zk_proofs::CircuitKind::Training);
        assert_eq!(proof.scheme, smp_zk_proofs::ProofScheme::DevelopmentSignedTranscriptV1);
    }

    // Test 2: Generate and serialize a valid training proof
    let context = ProvingContext::from_seed([0u8; 32]);
    let steps_completed = (data[0] % 20) as u32 + 1;
    let observed_loss_milli = ((data[1] % 500) as u64) + 10;
    
    let witness = TrainingPrivateWitness {
        steps_completed,
        observed_loss_milli,
        weight_update_digest: [5u8; 32],
        blinding: [1u8; 32],
    };

    if let Ok(public_inputs) = TrainingPublicInputs::from_witness(
        steps_completed,
        ((data[2] % 1000) as u64) + 100,
        [2u8; 32],
        &witness,
    ) {
        if let Ok(proof) = smp_zk_proofs::prove_training(&context, &public_inputs, &witness) {
            let _bytes = proof.to_bytes().unwrap();
        }
    }
}

fn fuzz_location_public_inputs_serialization(data: &[u8]) {
    // Test deserialization of LocationPublicInputs
    if let Ok(inputs) = LocationPublicInputs::from_bytes(data) {
        assert!(inputs.bounding_box.validate().is_ok());
    }
    
    // Test generation and serialization
    let witness = LocationPrivateWitness {
        x: (data[0] % 200) as i64,
        y: (data[1] % 200) as i64,
        blinding: [3u8; 32],
    };
    
    let bounding_box = BoundingBox {
        x_min: (data[2] % 100) as i64,
        x_max: ((data[2] + 50) % 100) as i64 + (data[2] % 100) as i64,
        y_min: (data[3] % 50) as i64,
        y_max: ((data[3] + 30) % 50) as i64 + (data[3] % 50) as i64,
    };
    
    if let Ok(inputs) = LocationPublicInputs::from_witness(bounding_box, &witness) {
        let _bytes = inputs.to_bytes().unwrap();
    }
}

fn fuzz_training_public_inputs_serialization(data: &[u8]) {
    // Test deserialization of TrainingPublicInputs
    if let Ok(inputs) = TrainingPublicInputs::from_bytes(data) {
        assert!(inputs.expected_steps > 0);
    }
    
    // Test generation and serialization
    let witness = TrainingPrivateWitness {
        steps_completed: (data[0] % 30) as u32 + 1,
        observed_loss_milli: ((data[1] % 1000) as u64) + 10,
        weight_update_digest: [5u8; 32],
        blinding: [1u8; 32],
    };
    
    if let Ok(inputs) = TrainingPublicInputs::from_witness(
        (data[2] % 50) as u32 + 1,
        ((data[3] % 2000) as u64) + 100,
        [2u8; 32],
        &witness,
    ) {
        let _bytes = inputs.to_bytes().unwrap();
    }
}

fn fuzz_proof_verification_key_serialization(data: &[u8]) {
    // Test deserialization of VerificationKey
    if let Ok(vk) = smp_zk_proofs::VerificationKey::from_bytes(data) {
        assert_eq!(vk.verifying_key.len(), 32);
    }
    
    // Test generation and serialization
    let context = ProvingContext::from_seed([0u8; 32]);
    let vk = context.verification_key();
    let _bytes = vk.to_bytes().unwrap();
}

fuzz_target!( |data: &[u8]| {
    // Run all fuzzing tests with the input data
    fuzz_location_proof_serialization(data);
    fuzz_training_proof_serialization(data);
    fuzz_location_public_inputs_serialization(data);
    fuzz_training_public_inputs_serialization(data);
    fuzz_proof_verification_key_serialization(data);
});
