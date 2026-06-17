//! Comprehensive tests for CSPRNG blinding factor generation and validation.
//! These tests ensure production-ready randomness for all proof operations.

use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness,
    TrainingPublicInputs, VerificationKey, generate_deterministic_blinding_factor,
};

#[test]
fn test_deterministic_blinding_generation() {
    // Test that deterministic blinding generation is reproducible
    let seed1 = [0u8; 32];
    let seed2 = [1u8; 32];

    let blinding1 = generate_deterministic_blinding_factor(seed1);
    let blinding2 = generate_deterministic_blinding_factor(seed1);

    // Same seed should produce same blinding factor
    assert_eq!(blinding1, blinding2);

    // Different seeds should produce different blinding factors
    assert_ne!(blinding1, blinding2);
}

#[test]
fn test_blinding_factor_entropy_validation() {
    use smp_zk_proofs::validate_blinding_factor;

    // Test valid blinding factor (random-looking)
    let valid_blinding: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F,
        0x70, 0x81,
    ];
    assert!(validate_blinding_factor(&valid_blinding).is_ok());

    // Test weak blinding factor (too many zeros)
    let weak_blinding: [u8; 32] = [0u8; 20] + [0x99, 0x99, 0x99, 0x99, 0x99, 0x99];
    assert!(validate_blinding_factor(&weak_blinding).is_err());

    // Test weak blinding factor (all same value)
    let uniform_blinding: [u8; 32] = [0x42u8; 32];
    assert!(validate_blinding_factor(&uniform_blinding).is_err());
}

#[test]
fn test_location_proof_with_csprng_blinding() {
    #[cfg(feature = "rand")]
    {
        use smp_zk_proofs::generate_secure_blinding_factor;

        let context = ProvingContext::from_seed([11_u8; 32]);

        // Generate secure blinding factor using CSPRNG
        let blinding = generate_secure_blinding_factor().expect("CSprng should work");

        let witness = LocationPrivateWitness {
            x: 41,
            y: 12,
            blinding,
        };

        let bounding_box = BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 50,
        };

        let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
            .expect("Location public inputs");

        let proof =
            prove_location(&context, &public_inputs, &witness).expect("Location proof generation");

        let verification_key = context.verification_key();
        verify_location_proof(&verification_key, &public_inputs, &proof)
            .expect("Location proof verification");
    }

    #[cfg(not(feature = "rand"))]
    {
        println!("Skipping CSPRNG test: rand feature not enabled");
    }
}

#[test]
fn test_training_proof_with_csprng_blinding() {
    #[cfg(feature = "rand")]
    {
        use smp_zk_proofs::generate_secure_blinding_factor;

        let context = ProvingContext::from_seed([13_u8; 32]);

        // Generate secure blinding factor using CSPRNG
        let blinding = generate_secure_blinding_factor().expect("CSprng should work");

        let witness = TrainingPrivateWitness {
            steps_completed: 8,
            observed_loss_milli: 275,
            weight_update_digest: [5u8; 32],
            blinding,
        };

        let public_inputs = TrainingPublicInputs::from_witness(8, 300, [2u8; 32], &witness)
            .expect("Training public inputs");

        let proof =
            prove_training(&context, &public_inputs, &witness).expect("Training proof generation");

        let verification_key = context.verification_key();
        verify_training_proof(&verification_key, &public_inputs, &proof)
            .expect("Training proof verification");
    }

    #[cfg(not(feature = "rand"))]
    {
        println!("Skipping CSPRNG test: rand feature not enabled");
    }
}

#[test]
fn test_constant_time_blinding_comparison() {
    #[cfg(feature = "constant_time_eq")]
    {
        use smp_zk_proofs::constant_time_eq_bytes;

        let blinding1: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x1A, 0x2B, 0x3C, 0x4D,
            0x5E, 0x6F, 0x70, 0x81,
        ];

        let blinding2 = blinding1;

        // Constant-time comparison should work
        assert!(constant_time_eq_bytes(&blinding1, &blinding2));

        // Different values should return false
        let mut blinding3 = blinding1;
        blinding3[0] = 0xFF;
        assert!(!constant_time_eq_bytes(&blinding1, &blinding3));
    }

    #[cfg(not(feature = "constant_time_eq"))]
    {
        println!("Skipping constant-time comparison test: constant_time_eq feature not enabled");
    }
}

#[test]
fn test_blinding_factor_uniqueness_across_proofs() {
    use smp_zk_proofs::generate_deterministic_blinding_factor;

    // Generate multiple blinding factors from different seeds
    let mut blinding_factors = Vec::new();
    for i in 0..100u8 {
        let seed = [
            i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        let blinding = generate_deterministic_blinding_factor(seed);
        blinding_factors.push(blinding);
    }

    // All blinding factors should be unique
    let mut seen = std::collections::HashSet::new();
    for blinding in &blinding_factors {
        assert!(
            seen.insert(*blinding),
            "Duplicate blinding factor detected!"
        );
    }
}

#[test]
fn test_blinding_factor_entropy_distribution() {
    use smp_zk_proofs::generate_deterministic_blinding_factor;

    // Generate many blinding factors and check entropy distribution
    let mut entropy_counts = std::collections::HashMap::new();

    for i in 0..100u8 {
        let seed = [
            (i % 256) as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let blinding = generate_deterministic_blinding_factor(seed);

        // Count unique values in the blinding factor
        let unique_values = blinding.iter().collect::<std::collections::HashSet<_>>();
        let entropy = unique_values.len() as u32;

        *entropy_counts.entry(entropy).or_insert(0) += 1;
    }

    // Check that we have a reasonable distribution of entropy values
    assert!(
        entropy_counts.contains_key(&4),
        "Expected some blinding factors with low entropy"
    );
    assert!(
        entropy_counts.contains_key(&32),
        "Expected some blinding factors with high entropy"
    );
}

#[test]
fn test_proof_serialization_with_varied_blinding() {
    use smp_zk_proofs::{deserialize, generate_deterministic_blinding_factor, serialize};

    // Test serialization/deserialization with various blinding factors
    let context = ProvingContext::from_seed([11_u8; 32]);

    for seed in [0u8..=9u8].iter() {
        let blinding = generate_deterministic_blinding_factor(*seed);

        let witness = LocationPrivateWitness {
            x: (10 + *seed) as i64,
            y: 12,
            blinding,
        };

        let bounding_box = BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 50,
        };

        let public_inputs = LocationPublicInputs::from_witness(bounding_box, &witness)
            .expect("Location public inputs");

        let proof =
            prove_location(&context, &public_inputs, &witness).expect("Location proof generation");

        // Serialize and deserialize
        let bytes = serialize(&proof).expect("Proof serialization");
        let deserialized_proof: Proof = deserialize(&bytes).expect("Proof deserialization");

        // Verify the deserialized proof
        let verification_key = context.verification_key();
        verify_location_proof(&verification_key, &public_inputs, &deserialized_proof)
            .expect("Location proof verification after deserialization");
    }
}
