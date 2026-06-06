use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

use crate::{
    ZkProofError,
    proofs::types::*,
    utils,
};

pub fn verify_location_proof(
    verification_key: &ZkSnarkVerifyingKey,
    public_inputs: &LocationPublicInputs,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    verify_zk_snark_proof(
        verification_key,
        CircuitKind::Location,
        public_inputs,
        proof,
    )
}

pub fn verify_training_proof(
    verification_key: &ZkSnarkVerifyingKey,
    public_inputs: &TrainingPublicInputs,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    verify_zk_snark_proof(
        verification_key,
        CircuitKind::Training,
        public_inputs,
        proof,
    )
}

fn verify_zk_snark_proof<T: serde::Serialize>(
    vk: &ZkSnarkVerifyingKey,
    expected_circuit: CircuitKind,
    public_inputs: &T,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    if proof.circuit != expected_circuit {
        return Err(ZkProofError::VerificationFailed(format!(
            "proof circuit {:?} does not match expected {:?}",
            proof.circuit, expected_circuit
        )));
    }

    if proof.scheme != ProofScheme::Groth16Bls12_381 {
        return Err(ZkProofError::VerificationFailed(
            "unsupported proof scheme".to_owned(),
        ));
    }

    let expected_statement_digest = utils::hash_serializable(public_inputs)?;
    if proof.statement_digest != expected_statement_digest {
        return Err(ZkProofError::VerificationFailed(
            "statement digest does not match the supplied public inputs".to_owned(),
        ));
    }

    // Verify the zk-SNARK proof
    let zk_proof = proof.zk_snark_proof.as_ref()
        .ok_or_else(|| ZkProofError::VerificationFailed("missing zk-SNARK proof".to_string()))?;
    
    let ark_proof = zk_proof.to_arkworks_proof()?;
    let ark_vk = vk.to_arkworks_vk()?;
    
    // Prepare public inputs for verification
    let mut public_input_values = Vec::new();
    
    match expected_circuit {
        CircuitKind::Location => {
            let loc_inputs = public_inputs.downcast_ref::<LocationPublicInputs>()
                .ok_or_else(|| ZkProofError::VerificationFailed("invalid public input type for location circuit".to_string()))?;
            
            public_input_values.push(ark_ff::Fp::from(loc_inputs.bounding_box.x_min as u64));
            public_input_values.push(ark_ff::Fp::from(loc_inputs.bounding_box.x_max as u64));
            public_input_values.push(ark_ff::Fp::from(loc_inputs.bounding_box.y_min as u64));
            public_input_values.push(ark_ff::Fp::from(loc_inputs.bounding_box.y_max as u64));
        },
        CircuitKind::Training => {
            let train_inputs = public_inputs.downcast_ref::<TrainingPublicInputs>()
                .ok_or_else(|| ZkProofError::VerificationFailed("invalid public input type for training circuit".to_string()))?;
            
            public_input_values.push(ark_ff::Fp::from(train_inputs.expected_steps as u64));
            public_input_values.push(ark_ff::Fp::from(train_inputs.max_loss_milli));
        },
    }
    
    Groth16::<Bls12_381>::verify_with_processed_vk(&ark_vk, &public_input_values, &ark_proof)
        .map_err(|e| ZkProofError::VerificationFailed(format!("zk-SNARK verification failed: {}", e)))?;

    Ok(())
}
