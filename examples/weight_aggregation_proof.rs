use smp_zk_proofs::{
    prove_training, verify_training_proof, Proof, ProvingContext, TrainingPrivateWitness,
    TrainingPublicInputs,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = ProvingContext::from_seed([9_u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 8,
        observed_loss_milli: 275,
        weight_update_digest: [5_u8; 32],
        blinding: [1_u8; 32],
    };
    let public_inputs = TrainingPublicInputs::from_witness(8, 300, [2_u8; 32], &witness)?;

    let proof = prove_training(&context, &public_inputs, &witness)?;
    let proof_bytes = proof.to_bytes()?;
    let decoded_proof = Proof::from_bytes(&proof_bytes)?;

    verify_training_proof(&context.verification_key(), &public_inputs, &decoded_proof)?;

    println!("training proof verified");
    println!("circuit: {:?}", decoded_proof.circuit);
    println!("scheme: {:?}", decoded_proof.scheme);
    println!("serialized proof size: {} bytes", proof_bytes.len());
    Ok(())
}
