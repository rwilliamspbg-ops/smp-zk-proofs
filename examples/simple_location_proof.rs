use smp_zk_proofs::{
    prove_location, verify_location_proof, BoundingBox, LocationPrivateWitness,
    LocationPublicInputs, Proof, ProvingContext,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = ProvingContext::from_seed([7_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 41,
        y: 12,
        blinding: [3_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 50,
        },
        &witness,
    )?;

    let proof = prove_location(&context, &public_inputs, &witness)?;
    let proof_bytes = proof.to_bytes()?;
    let decoded_proof = Proof::from_bytes(&proof_bytes)?;

    verify_location_proof(&context.verification_key(), &public_inputs, &decoded_proof)?;

    println!("location proof verified");
    println!("circuit: {:?}", decoded_proof.circuit);
    println!("scheme: {:?}", decoded_proof.scheme);
    println!("serialized proof size: {} bytes", proof_bytes.len());
    Ok(())
}
