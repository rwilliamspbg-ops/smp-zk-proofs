use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Projective as G1, G2Projective as G2};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey as ArkVerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::UniformRand;
use rand::rngs::OsRng;

use crate::{
    ConstraintReport, LocationCircuit, TrainingCircuit, ZkProofError,
    constraints::Circuit,
    proofs::types::*,
    utils,
};

/// Location circuit wrapper for arkworks R1CS
#[derive(Clone)]
pub struct ArkLocationCircuit {
    pub public_inputs: Option<LocationPublicInputs>,
    pub private_witness: Option<LocationPrivateWitness>,
}

impl ConstraintSynthesizer<BlsFr> for ArkLocationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsFr>,
    ) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let x_min = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().bounding_box.x_min as u64)))?;
        let x_max = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().bounding_box.x_max as u64)))?;
        let y_min = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().bounding_box.y_min as u64)))?;
        let y_max = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().bounding_box.y_max as u64)))?;
        
        // Allocate private witness
        let x = cs.new_witness(|| Ok(BlsFr::from(self.private_witness.as_ref().unwrap().x as u64)))?;
        let y = cs.new_witness(|| Ok(BlsFr::from(self.private_witness.as_ref().unwrap().y as u64)))?;
        
        // Constraint: x_min <= x <= x_max
        // We enforce: (x - x_min) * (x_max - x) >= 0
        // In R1CS: we check that x is in range by ensuring constraints are satisfied
        let x_minus_min = cs.new_witness(|| {
            Ok(x.value()? - x_min.value()?)
        })?;
        let max_minus_x = cs.new_witness(|| {
            Ok(x_max.value()? - x.value()?)
        })?;
        
        // Enforce x - x_min = x_minus_min
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(x.value()? - x_min.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(x_minus_min.value()?), ark_relations::r1cs::VariableType::Witness)?,
        )?;
        
        // Enforce x_max - x = max_minus_x
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(x_max.value()? - x.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(max_minus_x.value()?), ark_relations::r1cs::VariableType::Witness)?,
        )?;
        
        // Similar constraints for y
        let y_minus_min = cs.new_witness(|| {
            Ok(y.value()? - y_min.value()?)
        })?;
        let max_minus_y = cs.new_witness(|| {
            Ok(y_max.value()? - y.value()?)
        })?;
        
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(y.value()? - y_min.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(y_minus_min.value()?), ark_relations::r1cs::VariableType::Witness)?,
        )?;
        
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(y_max.value()? - y.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(max_minus_y.value()?), ark_relations::r1cs::VariableType::Witness)?,
        )?;
        
        Ok(())
    }
}

/// Training circuit wrapper for arkworks R1CS
#[derive(Clone)]
pub struct ArkTrainingCircuit {
    pub public_inputs: Option<TrainingPublicInputs>,
    pub private_witness: Option<TrainingPrivateWitness>,
}

impl ConstraintSynthesizer<BlsFr> for ArkTrainingCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsFr>,
    ) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let expected_steps = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().expected_steps as u64)))?;
        let max_loss = cs.new_input(|| Ok(BlsFr::from(self.public_inputs.as_ref().unwrap().max_loss_milli)))?;
        
        // Allocate private witness
        let steps = cs.new_witness(|| Ok(BlsFr::from(self.private_witness.as_ref().unwrap().steps_completed as u64)))?;
        let loss = cs.new_witness(|| Ok(BlsFr::from(self.private_witness.as_ref().unwrap().observed_loss_milli)))?;
        
        // Constraint: steps == expected_steps
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(steps.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(expected_steps.value()?), ark_relations::r1cs::VariableType::Input)?,
        )?;
        
        // Constraint: loss <= max_loss
        let diff = cs.new_witness(|| {
            Ok(max_loss.value()? - loss.value()?)
        })?;
        
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::new_variable(cs.clone(), || Ok(diff.value()?), ark_relations::r1cs::VariableType::Witness)?,
            ark_relations::r1cs::LinearCombination::one(),
            ark_relations::r1cs::LinearCombination::one(),
        )?;
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProvingContext {
    location_pk: Option<ProvingKey<Bls12_381>>,
    training_pk: Option<ProvingKey<Bls12_381>>,
    location_vk: Option<ZkSnarkVerifyingKey>,
    training_vk: Option<ZkSnarkVerifyingKey>,
}

impl ProvingContext {
    pub fn setup() -> Result<Self, ZkProofError> {
        let mut rng = OsRng;
        
        // Setup location circuit with dummy parameters
        let location_circuit = ArkLocationCircuit {
            public_inputs: Some(LocationPublicInputs {
                bounding_box: BoundingBox {
                    x_min: 0,
                    x_max: 1000,
                    y_min: 0,
                    y_max: 1000,
                },
                coordinate_commitment: [0u8; 32],
            }),
            private_witness: Some(LocationPrivateWitness {
                x: 500,
                y: 500,
                blinding: [0u8; 32],
            }),
        };
        
        let (_, location_pk, location_vk) = Groth16::<Bls12_381>::circuit_specific_setup(location_circuit, &mut rng)
            .map_err(|e| ZkProofError::SetupFailed(e.to_string()))?;
        
        let location_vk_wrapper = ZkSnarkVerifyingKey::from_arkworks_vk(&location_vk)?;
        
        // Setup training circuit with dummy parameters
        let training_circuit = ArkTrainingCircuit {
            public_inputs: Some(TrainingPublicInputs {
                expected_steps: 100,
                max_loss_milli: 1000,
                base_model_digest: [0u8; 32],
                update_commitment: [0u8; 32],
            }),
            private_witness: Some(TrainingPrivateWitness {
                steps_completed: 100,
                observed_loss_milli: 500,
                weight_update_digest: [0u8; 32],
                blinding: [0u8; 32],
            }),
        };
        
        let (_, training_pk, training_vk) = Groth16::<Bls12_381>::circuit_specific_setup(training_circuit, &mut rng)
            .map_err(|e| ZkProofError::SetupFailed(e.to_string()))?;
        
        let training_vk_wrapper = ZkSnarkVerifyingKey::from_arkworks_vk(&training_vk)?;
        
        Ok(Self {
            location_pk: Some(location_pk),
            training_pk: Some(training_pk),
            location_vk: Some(location_vk_wrapper),
            training_vk: Some(training_vk_wrapper),
        })
    }

    pub fn verification_key(&self) -> VerificationKey {
        // Use a hash of the VKs as the identifier
        let vk_bytes = utils::hash_bytes(&[b"verification-key-v1"]);
        VerificationKey {
            verifying_key: vk_bytes,
            zk_snark_vk: None, // Can be populated with specific VK if needed
        }
    }
    
    pub fn location_verification_key(&self) -> Option<ZkSnarkVerifyingKey> {
        self.location_vk.clone()
    }
    
    pub fn training_verification_key(&self) -> Option<ZkSnarkVerifyingKey> {
        self.training_vk.clone()
    }
}

pub fn prove_location(
    context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    // First validate constraints
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    
    // Generate zk-SNARK proof
    let mut rng = OsRng;
    let circuit = ArkLocationCircuit {
        public_inputs: Some(public_inputs.clone()),
        private_witness: Some(private_witness.clone()),
    };
    
    let pk = context.location_pk.as_ref()
        .ok_or_else(|| ZkProofError::SetupFailed("Location proving key not initialized".to_string()))?;
    
    let ark_proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| ZkProofError::ProofGenerationFailed(e.to_string()))?;
    
    let zk_snark_proof = ZkSnarkProof::from_arkworks_proof(&ark_proof)?;
    
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;
    
    Ok(Proof {
        circuit: CircuitKind::Location,
        scheme: ProofScheme::Groth16Bls12_381,
        statement_digest,
        constraint_digest,
        zk_snark_proof: Some(zk_snark_proof),
    })
}

pub fn prove_training(
    context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    // First validate constraints
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
<<<<<<< HEAD
    
    // Generate zk-SNARK proof
    let mut rng = OsRng;
    let circuit = ArkTrainingCircuit {
        public_inputs: Some(public_inputs.clone()),
        private_witness: Some(private_witness.clone()),
    };
    
    let pk = context.training_pk.as_ref()
        .ok_or_else(|| ZkProofError::SetupFailed("Training proving key not initialized".to_string()))?;
    
    let ark_proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| ZkProofError::ProofGenerationFailed(e.to_string()))?;
    
    let zk_snark_proof = ZkSnarkProof::from_arkworks_proof(&ark_proof)?;
    
=======
    sign_proof(context, public_inputs, report)
}

#[cfg(feature = "halo2")]
pub fn prove_location_halo2(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    // Build a Halo2 proof (scaffold) and wrap it into the existing `Proof` type.
    let proof_bytes =
        crate::proofs::halo2_backend::prove_location_halo2(public_inputs, private_witness)?;
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Halo2V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "halo2")]
pub fn prove_training_halo2(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::halo2_backend::prove_training_halo2(public_inputs, private_witness)?;
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Halo2V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "groth16")]
pub fn prove_location_groth16(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::groth16_backend::prove_location_groth16(public_inputs, private_witness)?;
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Groth16V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "groth16")]
pub fn prove_training_groth16(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::groth16_backend::prove_training_groth16(public_inputs, private_witness)?;
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Groth16V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

fn sign_proof<T: Serialize>(
    context: &ProvingContext,
    public_inputs: &T,
    report: ConstraintReport,
) -> Result<Proof, ZkProofError> {
>>>>>>> origin/main
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;
    
    Ok(Proof {
        circuit: CircuitKind::Training,
        scheme: ProofScheme::Groth16Bls12_381,
        statement_digest,
        constraint_digest,
<<<<<<< HEAD
        zk_snark_proof: Some(zk_snark_proof),
=======
        signature,
        backend_proof: None,
>>>>>>> origin/main
    })
}
