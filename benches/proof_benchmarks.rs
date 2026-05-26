use criterion::{Criterion, criterion_group, criterion_main};
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, ProvingContext,
    TrainingPrivateWitness, TrainingPublicInputs, prove_location, prove_training,
    verify_location_proof, verify_training_proof,
};

fn bench_location(c: &mut Criterion) {
    let context = ProvingContext::from_seed([11_u8; 32]);
    let witness = LocationPrivateWitness {
        x: 15,
        y: 18,
        blinding: [4_u8; 32],
    };
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 100,
        },
        &witness,
    )
    .expect("location public inputs");
    let proof = prove_location(&context, &public_inputs, &witness).expect("location proof");
    let verification_key = context.verification_key();

    c.bench_function("prove_location", |b| {
        b.iter(|| prove_location(&context, &public_inputs, &witness).expect("location proof"))
    });
    c.bench_function("verify_location", |b| {
        b.iter(|| verify_location_proof(&verification_key, &public_inputs, &proof).expect("verify"))
    });
}

fn bench_training(c: &mut Criterion) {
    let context = ProvingContext::from_seed([13_u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 16,
        observed_loss_milli: 300,
        weight_update_digest: [8_u8; 32],
        blinding: [6_u8; 32],
    };
    let public_inputs = TrainingPublicInputs::from_witness(16, 400, [10_u8; 32], &witness)
        .expect("training public inputs");
    let proof = prove_training(&context, &public_inputs, &witness).expect("training proof");
    let verification_key = context.verification_key();

    c.bench_function("prove_training", |b| {
        b.iter(|| prove_training(&context, &public_inputs, &witness).expect("training proof"))
    });
    c.bench_function("verify_training", |b| {
        b.iter(|| verify_training_proof(&verification_key, &public_inputs, &proof).expect("verify"))
    });
}

criterion_group!(benches, bench_location, bench_training);
criterion_main!(benches);
