use criterion::{Criterion, criterion_group, criterion_main, BenchmarkId};
use std::hint::black_box;
use vanity_ssh_rs::core::keypair::{generate_keypair_batch, BATCH_SIZE};
use vanity_ssh_rs::core::pattern::{Pattern, public_key_matches_pattern};
use vanity_ssh_rs::worker::generator::generate_and_check_batch;

fn bench_generate_key_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_keypair_batch");
    group.measurement_time(std::time::Duration::from_secs(10));
    group.bench_with_input(
        BenchmarkId::from_parameter(BATCH_SIZE),
        &BATCH_SIZE,
        |b, &size| {
            b.iter(|| {
                let key_pairs = generate_keypair_batch(size);
                black_box(key_pairs)
            })
        },
    );
    group.finish();
}

fn bench_check_suffix_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("public_key_matches_pattern_batch");
    let pattern = Pattern::Suffix("yee".to_string());
    let key_pairs = generate_keypair_batch(BATCH_SIZE);
    
    group.bench_with_input(
        BenchmarkId::from_parameter(BATCH_SIZE),
        &BATCH_SIZE,
        |b, &_size| {
            b.iter(|| {
                let matches: Vec<bool> = key_pairs
                    .iter()
                    .map(|kp| public_key_matches_pattern(&kp.public_key, &pattern))
                    .collect();
                black_box(matches)
            })
        },
    );
    group.finish();
}

fn bench_generate_and_check_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_and_check_batch");
    group.measurement_time(std::time::Duration::from_secs(10));
    let patterns = vec![Pattern::Suffix("yee".to_string())];
    
    group.bench_function("generate_and_check_batch", |b| {
        b.iter(|| {
            let result = generate_and_check_batch(&patterns);
            black_box(result)
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_generate_key_batch,
    bench_check_suffix_batch,
    bench_generate_and_check_batch
);
criterion_main!(benches);
