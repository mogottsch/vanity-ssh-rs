use criterion::{Criterion, criterion_group, criterion_main, BenchmarkId};
use std::hint::black_box;
use vanity_ssh_rs::core::keypair::{generate_keypair_batch, BATCH_SIZE};
use vanity_ssh_rs::core::pattern::{Pattern, public_key_matches_pattern};
use vanity_ssh_rs::worker::generator::generate_and_check_batch;
use vanity_ssh_rs::core::keypair::bench_helpers::*;

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
                    .map(|kp| public_key_matches_pattern(kp, &pattern))
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

fn bench_secret_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation_components");
    group.measurement_time(std::time::Duration::from_secs(10));
    
    group.bench_function("secret_key_generation", |b| {
        b.iter(|| {
            let secret_key = generate_secret_key();
            black_box(secret_key)
        })
    });
    group.finish();
}

fn bench_expand_secret_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation_components");
    group.measurement_time(std::time::Duration::from_secs(10));
    
    let secret_key = generate_secret_key();
    
    group.bench_function("expand_secret_key", |b| {
        b.iter(|| {
            let expanded = expand_secret_key(&secret_key);
            black_box(expanded)
        })
    });
    group.finish();
}

fn bench_mul_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation_components");
    group.measurement_time(std::time::Duration::from_secs(10));
    
    let secret_key = generate_secret_key();
    let expanded = expand_secret_key(&secret_key);
    
    group.bench_function("mul_base", |b| {
        b.iter(|| {
            let point = compute_mul_base(&expanded);
            black_box(point)
        })
    });
    group.finish();
}

fn bench_compress_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation_components");
    group.measurement_time(std::time::Duration::from_secs(10));
    
    let secret_key = generate_secret_key();
    let expanded = expand_secret_key(&secret_key);
    let point = compute_mul_base(&expanded);
    
    group.bench_function("compress_point", |b| {
        b.iter(|| {
            let compressed = compress_point(&point);
            black_box(compressed)
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_generate_key_batch,
    bench_check_suffix_batch,
    bench_generate_and_check_batch,
    bench_secret_key_generation,
    bench_expand_secret_key,
    bench_mul_base,
    bench_compress_point,
);
criterion_main!(benches);
