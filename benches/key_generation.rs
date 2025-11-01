use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};
use vanity_ssh_rs::core::keypair::bench_helpers::*;
use vanity_ssh_rs::core::keypair::{BATCH_SIZE, generate_keypair_batch};
use vanity_ssh_rs::core::pattern::{Pattern, public_key_matches_pattern};
use vanity_ssh_rs::worker::generator::generate_and_check_batch;

const MEASUREMENT_SECS: u64 = 10;

fn measurement_time() -> Duration {
    Duration::from_secs(MEASUREMENT_SECS)
}

fn bench_generate_key_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_keypair_batch");
    group.measurement_time(measurement_time());
    group.throughput(Throughput::Elements(BATCH_SIZE as u64));
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
    group.measurement_time(measurement_time());
    group.throughput(Throughput::Elements(BATCH_SIZE as u64));
    group.bench_with_input(
        BenchmarkId::from_parameter(BATCH_SIZE),
        &BATCH_SIZE,
        |b, &size| {
            let pattern = Pattern::Suffix("yee".to_string());
            b.iter(|| {
                let key_pairs = generate_keypair_batch(size);
                let hits = key_pairs
                    .iter()
                    .filter(|kp| public_key_matches_pattern(kp, &pattern))
                    .count();
                black_box(hits)
            })
        },
    );
    group.finish();
}

fn bench_generate_and_check_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_and_check_batch");
    group.measurement_time(measurement_time());
    group.throughput(Throughput::Elements(BATCH_SIZE as u64));
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
    group.measurement_time(measurement_time());
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
    group.measurement_time(measurement_time());
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
    group.measurement_time(measurement_time());
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
    group.measurement_time(measurement_time());
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
