use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};
use vanity_ssh_rs::core::keypair::generate_keypair_batch;
use vanity_ssh_rs::core::pattern::{Pattern, public_key_matches_pattern};

const SWEEP_SIZES: &[usize] = &[25, 50, 100, 250, 500];
const MEASUREMENT_SECS: u64 = 10;

fn measurement_time() -> Duration {
    Duration::from_secs(MEASUREMENT_SECS)
}

fn bench_generate_key_batch_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_keypair_batch_sweep");
    group.measurement_time(measurement_time());
    for &size in SWEEP_SIZES {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let key_pairs = generate_keypair_batch(size);
                black_box(key_pairs)
            })
        });
    }
    group.finish();
}

fn bench_check_suffix_batch_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("public_key_matches_pattern_batch_sweep");
    group.measurement_time(measurement_time());
    for &size in SWEEP_SIZES {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let pattern = Pattern::Suffix("yee".to_string());
            b.iter(|| {
                let key_pairs = generate_keypair_batch(size);
                let hits = key_pairs
                    .iter()
                    .filter(|kp| public_key_matches_pattern(kp, &pattern))
                    .count();
                black_box(hits)
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_generate_key_batch_sweep,
    bench_check_suffix_batch_sweep,
);
criterion_main!(benches);
