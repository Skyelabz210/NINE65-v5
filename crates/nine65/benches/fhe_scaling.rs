//! FHE Scaling Benchmark - Full FFT + Nested Parallelism Power
//!
//! Tests homo_mul performance across N=1024, 2048, 4096, 8192
//! to demonstrate O(N log N) FFT scaling vs O(N²) baseline

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use nine65::prelude::*;

fn bench_homo_mul_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("homo_mul_scaling");
    group.sample_size(10);  // Fewer samples for large N

    // Test configurations at different N values
    let configs = [
        ("N=1024", FHEConfig::light()),
        ("N=2048", FHEConfig::he_standard_128()),
        ("N=4096", FHEConfig::standard_128()),
        ("N=8192", FHEConfig::high_192()),
    ];

    for (name, config) in configs.iter() {
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(0xDEADBEEF);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        let ct1 = encryptor.encrypt(42, &mut rng);
        let ct2 = encryptor.encrypt(17, &mut rng);

        group.bench_with_input(BenchmarkId::new("parallel", name), &name, |b, _| {
            b.iter(|| {
                black_box(evaluator.mul(&ct1, &ct2))
            })
        });
    }

    group.finish();
}

fn bench_ntt_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_scaling");
    group.sample_size(20);

    let sizes = [1024, 2048, 4096, 8192];
    let q = 998244353u64;  // NTT-friendly prime

    for &n in &sizes {
        let ntt = NTTEngine::new(q, n);
        let data: Vec<u64> = (0..n).map(|i| (i as u64 * 12345) % q).collect();

        group.bench_with_input(BenchmarkId::new("forward", n), &n, |b, _| {
            b.iter(|| {
                let mut input = data.clone();
                ntt.ntt_inplace(&mut input);
                black_box(input)
            })
        });

        group.bench_with_input(BenchmarkId::new("roundtrip", n), &n, |b, _| {
            b.iter(|| {
                let mut input = data.clone();
                ntt.ntt_inplace(&mut input);
                ntt.intt_inplace(&mut input);
                black_box(input)
            })
        });
    }

    group.finish();
}

fn bench_encrypt_decrypt_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt_scaling");
    group.sample_size(20);

    let configs = [
        (1024, FHEConfig::light()),
        (2048, FHEConfig::he_standard_128()),
        (4096, FHEConfig::standard_128()),
        (8192, FHEConfig::high_192()),
    ];

    for (n, config) in configs.iter() {
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        group.bench_with_input(BenchmarkId::new("encrypt", n), &n, |b, _| {
            b.iter(|| {
                black_box(encryptor.encrypt(42, &mut rng))
            })
        });

        let ct = encryptor.encrypt(42, &mut rng);
        group.bench_with_input(BenchmarkId::new("decrypt", n), &n, |b, _| {
            b.iter(|| {
                black_box(decryptor.decrypt(&ct))
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_homo_mul_scaling,
    bench_ntt_scaling,
    bench_encrypt_decrypt_scaling
);
criterion_main!(benches);
