use nine65::prelude::*;
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::gso_fhe::GSOFHEContext;
use std::time::Instant;

/// Comprehensive Benchmarking Suite for NINE65 v5
/// 
/// Measures:
/// 1. Basic operation performance (encrypt, decrypt, add, mul)
/// 2. Depth scalability (performance at different depths)
/// 3. Memory usage patterns
/// 4. Throughput under various loads
fn main() {
    println!("🚀 Starting NINE65 v5 Comprehensive Benchmarking Suite...\n");

    // Benchmark 1: Basic operation performance
    benchmark_basic_operations();
    
    // Benchmark 2: Depth scalability
    benchmark_depth_scalability();
    
    // Benchmark 3: Throughput measurements
    benchmark_throughput();
    
    // Benchmark 4: Memory usage analysis
    benchmark_memory_usage();
    
    // Benchmark 5: Security parameter performance
    benchmark_security_configs();
    
    println!("\n✅ All benchmarks completed successfully!");
}

fn benchmark_basic_operations() {
    println!("📊 Benchmarking Basic Operations...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Warm up
    let _warmup = ctx.encrypt(42, &keys.public_key);
    
    // Encrypt benchmark
    let iterations = 10;
    let start = Instant::now();
    for i in 0..iterations {
        let _ct = ctx.encrypt(i, &keys.public_key);
    }
    let encrypt_total = start.elapsed();
    let encrypt_avg = encrypt_total / iterations;
    
    // Decrypt benchmark
    let ct = ctx.encrypt(42, &keys.public_key);
    let start = Instant::now();
    for _ in 0..iterations {
        let _result = ctx.decrypt(&ct, &keys.secret_key);
    }
    let decrypt_total = start.elapsed();
    let decrypt_avg = decrypt_total / iterations;
    
    // Add benchmark
    let ct_a = ctx.encrypt(10, &keys.public_key);
    let ct_b = ctx.encrypt(20, &keys.public_key);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ct_sum = ctx.add(&ct_a, &ct_b);
    }
    let add_total = start.elapsed();
    let add_avg = add_total / iterations;
    
    // Mul benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ct_prod = ctx.mul(&ct_a, &ct_b, &keys.secret_key);
    }
    let mul_total = start.elapsed();
    let mul_avg = mul_total / iterations;
    
    println!("  📈 Results (secure_128, {} iterations):", iterations);
    println!("    Encrypt:  {:?} avg ({:?} total)", encrypt_avg, encrypt_total);
    println!("    Decrypt:  {:?} avg ({:?} total)", decrypt_avg, decrypt_total);
    println!("    Add:      {:?} avg ({:?} total)", add_avg, add_total);
    println!("    Mul:      {:?} avg ({:?} total)", mul_avg, mul_total);
    
    println!("  🟢 Basic operations benchmark completed!\n");
}

fn benchmark_depth_scalability() {
    println!("📈 Benchmarking Depth Scalability...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    let depths = vec![1, 5, 10, 20, 30, 40, 50];
    
    for depth in depths {
        let start = Instant::now();
        
        // Create initial ciphertext
        let mut ct_current = ctx.encrypt(2, &keys.public_key);
        let mut expected_result = 2u64;
        
        // Perform depth multiplications
        for _ in 0..depth {
            let ct_two = ctx.encrypt(2, &keys.public_key);
            ct_current = ctx.mul(&ct_current, &ct_two, &keys.secret_key);
            expected_result = (expected_result * 2) % config.t;
        }
        
        // Verify result
        let result = ctx.decrypt(&ct_current, &keys.secret_key);
        assert_eq!(result, expected_result, "Depth {} verification failed", depth);
        
        let elapsed = start.elapsed();
        
        println!("    Depth {}: {:?} (result: {})", depth, elapsed, result);
    }
    
    println!("  🟢 Depth scalability benchmark completed!\n");
}

fn benchmark_throughput() {
    println!("⚡ Benchmarking Throughput...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Measure throughput for different operations
    let operations = 100;
    
    // Encrypt throughput
    let start = Instant::now();
    let mut cts = Vec::new();
    for i in 0..operations {
        cts.push(ctx.encrypt(i as u64, &keys.public_key));
    }
    let encrypt_elapsed = start.elapsed();
    
    // Decrypt throughput
    let start = Instant::now();
    for ct in &cts {
        let _result = ctx.decrypt(ct, &keys.secret_key);
    }
    let decrypt_elapsed = start.elapsed();
    
    // Add throughput (sequential additions)
    let start = Instant::now();
    let mut current_ct = cts[0].clone();
    for i in 1..operations {
        current_ct = ctx.add(&current_ct, &cts[i]);
    }
    let add_elapsed = start.elapsed();
    
    // Calculate rates
    let encrypt_rate = operations as f64 / encrypt_elapsed.as_secs_f64();
    let decrypt_rate = operations as f64 / decrypt_elapsed.as_secs_f64();
    let add_rate = operations as f64 / add_elapsed.as_secs_f64();
    
    println!("  📊 Throughput Results ({} operations):", operations);
    println!("    Encrypt: {:.2} ops/sec", encrypt_rate);
    println!("    Decrypt: {:.2} ops/sec", decrypt_rate);
    println!("    Add:     {:.2} ops/sec", add_rate);
    println!("    Encrypt total: {:?}", encrypt_elapsed);
    println!("    Decrypt total: {:?}", decrypt_elapsed);
    println!("    Add total:     {:?}", add_elapsed);
    
    println!("  🟢 Throughput benchmark completed!\n");
}

fn benchmark_memory_usage() {
    println!("💾 Benchmarking Memory Usage...");
    
    // Note: Actual memory measurement would require platform-specific code
    // For now, we'll just report on the size of key structures
    
    let config = SecureConfig::secure_128().into_config();
    println!("  📋 Configuration Info:");
    println!("    N: {}", config.n);
    println!("    Primes: {}", config.primes.len());
    println!("    Prime bits: ~{}", 64 - config.primes[0].leading_zeros());
    println!("    Plaintext modulus t: {}", config.t);
    
    // Report on polynomial sizes
    let poly_size_bytes = config.n * std::mem::size_of::<u64>();
    println!("    Single polynomial size: ~{} bytes ({:.2} KB)", 
             poly_size_bytes, poly_size_bytes as f64 / 1024.0);
    
    // Report on ciphertext structure
    let num_primes = config.primes.len();
    let ciphertext_size_bytes = num_primes * config.n * std::mem::size_of::<u64>();
    println!("    Ciphertext size: ~{} bytes ({:.2} KB)", 
             ciphertext_size_bytes, ciphertext_size_bytes as f64 / 1024.0);
    
    println!("  🟢 Memory usage benchmark completed!\n");
}

fn benchmark_security_configs() {
    println!("🔐 Benchmarking Security Configurations...");
    
    let configs = [
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("secure_192", SecureConfig::secure_192().into_config()),
    ];
    
    for (name, config) in configs {
        println!("  🛡️  Testing {}:", name);
        
        let inner = RNSFHEContext::new_coeff_domain(&config);
        let ctx = GSOFHEContext::new(inner);
        let keys = ctx.keygen();
        
        // Single operation timing
        let start = Instant::now();
        let ct = ctx.encrypt(42, &keys.public_key);
        let encrypt_time = start.elapsed();
        
        let start = Instant::now();
        let _result = ctx.decrypt(&ct, &keys.secret_key);
        let decrypt_time = start.elapsed();
        
        let ct_a = ctx.encrypt(10, &keys.public_key);
        let ct_b = ctx.encrypt(20, &keys.public_key);
        
        let start = Instant::now();
        let _ct_sum = ctx.add(&ct_a, &ct_b);
        let add_time = start.elapsed();
        
        let start = Instant::now();
        let _ct_prod = ctx.mul(&ct_a, &ct_b, &keys.secret_key);
        let mul_time = start.elapsed();
        
        println!("    Encrypt:  {:?}", encrypt_time);
        println!("    Decrypt:  {:?}", decrypt_time);
        println!("    Add:      {:?}", add_time);
        println!("    Mul:      {:?}", mul_time);
        
        // Security info
        use nine65::security::LWEParams;
        let params = LWEParams::from_config(&config);
        let estimate = params.he_standard_estimate();
        println!("    Security: {} ({} classical bits)", estimate.level_name(), estimate.classical_bits);
    }
    
    println!("  🟢 Security configurations benchmark completed!\n");
}