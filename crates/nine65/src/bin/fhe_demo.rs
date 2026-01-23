use nine65::prelude::*;
use std::time::Instant;

fn expect_eq(label: &str, got: u64, expected: u64) {
    if got != expected {
        eprintln!("{label} failed: got {got}, expected {expected}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "Usage: fhe_demo [--a <u64>] [--b <u64>] [--config <name>] [--seed <u64> | --os-seed]\n\
         \n\
         Options:\n\
           --a <u64>           First plaintext (default: 17)\n\
           --b <u64>           Second plaintext (default: 25)\n\
           --config <name>     he_standard_128 | standard_128 | high_192 | light (default: he_standard_128)\n\
           --seed <u64>        Deterministic RNG seed (default: 42)\n\
           --os-seed           Use OS entropy for RNG\n\
           -h, --help          Show this help\n"
    );
}

fn parse_u64(value: &str, flag: &str) -> u64 {
    value.parse::<u64>().unwrap_or_else(|_| {
        eprintln!("Invalid value for {flag}: {value}");
        std::process::exit(2);
    })
}

fn main() {
    let mut a = 17u64;
    let mut b = 25u64;
    let mut config_name = String::from("he_standard_128");
    let mut seed: Option<u64> = Some(42);
    let mut use_os_seed = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            print_usage();
            return;
        }

        let (flag, value) = if let Some((left, right)) = arg.split_once('=') {
            (left, Some(right.to_string()))
        } else {
            (arg.as_str(), None)
        };

        match flag {
            "--a" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --a");
                    std::process::exit(2);
                }
                a = parse_u64(&v, "--a");
            }
            "--b" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --b");
                    std::process::exit(2);
                }
                b = parse_u64(&v, "--b");
            }
            "--config" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --config");
                    std::process::exit(2);
                }
                config_name = v;
            }
            "--seed" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --seed");
                    std::process::exit(2);
                }
                seed = Some(parse_u64(&v, "--seed"));
            }
            "--os-seed" => {
                use_os_seed = true;
            }
            _ => {
                eprintln!("Unknown option: {flag}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    if use_os_seed && seed.is_some() {
        eprintln!("Use either --seed or --os-seed, not both");
        std::process::exit(2);
    }

    let config = match config_name.as_str() {
        "light" => FHEConfig::light(),
        "he_standard_128" | "he-standard-128" => FHEConfig::he_standard_128(),
        "standard_128" | "standard-128" => FHEConfig::standard_128(),
        "high_192" | "high-192" => FHEConfig::high_192(),
        other => {
            eprintln!("Unknown config: {other}");
            print_usage();
            std::process::exit(2);
        }
    };

    println!("NINE65 FHE demo");
    println!("Note: demo uses deterministic Shadow Entropy unless --os-seed is set.");

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = if use_os_seed {
        ShadowHarvester::from_os_seed()
    } else {
        ShadowHarvester::with_seed(seed.unwrap_or(42))
    };

    let start = Instant::now();
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let keygen_ms = start.elapsed().as_millis();

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

    let ct_a = encryptor.encrypt(a, &mut rng);
    let ct_b = encryptor.encrypt(b, &mut rng);

    let ct_sum = evaluator.add(&ct_a, &ct_b);
    let sum = decryptor.decrypt(&ct_sum);
    expect_eq("add", sum, a + b);

    let ct_diff = evaluator.sub(&ct_b, &ct_a);
    let diff = decryptor.decrypt(&ct_diff);
    expect_eq("sub", diff, b - a);

    let ct_neg = evaluator.negate(&ct_a);
    let neg = decryptor.decrypt(&ct_neg);
    expect_eq("neg", neg, (config.t - a) % config.t);

    let ct_add_plain = evaluator.add_plain(&ct_a, 10);
    let add_plain = decryptor.decrypt(&ct_add_plain);
    expect_eq("add_plain", add_plain, a + 10);

    let ct_mul_plain = evaluator.mul_plain(&ct_a, 3);
    let mul_plain = decryptor.decrypt(&ct_mul_plain);
    expect_eq("mul_plain", mul_plain, (a * 3) % config.t);

    println!("Parameters: n={}, q={}, t={}, eta={}", config.n, config.q, config.t, config.eta);
    println!("Keygen: {} ms", keygen_ms);
    println!("Results:");
    println!("  {} + {} = {}", a, b, sum);
    println!("  {} - {} = {}", b, a, diff);
    println!("  -{} = {} (mod {})", a, neg, config.t);
    println!("  {} + 10 = {}", a, add_plain);
    println!("  {} * 3 = {}", a, mul_plain);
    println!("Status: PASS");
}
