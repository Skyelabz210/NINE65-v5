use nine65::params::secure_configs::SecureConfig;
use nine65::params::security_estimator::{CostModel, LatticeSecurityEstimator, SecretDistribution};
use std::env;

fn log2_u64(value: u64) -> f64 {
    (value as f64).log2()
}

fn log2_product(primes: &[u64]) -> f64 {
    primes.iter().map(|&p| log2_u64(p)).sum()
}

fn log2_product_floor_bits(primes: &[u64]) -> u32 {
    primes.iter().map(|&p| 64 - p.leading_zeros()).sum()
}

fn parse_args() -> (String, CostModel) {
    let mut format = "markdown".to_string();
    let mut cost_model = CostModel::CoreSVP;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                if let Some(value) = args.next() {
                    format = value;
                }
            }
            "--cost-model" => {
                if let Some(value) = args.next() {
                    match value.as_str() {
                        "core" | "core-svp" => cost_model = CostModel::CoreSVP,
                        "matzov" => cost_model = CostModel::MATZOV,
                        _ => {}
                    }
                }
            }
            "--help" | "-h" => {
                println!("Usage: security_estimator_baseline [--format markdown|csv] [--cost-model core|matzov]");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    (format, cost_model)
}

fn main() {
    let (format, cost_model) = parse_args();
    let estimator = LatticeSecurityEstimator::new(cost_model);

    let configs = [
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("secure_192", SecureConfig::secure_192().into_config()),
        ("secure_256", SecureConfig::secure_256().into_config()),
    ];

    if format == "csv" {
        println!("config,n,log2(q),effective_bits,cost_model");
        for (name, config) in configs {
        let log_q_bits = log2_product_floor_bits(&config.primes);
        let estimate = estimator.estimate(
            config.n,
            log_q_bits,
            SecretDistribution::Ternary,
            config.security_bits as u32,
        );
        println!(
            "{},{},{:.2},{},{}",
            name,
            config.n,
            log2_product(&config.primes),
            estimate.effective_bits,
            match cost_model {
                CostModel::CoreSVP => "core-svp",
                CostModel::MATZOV => "matzov",
                }
            );
        }
        return;
    }

    println!("| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |");
    println!("| --- | --- | --- | --- | --- |");
    for (name, config) in configs {
        let log_q_bits = log2_product_floor_bits(&config.primes);
        let estimate = estimator.estimate(
            config.n,
            log_q_bits,
            SecretDistribution::Ternary,
            config.security_bits as u32,
        );
        println!(
            "| {} | {} | {:.2} | {} | {} |",
            name,
            config.n,
            log2_product(&config.primes),
            estimate.effective_bits,
            match cost_model {
                CostModel::CoreSVP => "core-svp",
                CostModel::MATZOV => "matzov",
            }
        );
    }
}
