#!/usr/bin/env bash
set -euo pipefail

date_tag=$(date -u +%Y-%m-%d)
out="docs/PERFORMANCE_BASELINE_${date_tag}.md"

mkdir -p docs

{
  echo "# Performance Baseline (${date_tag})"
  echo
  echo "Results are hardware- and config-dependent; re-run on your target hardware and"
  echo "record updated baselines when publishing."
  echo
  echo "## Environment"
  echo "- OS: $(uname -a)"
  echo "- CPU: $(lscpu | grep -m1 'Model name' | sed 's/^Model name:[[:space:]]*//')"
  echo "- Rust: $(rustc --version)"
  echo "- Cargo: $(cargo --version)"
  echo
  echo "## Commands"
} > "${out}"

run_cmd() {
  local title="$1"
  local cmd_display="$2"
  shift 2

  {
    echo
    echo "### ${title}"
    echo
    echo "Command:"
    echo "\`\`\`"
    echo "${cmd_display}"
    echo "\`\`\`"
    echo
    echo "Output:"
    echo "\`\`\`"
  } >> "${out}"

  bash -lc "${cmd_display}" >> "${out}" 2>&1

  {
    echo "\`\`\`"
    echo
  } >> "${out}"
}

run_cmd "Full Arithmetic Benchmark (light_rns_exact)" \
  "cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic -- --nocapture"

run_cmd "Secure Config FHE Ops (secure_128)" \
  "cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 -- --nocapture"

run_cmd "Secure Config FHE Ops (secure_192)" \
  "cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --nocapture"

run_cmd "Symmetric Max Depth (secure_128)" \
  "cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture"

run_cmd "Symmetric Max Depth (secure_192)" \
  "cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --nocapture"

echo "Wrote ${out}"
