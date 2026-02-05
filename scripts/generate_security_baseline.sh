#!/usr/bin/env bash
set -euo pipefail

date_tag=$(date -u +%Y-%m-%d)
out="docs/LATTICE_ESTIMATOR_BASELINE_${date_tag}.md"

mkdir -p docs

{
  echo "# Lattice Estimator Baseline (${date_tag})"
  echo
  echo "Command:"
  echo "- cargo run -p nine65 --bin security_estimator_baseline"
  echo
  echo "## Environment"
  echo "- OS: $(uname -a)"
  echo "- Rust: $(rustc --version)"
  echo "- Cargo: $(cargo --version)"
  echo
  echo "## Results (Core-SVP)"
  cargo run -p nine65 --bin security_estimator_baseline -- --format markdown
} > "${out}"

echo "Wrote ${out}"
