#!/usr/bin/env bash
# ==============================================================================
# scripts/demo-angels.sh - Milestone 6 Demonstration Runner
# Multi-Harness Skill Neutrality Proof & Three-Device / clj-einsum Angels Demo
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

exec clojure -M -m bitecho.main demo-angels "$@"
