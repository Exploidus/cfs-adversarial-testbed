#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo " Building NASA cFS Adversarial Security Testbed                  "
echo "================================================================="

make clean
make all

echo ""
echo "================================================================="
echo " Running Automated Qualification Scenarios                       "
echo "================================================================="

./cfs_testbed
