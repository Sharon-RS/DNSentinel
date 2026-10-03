#!/bin/bash

echo "=========================================="
echo " DNSentinel Demo Reset"
echo "=========================================="

# Remove live learned profiles
rm -f data/profiles/*.json
rm -f data/organization/organization.json

# Recreate required directories
mkdir -p data/profiles
mkdir -p data/organization

echo
echo "[+] DNSentinel state cleared."
echo "[+] Ready for a fresh demonstration."
echo
echo "Next:"
echo "  1. Start DNSentinel"
echo "  2. Generate normal DNS traffic"
echo "  3. Generate tunnel traffic"
echo "  4. Observe the risk scores"
echo "=========================================="
