#!/bin/bash

set -e

echo "=========================================="
echo " DNSentinel Demo Reset"
echo "=========================================="

mkdir -p data/demo_backups

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --------------------------------------------------
# Backup current live profiles
# --------------------------------------------------

if [ -d data/profiles ]; then

    mkdir -p "data/demo_backups/profiles_${TIMESTAMP}"

    find data/profiles -maxdepth 1 -type f -name "*.json" \
        -exec cp {} "data/demo_backups/profiles_${TIMESTAMP}/" \;

    echo "[+] Existing host profiles backed up."

fi

# --------------------------------------------------
# Backup organization baseline
# --------------------------------------------------

if [ -f data/profiles/192.168.145.1.json ]; then

    cp data/profiles/192.168.145.1.json \
       "data/demo_backups/host_${TIMESTAMP}.json"

    echo "[+] Existing host baseline backed up."

fi

# --------------------------------------------------
# Remove ONLY live baseline
# --------------------------------------------------

find data/profiles -maxdepth 1 -type f \
    -name "*.json" \
    ! -name "*.backup.json" \
    ! -name "*.contaminated.json" \
    ! -name "experiment_*.json" \
    -delete

rm -f data/organization/organization.json

# --------------------------------------------------
# Recreate directories
# --------------------------------------------------

mkdir -p data/profiles
mkdir -p data/organization

echo
echo "[+] Live demo baseline cleared."
echo "[+] Previous experiments preserved."
echo
echo "Next steps:"
echo "  1. Start DNSentinel"
echo "  2. Generate legitimate DNS traffic"
echo "  3. Generate tunnel traffic"
echo
echo "=========================================="