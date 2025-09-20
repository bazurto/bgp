#!/usr/bin/env bash
set -euo pipefail

# Demo script for README: generates a key, lists keys, and exports by ID
WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

KEystore="$WORKDIR/keystore"
mkdir -p "$KEystore"

BIN=$(pwd)/bgp

echo "Using keystore: $KEystore"

echo "1) Generate key for demo user 'demo'"
$BIN -keystore "$KEystore" keygen -name demo -email demo@example.com

echo
echo "2) List keys (shows Key ID):"
$BIN -keystore "$KEystore" list

echo
echo "3) Extract Key ID from listing and export the key by ID"
ID=$($BIN -keystore "$KEystore" list -v | sed -n 's/.*Key ID: \([0-9a-fA-F]\+\).*/\1/p' | head -n1)
echo "Found Key ID: $ID"
$BIN -keystore "$KEystore" export -id "$ID" -out "$WORKDIR/demo_export.pem"
echo "Exported to: $WORKDIR/demo_export.pem"

echo
echo "Demo complete"
