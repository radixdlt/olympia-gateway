#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

keystore_folder="$SCRIPT_DIR/../container-volumes/fullnode/"
keystore_filename="keystore.ks"

if [[ ! -f "$keystore_folder$keystore_filename" ]]; then
    echo "Node key store doesn't exist - creating it..."
    echo

    export $(grep -v '^#' ../.env | xargs) # Import variables from ../.env
    docker run --rm -v "$keystore_folder:/keygen/node" radixdlt/keygen:1.0.0 --keystore="/keygen/node/$keystore_filename" --password="$FULLNODE_KEY_PASSWORD" --keypair-name=node

    echo
    echo "Key store created successfully"
    echo
fi
