#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

./scripts/ensure-env-exists.sh
./scripts/ensure-key-generated.sh

docker-compose --profile fullnode --profile network-gateway-image up
