#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

if [[ ! -f "$SCRIPT_DIR/../.env" ]]; then
    echo "You must copy the .template.env file to an .env file in the deployment folder so that you can configure docker-compose."
    echo "Please read the section on \"Preparing the toy set-up\" in the deployment readme for more information."
    exit 1
fi
