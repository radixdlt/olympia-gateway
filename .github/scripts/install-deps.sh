#!/usr/bin/env bash

set -euo pipefail

curl https://raw.githubusercontent.com/OpenAPITools/openapi-generator/v5.3.0/bin/utils/openapi-generator-cli.sh > /usr/bin/openapi-generator
chmod 755 /usr/bin/openapi-generator

apt-get update -y -qq
apt-get install -y -qq maven jq
