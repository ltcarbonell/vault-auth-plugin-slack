#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


echo "Cleaning up.."
$(pwd)/docker-cleanup.sh &> /dev/null

echo "Setting environment variables.."
export SLACK_USER_ACCESS_TOKEN=$(cat $(pwd)/.slack-token)

tmpdir=$(mktemp -d vaultplg)
mkdir "$tmpdir/data"

docker pull hashicorp/vault

set -ex

GOOS=linux go build

docker run --rm -d -p8200:8200 --name vaultplg -v "$(pwd)/$tmpdir/data":/data -v $(pwd):/slack --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG=
{
  "backend": {"file": {"path": "/data"}},
  "listener": [{"tcp": {"address": "0.0.0.0:8200", "tls_disable": true}}],
  "plugin_directory": "/slack",
  "log_level": "trace",
  "disable_mlock": true,
  "api_addr": "http://localhost:8200"
}
' hashicorp/vault server
sleep 1

export VAULT_ADDR=http://localhost:8200

initoutput=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
vault operator unseal $(echo "$initoutput" | jq -r .unseal_keys_hex[0])

export VAULT_TOKEN=$(echo "$initoutput" | jq -r .root_token)

vault write sys/plugins/catalog/auth/slack-auth-plugin \
    sha_256=$(shasum -a 256 vault-auth-plugin-slack | cut -d' ' -f1) \
    command="vault-auth-plugin-slack"

vault auth enable \
    -path="slack" \
    -plugin-name="slack-auth-plugin" plugin

# Configure
vault write auth/slack/config \
    token="${SLACK_USER_ACCESS_TOKEN}"

# Display config
vault read auth/slack/config

vault write auth/slack/login token="${SLACK_USER_ACCESS_TOKEN}"
