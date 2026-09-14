#!/usr/bin/env bash
set -euo pipefail

kubectl set env deployment/nginx-test -n rca-agent-test APP_CONFIG_ENV=production
