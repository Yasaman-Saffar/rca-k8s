#!/usr/bin/env bash
# Easy failure #1: remove a required env var -> CrashLoopBackOff
# Target: deployment/nginx-test in namespace rca-agent-test
# Symptom: container logs "FATAL: APP_CONFIG_ENV is required but not set", pod CrashLoopBackOff
set -euo pipefail

kubectl set env deployment/nginx-test -n rca-agent-test APP_CONFIG_ENV-
