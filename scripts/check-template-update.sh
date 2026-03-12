#!/usr/bin/env bash
# Post-checkout hook adapter for copier check-update.
# Informational only — never blocks checkout.
[[ "${3:-1}" == "0" ]] && exit 0  # skip file-level restores
copier check-update || true
