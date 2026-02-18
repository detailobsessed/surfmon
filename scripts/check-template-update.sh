#!/usr/bin/env bash
# Check if a newer version of the copier template is available.
# Runs as a post-checkout hook — informational only, never blocks.
# Override COPIER_CHECK_INTERVAL in .envrc (default: 900 = 15 min, script fallback: 86400 = 24h).
set -euo pipefail

# Skip file-level restores (arg 3 = 0); runs on branch switch, pull, rebase, clone
[[ "${3:-1}" == "0" ]] && exit 0

# Cooldown: throttle when called as a git hook (3 args); always run for manual poe invocation (0 args)
check_interval="${COPIER_CHECK_INTERVAL:-86400}"
cache_dir="/tmp"
cache_file="${cache_dir}/.copier-template-check-$(echo "$PWD" | (sha1sum 2>/dev/null || shasum) | cut -c1-8)"
if [[ $# -gt 0 && -f "$cache_file" ]]; then
  last_check=$(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo 0)
  now=$(date +%s)
  (( now - last_check < check_interval )) && exit 0
fi

answers=".copier-answers.yml"
[[ -f "$answers" ]] || exit 0

local_version=$(grep "^_commit:" "$answers" | sed "s/_commit: *//;s/^['\"]//;s/['\"]$//") || true
src_path=$(grep "^_src_path:" "$answers" | sed "s/_src_path: *//;s/^['\"]//;s/['\"]$//") || true

[[ -z "$local_version" || -z "$src_path" ]] && exit 0

# Only supports GitHub for now — silently exit for other providers
case "$src_path" in
  gh:*|https://github.com/*) ;;
  *) exit 0 ;;
esac

# Convert copier src_path to GitHub owner/repo
repo="${src_path#gh:}"
repo="${repo#https://github.com/}"
repo="${repo%.git}"

latest=$(curl -s --connect-timeout 3 --max-time 5 \
  "https://api.github.com/repos/${repo}/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//') || true

[[ -z "$latest" ]] && exit 0

# Update cooldown cache after successful API check
touch "$cache_file"

if [[ "$local_version" != "$latest" ]]; then
  cyan='\033[0;36m'; yellow='\033[1;33m'; dim='\033[2m'; bold='\033[1m'; reset='\033[0m'
  # Write to /dev/tty to bypass output capture by hook runners (prek, gt).
  # Falls back to stdout for non-interactive contexts (CI, scripts, tests).
  out="/dev/stdout"
  if (echo -n > /dev/tty) 2>/dev/null; then out="/dev/tty"; fi
  echo "" > "$out"
  echo -e "  ${cyan}ℹ️  Template update available:${reset} ${dim}${local_version}${reset} ${bold}→${reset} ${yellow}${latest}${reset}" > "$out"
  echo -e "  ${dim}Run:${reset} copier update --trust . --skip-answered" > "$out"
  echo -e "  ${dim}Or:${reset}  poe update-template" > "$out"
  echo "" > "$out"
fi
