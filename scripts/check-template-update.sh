#!/usr/bin/env bash
# Check if a newer version of the copier template is available.
# Runs as a post-merge hook — informational only, never blocks.
set -euo pipefail

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

if [[ "$local_version" != "$latest" ]]; then
  cyan='\033[0;36m'; yellow='\033[1;33m'; dim='\033[2m'; bold='\033[1m'; reset='\033[0m'
  echo ""
  echo -e "  ${cyan}ℹ️  Template update available:${reset} ${dim}${local_version}${reset} ${bold}→${reset} ${yellow}${latest}${reset}"
  echo -e "  ${dim}Run:${reset} copier update --trust . --skip-answered"
  echo -e "  ${dim}Or:${reset}  poe update-template"
  echo ""
fi
