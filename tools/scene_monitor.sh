#!/bin/bash
# PS4 Scene Monitor — polls key sources and logs changes to scene_watch.log
# Usage:
#   ./scene_monitor.sh --once     single pass (default if cron absent)
#   ./scene_monitor.sh --loop     hourly loop in foreground (for termux no-cron env)
#   ./scene_monitor.sh --now       run pass then exit (aliases --once)

set -u
BASE="$(dirname "$(readlink -f "$0")")/.."
LOG="$BASE/scene_watch.log"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() { date '+%Y-%m-%d %H:%M:%S %Z'; }

log() {
  local line="$1"
  printf '%s | %s\n' "$(ts)" "$line" >> "$LOG"
}

# GitHub API helper: last commit date for a repo's default branch
gh_last_commit() {
  local repo="$1"
  curl -s --max-time 20 "https://api.github.com/repos/$repo/commits?per_page=1" \
    | grep -m1 '"date"' | sed -E 's/.*"date": "([^"]+)".*/\1/'
}

# Structured: list recent commit msgs (best signal for "added FW support")
gh_recent_msgs() {
  local repo="$1" n="${2:-6}"
  curl -s --max-time 25 "https://api.github.com/repos/$repo/commits?per_page=$n" \
    | grep '"message"' | sed -E 's/.*"message": "(.*)",?/\1/' | head -n "$n"
}

gh_latest_release() {
  local repo="$1"
  curl -s --max-time 20 "https://api.github.com/repos/$repo/releases/latest" \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/'
}

# state store
STATE="$BASE/.scene_watch_state"
mkdir -p "$(dirname "$STATE")"
touch "$STATE"

check_repo() {
  local key="$1" repo="$2"
  local cur prev
  cur="$(gh_last_commit "$repo")"
  prev="$(grep -F "last=$key " "$STATE" 2>/dev/null | awk '{print $2}' | cut -d= -f2)"
  if [ -n "$cur" ]; then
    if [ "$cur" != "$prev" ]; then
      log "UPDATE [$key] $repo new commit: $cur (was: ${prev:-none})"
      MSG="$(gh_recent_msgs "$repo" 3 | tr '\n' '|')"
      log "      [$key] recent msgs: $MSG"
    else
      log "OK     [$key] $repo no change ($cur)"
    fi
    sed -i "/last=$key /d" "$STATE"
    echo "last=$key $cur" >> "$STATE"
  else
    log "ERR    [$key] $repo API failed/unreachable"
  fi
}

log "=== SCENE MONITOR PASS START ==="

# Core scene repos
check_repo cssfontface ntfargo/CSSFontFace-Exploit
check_repo webkitty ArabPixel/WebKitty
check_repo vue TanKanT97/vue-after-free_TanKanTZBuild
check_repo vue_upstream Vuemony/vue-after-free
check_repo poops bd-un-jb   # Gezine BD-UN-JB (payloads/poops) — mirrors may vary
check_repo goldhen GoldHEN/GoldHEN
check_repo ps4linux ps4-linux/ps4-linux-loader

# Release tags (GoldHEN & friends use tags as version markers)
rel="$(gh_latest_release GoldHEN/GoldHEN)"
if [ -n "$rel" ]; then
  prev_rel="$(grep -F "rel=goldhen " "$STATE" 2>/dev/null | awk '{print $2}' | cut -d= -f2)"
  if [ "$rel" != "$prev_rel" ]; then
    log "RELEASE [goldhen] GoldHEN new tag: $rel (was: ${prev_rel:-none})"
    sed -i "/rel=goldhen /d" "$STATE"
    echo "rel=goldhen $rel" >> "$STATE"
  fi
fi

# News via RSS feeds (Reddit/known blogs that mirror scene news)
for feed in \
  "https://www.reddit.com/r/ps4homebrew/new/.rss?limit=5" \
  "https://www.reddit.com/r/ps5homebrew/new/.rss?limit=5"; do
  n="$(curl -s --max-time 20 "$feed" | grep -c '<entry>' 2>/dev/null || echo 0)"
  log "FEED   [$feed] entries=$n"
done

log "=== SCENE MONITOR PASS END ==="
echo "logged to $LOG"

# ---- mode handling ----
MODE="${1:---once}"
if [ "$MODE" = "--loop" ]; then
  while true; do
    sleep 3600
    bash "$0" --once
  done
fi