#!/bin/bash
# Wrapper for Custom AI Agent (Burp): claude 2.1.285 doesn't know
# --skip-git-repo-check and --output-last-message. Strip the former,
# emulate the latter. stderr silenced in -p mode only (banner noise).
REAL=/home/debian/.local/bin/claude
printf "%s %s\n" "$(date -Is)" "$*" >> /tmp/claude-burp-calls.log
args=(); outfile=""; prev=""; oneshot=0
for a in "$@"; do
  if [ "$prev" = "--output-last-message" ]; then outfile="$a"; prev=""; continue; fi
  case "$a" in
    --skip-git-repo-check) prev=""; continue ;;
    --output-last-message) prev="$a"; continue ;;
    -p|--print|--prompt) oneshot=1; args+=("$a"); prev="$a" ;;
    *) args+=("$a"); prev="$a" ;;
  esac
done
if [ -n "$outfile" ]; then
  out=$("$REAL" "${args[@]}" 2>/dev/null)
  printf '%s\n' "$out" > "$outfile"
  printf '%s\n' "$out"
elif [ "$oneshot" = 1 ]; then
  exec "$REAL" "${args[@]}" 2>/dev/null
else
  exec "$REAL" "${args[@]}"
fi
