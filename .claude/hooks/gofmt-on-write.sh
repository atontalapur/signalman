#!/bin/bash
# PostToolUse hook for Edit|Write. If the touched file is Go and not gofmt
# clean, format it and exit 2 so the message reaches Claude, which must
# re-read the file before editing it again. Skips are reported, not silent.
file=$(jq -r '.tool_input.file_path // empty' 2>/dev/null)
case "$file" in *.go) ;; *) exit 0 ;; esac
command -v gofmt >/dev/null 2>&1 || { echo "gofmt-on-write: gofmt not installed, $file not formatted" >&2; exit 0; }
if ! out=$(gofmt -l "$file" 2>&1); then
  echo "gofmt-on-write: gofmt failed on $file: $out" >&2; exit 2
fi
if [ -n "$out" ]; then
  gofmt -w "$file" && echo "gofmt-on-write: reformatted $file; re-read it before the next edit" >&2; exit 2
fi
exit 0
