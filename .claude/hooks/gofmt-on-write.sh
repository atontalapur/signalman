#!/bin/bash
# PostToolUse hook: gofmt any .go file Claude just wrote or edited, so
# formatting never reaches a commit. Silent when gofmt is absent.
command -v gofmt >/dev/null 2>&1 || exit 0
file=$(jq -r '.tool_input.file_path // empty' 2>/dev/null)
case "$file" in
  *.go) gofmt -w "$file" ;;
esac
exit 0
