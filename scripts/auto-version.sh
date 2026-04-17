#!/usr/bin/env bash
set -euo pipefail

# Resolve the raw branch name (before sanitization) so that comparisons against
# "main"/"master" can't be fooled by branches like `main.` or `main_` that
# collapse to `main-` after character sanitization.
#
# Precedence:
#   1. GITHUB_HEAD_REF — set on pull_request events; contains the PR source
#      branch (GITHUB_REF_NAME would be "<N>/merge" here, which is useless).
#   2. GITHUB_REF_NAME — set on push/workflow_dispatch events; the branch name.
#   3. git symbolic-ref --short HEAD — local developer runs.
RAW_BRANCH="${GITHUB_HEAD_REF:-}"
if [ -z "$RAW_BRANCH" ]; then
  RAW_BRANCH="${GITHUB_REF_NAME:-}"
fi
if [ -z "$RAW_BRANCH" ]; then
  if git symbolic-ref --short HEAD > /dev/null 2>&1; then
    RAW_BRANCH="$(git symbolic-ref --short HEAD)"
  fi
fi

SHORT_HASH=$(git rev-parse --short=12 HEAD)
MAJOR=0

# Sanitized branch for use in semver build metadata (allowed: [0-9A-Za-z-]).
# The trailing "-" is a separator before SHORT_HASH; omitted when branch is empty.
if [ -n "$RAW_BRANCH" ]; then
  # shellcheck disable=SC2001
  BRANCH_META="$(echo "$RAW_BRANCH" | sed 's/[^a-zA-Z0-9-]/-/g')-"
else
  BRANCH_META=
fi

if [ "$RAW_BRANCH" = "main" ] || [ "$RAW_BRANCH" = "master" ]; then
  HEIGHT=$(git rev-list --count HEAD)
  echo "$MAJOR.$HEIGHT.0+${BRANCH_META}$SHORT_HASH"
  exit 0
fi

# Which main do we diff against?
REMOTE=$(git remote -v | awk '/[[:space:]]\(fetch\)/ && /anchorageoss\/visualsign-turnkeyclient/ {print $1; exit}')
if [ -z "$REMOTE" ]; then
  REMOTE="origin"
fi

# Try main first, fall back to master
DEFAULT_BRANCH="main"
if ! git rev-parse --verify "$REMOTE/$DEFAULT_BRANCH" > /dev/null 2>&1; then
  DEFAULT_BRANCH="master"
fi

MERGE_BASE=$(git merge-base "$REMOTE/$DEFAULT_BRANCH" HEAD)
if [ "$MERGE_BASE" = "$(git rev-parse "$REMOTE/$DEFAULT_BRANCH")" ]; then
  # Local remote-tracking ref may be stale — fetch to get the real merge base
  echo "Fetching $REMOTE..." >&2
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    git fetch "$REMOTE" >&2
  else
    git fetch "$REMOTE" > /dev/null 2>&1 || echo "Warning: fetch from $REMOTE failed, continuing with local ref" >&2
  fi
  MERGE_BASE=$(git merge-base "$REMOTE/$DEFAULT_BRANCH" HEAD)
fi
MERGE_HEIGHT=$(git rev-list --count "$MERGE_BASE")
HEIGHT=$(git rev-list --count HEAD)
MERGE_DIFF=$((HEIGHT - MERGE_HEIGHT))
echo "$MAJOR.$MERGE_HEIGHT.$MERGE_DIFF+${BRANCH_META}$SHORT_HASH"
