#!/usr/bin/env bash
set -euo pipefail

# Note that the - is included in GIT_BRANCH and BRANCH so we can omit it in case of not being on a branch
GIT_BRANCH="${GITHUB_REF_NAME:-}-"
if [ "$GIT_BRANCH" = "-" ]; then
  if git symbolic-ref --short HEAD > /dev/null 2>&1; then
    GIT_BRANCH="$(git symbolic-ref --short HEAD)-"
  else
    GIT_BRANCH=
  fi
fi

SHORT_HASH=$(git rev-parse --short=12 HEAD)
# remove invalid characters
# shellcheck disable=SC2001
BRANCH="$(echo "$GIT_BRANCH" | sed 's/[^a-zA-Z0-9-]/-/g')"
MAJOR=0

if [ "$BRANCH" = "main-" ] || [ "$BRANCH" = "master-" ]; then
  HEIGHT=$(git rev-list --count HEAD)
  echo "$MAJOR.$HEIGHT.0+${BRANCH}$SHORT_HASH"
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
MERGE_DIFF=$((HEIGHT-MERGE_HEIGHT))
echo "$MAJOR.$MERGE_HEIGHT.$MERGE_DIFF+$BRANCH$SHORT_HASH"
