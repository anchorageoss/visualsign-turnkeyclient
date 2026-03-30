#!/usr/bin/env bash
set -eo pipefail

# Note that the - is included in GIT_BRANCH and BRANCH so we can omit it in case of not being on a branch
GIT_BRANCH="${GITHUB_REF_NAME}-"
if [ "$GIT_BRANCH" = "-" ]; then
  if git symbolic-ref --short HEAD > /dev/null 2>&1; then
    GIT_BRANCH="$(git symbolic-ref --short HEAD)-"
  else
    GIT_BRANCH=
  fi
else
  # remove the : prefix if present
  GIT_BRANCH="${GIT_BRANCH#*:}"
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
REMOTE=$(git remote -v | grep fetch | grep anchorageoss/visualsign-turnkeyclient | awk '{print $1}' | head -1)
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
  # If the merge base is actually just the other branch (there's linear history since the other branch)
  # then maybe the other branch is just old and this is not the real merge base. We just need to pull
  echo "Fetching $REMOTE..." >&2
  git fetch "$REMOTE" > /dev/null
  MERGE_BASE=$(git merge-base "$REMOTE/$DEFAULT_BRANCH" HEAD)
fi
MERGE_HEIGHT=$(git rev-list --count "$MERGE_BASE")
HEIGHT=$(git rev-list --count HEAD)
MERGE_DIFF=$((HEIGHT-MERGE_HEIGHT))
echo "$MAJOR.$MERGE_HEIGHT.$MERGE_DIFF+$BRANCH$SHORT_HASH"
