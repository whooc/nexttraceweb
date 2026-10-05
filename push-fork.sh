#!/usr/bin/env bash
# Push this local working copy to your own GitHub fork.
#
# Usage:
#   bash push-fork.sh                      # fork via GitHub UI first, then run this
#   GITHUB_TOKEN=ghp_xxx bash push-fork.sh # create/update the fork automatically
#
# The token needs the `repo` scope (classic) or Contents:write + Administration:write
# (fine-grained) so it can create the fork and push to it.

set -euo pipefail

OWNER="${FORK_OWNER:-whooc}"
REPO="${FORK_REPO:-nexttraceweb}"
BRANCH="${FORK_BRANCH:-neutral-dark-theme}"
UPSTREAM="https://github.com/nxtrace/nexttraceweb.git"

cd "$(dirname "$0")"

echo "==> repo:    $OWNER/$REPO"
echo "==> branch:  $BRANCH"
echo ""

if [ ! -d .git ]; then
    echo "!! Not a git repository. Run this from the cloned nexttraceweb checkout." >&2
    exit 1
fi

# Keep the upstream remote around so future upstream changes are easy to pull.
if ! git remote get-url upstream >/dev/null 2>&1; then
    git remote add upstream "$UPSTREAM"
    echo "==> added 'upstream' remote -> $UPSTREAM"
fi

if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "==> creating fork via API (or reusing the existing one)..."
    status=$(curl -s -o /tmp/fork-resp.json -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/nxtrace/nexttraceweb/forks")

    case "$status" in
        202) echo "    fork is being created" ;;
        422) echo "    fork already exists, continuing" ;;
        *)   echo "!! fork request returned HTTP $status:"; cat /tmp/fork-resp.json; echo ;;
    esac

    # Give GitHub a moment to finish provisioning the new repository.
    sleep 5
    git remote set-url origin "https://${OWNER}:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git"
    echo "==> origin now points at the fork (token embedded for this push only)"
fi

echo "==> pushing $BRANCH..."
git push -u origin "$BRANCH"

if [ -n "${GITHUB_TOKEN:-}" ]; then
    # Do not leave the credential sitting in .git/config.
    git remote set-url origin "https://github.com/${OWNER}/${REPO}.git"
    echo "==> scrubbed token from .git/config"
fi

echo ""
echo "Done. Open a PR against upstream if you want it merged:"
echo "  https://github.com/nxtrace/nexttraceweb/compare/master...${OWNER}:${REPO}:${BRANCH}?expand=1"
