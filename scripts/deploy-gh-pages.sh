#!/usr/bin/env bash
# Publish a built site to the gh-pages branch with plain git.
#
# Usage:
#   deploy-gh-pages.sh production <site-dir>
#       Publish <site-dir> at the branch root. Stale production files are
#       deleted, pr-preview/ is left alone, and CNAME + .nojekyll are written.
#   deploy-gh-pages.sh preview <pr-number> <site-dir>
#       Publish <site-dir> into pr-preview/pr-<pr-number>/ and nothing else.
#   deploy-gh-pages.sh cleanup <pr-number>
#       Remove pr-preview/pr-<pr-number>/ and nothing else.
#
# Environment:
#   DEPLOY_REPO_URL      repository to publish to
#                        (default: https://github.com/$GITHUB_REPOSITORY.git)
#   DEPLOY_BRANCH        branch to publish to (default: gh-pages)
#   DEPLOY_CNAME         custom domain written to CNAME (default: casvancooten.com)
#   DEPLOY_MAX_ATTEMPTS  push attempts before giving up (default: 5)
#   GITHUB_TOKEN         used for https://github.com/ through an environment-only
#                        git config entry, so it is never written to disk
#   GITHUB_SHA           source commit, recorded in the commit message
#
# A deploy that changes nothing exits 0 without committing. A rejected push
# (another deploy landed first) is retried after a fetch and rebase.

set -euo pipefail

log() { printf 'deploy-gh-pages: %s\n' "$*"; }
die() { printf 'deploy-gh-pages: error: %s\n' "$*" >&2; exit 1; }
usage() {
  sed -n '4,11s/^# \{0,1\}//p' "$0" >&2
  exit 2
}

valid_pr() { [[ "$1" =~ ^[1-9][0-9]{0,8}$ ]]; }

check_site_dir() {
  [[ -d "$1" ]] || die "site directory not found: $1"
  [[ -f "$1/index.html" ]] || die "$1 has no index.html; refusing to publish it"
  local links
  links=$(find "$1" -type l -print -quit) || die "could not scan $1"
  [[ -z "$links" ]] || die "$1 contains symlinks ($links); refusing to publish it"
}

# --- arguments ---------------------------------------------------------------

mode=${1:-}
pr=""
site=""
target=""
case "$mode" in
  production)
    [[ $# -eq 2 ]] || usage
    site=$2
    ;;
  preview)
    [[ $# -eq 3 ]] || usage
    valid_pr "$2" || die "PR number must be a positive integer, got '$2'"
    pr=$2
    site=$3
    target="pr-preview/pr-$pr"
    ;;
  cleanup)
    [[ $# -eq 2 ]] || usage
    valid_pr "$2" || die "PR number must be a positive integer, got '$2'"
    pr=$2
    target="pr-preview/pr-$pr"
    ;;
  *)
    usage
    ;;
esac

if [[ -n "$site" ]]; then
  check_site_dir "$site"
  site=$(cd "$site" && pwd -P)
  if [[ "$mode" == production && -e "$site/pr-preview" ]]; then
    die "$site contains pr-preview/, which is reserved for PR previews"
  fi
fi

repo_url=${DEPLOY_REPO_URL:-}
if [[ -z "$repo_url" ]]; then
  [[ -n "${GITHUB_REPOSITORY:-}" ]] || die "set DEPLOY_REPO_URL or GITHUB_REPOSITORY"
  repo_url="https://github.com/${GITHUB_REPOSITORY}.git"
fi
branch=${DEPLOY_BRANCH:-gh-pages}
git check-ref-format --branch "$branch" >/dev/null 2>&1 || die "invalid branch name: $branch"
cname=${DEPLOY_CNAME:-casvancooten.com}
[[ "$cname" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid DEPLOY_CNAME: $cname"
max_attempts=${DEPLOY_MAX_ATTEMPTS:-5}
[[ "$max_attempts" =~ ^[1-9][0-9]?$ ]] || die "DEPLOY_MAX_ATTEMPTS must be 1-99"
command -v rsync >/dev/null || die "rsync is required"

# --- git setup ---------------------------------------------------------------

export GIT_TERMINAL_PROMPT=0
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  basic=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    echo "::add-mask::$basic"
  fi
  n=${GIT_CONFIG_COUNT:-0}
  export "GIT_CONFIG_KEY_$n=http.https://github.com/.extraheader"
  export "GIT_CONFIG_VALUE_$n=AUTHORIZATION: basic $basic"
  export GIT_CONFIG_COUNT=$((n + 1))
  unset basic n
fi

tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gh-pages.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
work="$tmp/work"

log "cloning $branch"
git clone --quiet --depth 1 --single-branch --no-tags --branch "$branch" -- "$repo_url" "$work" \
  || die "could not clone branch $branch"
cd "$work"
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'

# Previews only ever live in real directories inside the work tree.
if [[ -n "$target" ]]; then
  for p in pr-preview "$target"; do
    if [[ -L "$p" ]] || { [[ -e "$p" ]] && [[ ! -d "$p" ]]; }; then
      die "$p on $branch is not a plain directory; refusing to touch it"
    fi
  done
fi

# --- apply the change --------------------------------------------------------

source_sha=""
if [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  source_sha=" from ${GITHUB_SHA:0:12}"
fi

# --checksum: compare content, not size + mtime, since git only sees content.
case "$mode" in
  production)
    rsync -a --checksum --delete --exclude=.git --exclude=/pr-preview/ -- "$site"/ "$work"/
    printf '%s\n' "$cname" > CNAME
    : > .nojekyll
    git add -A -- . ':(exclude)pr-preview'
    message="Deploy production${source_sha}"
    ;;
  preview)
    mkdir -p -- "$target"
    rsync -a --checksum --delete --exclude=.git -- "$site"/ "$target"/
    git add -A -- "$target"
    message="Deploy preview for PR #${pr}${source_sha}"
    ;;
  cleanup)
    git rm -r -q --ignore-unmatch -- "$target"
    rm -rf -- "$target"
    message="Remove preview for PR #${pr}"
    ;;
esac

if git diff --cached --quiet; then
  log "no changes; $branch is already up to date"
  exit 0
fi

# Refuse to commit anything outside the scope of this mode.
git diff --cached --name-only --no-renames -z > "$tmp/changed"
while IFS= read -r -d '' path; do
  if [[ "$mode" == production ]]; then
    [[ "$path" != pr-preview/* ]] || die "production deploy would change $path; aborting"
  else
    [[ "$path" == "$target"/* ]] || die "$mode would change $path outside $target/; aborting"
  fi
done < "$tmp/changed"

log "$mode: $(git diff --cached --shortstat)"
git commit --quiet --no-verify -m "$message"

# --- push, retrying when another deploy got there first -----------------------

attempt=1
until git push --quiet origin "HEAD:refs/heads/$branch"; do
  if (( attempt >= max_attempts )); then
    die "push still rejected after $max_attempts attempts"
  fi
  log "push rejected (attempt $attempt of $max_attempts); fetching and rebasing"
  sleep $((attempt * 2 + RANDOM % 3))
  git fetch --quiet origin "$branch"
  if ! git rebase --quiet "origin/$branch"; then
    git rebase --abort || true
    die "could not rebase onto the updated $branch"
  fi
  attempt=$((attempt + 1))
done

log "published $(git rev-parse --short HEAD) to $branch"
