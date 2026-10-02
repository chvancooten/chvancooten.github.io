#!/usr/bin/env bash
# Purge Cloudflare's cache for the site once GitHub Pages serves a new deploy.
#
# Usage:
#   purge-cloudflare.sh <site-dir> <url-path>
#       <site-dir> is the build that was just published, <url-path> where it was published ("/" for production,
#       "/pr-preview/pr-<N>/" for a preview). The script waits until GitHub Pages itself (not Cloudflare) serves
#       that build's index.html at <url-path>, then purges the whole zone. Purging right after the push to gh-pages
#       would be too early: Pages publishes a minute or so later, and Cloudflare would cache the old page again.
#
# Environment:
#   CLOUDFLARE_ZONE_ID    the zone of the site
#   CLOUDFLARE_API_TOKEN  an API token with only the Zone > Cache Purge permission, for that zone
#                         Without both, the script prints a notice and exits 0 (nothing to purge with).
#   PURGE_HOST            the site's host name (default: casvancooten.com)
#   PURGE_ORIGIN_IP       a GitHub Pages address to reach the origin past Cloudflare (default: 185.199.108.153)
#   PURGE_WAIT            seconds to wait for Pages to publish (default: 360). After that the script purges anyway
#                         and warns.
#
# Exits 1 when Cloudflare does not confirm the purge.

set -euo pipefail

log() { printf 'purge-cloudflare: %s\n' "$*"; }
die() { printf '::error::purge-cloudflare: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 2 ]] || { sed -n '/^# Usage:/,/^#$/{/^#$/d; s/^# \{0,1\}//; p;}' "$0" >&2; exit 2; }
site=$1
path=$2
[[ -f "$site/index.html" ]] || die "$site has no index.html"
[[ "$path" == /* && "$path" == */ ]] || die "the URL path must start and end with /: $path"

if [[ -z "${CLOUDFLARE_ZONE_ID:-}" || -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "::notice::Cloudflare cache not purged: set the CLOUDFLARE_ZONE_ID variable and the CLOUDFLARE_API_TOKEN secret to purge it after each deploy"
  exit 0
fi
[[ "$CLOUDFLARE_ZONE_ID" =~ ^[0-9a-f]{32}$ ]] || die "CLOUDFLARE_ZONE_ID is not a zone id (32 hex digits)"

host=${PURGE_HOST:-casvancooten.com}
ip=${PURGE_ORIGIN_IP:-185.199.108.153}
wait_s=${PURGE_WAIT:-360}
want=$(sha256sum "$site/index.html" | cut -d' ' -f1)

# The origin answers for the custom domain at its own address. -k: its certificate need not be for this host
# (Cloudflare terminates TLS for visitors). The query string makes a fresh request past GitHub's own CDN cache.
log "waiting up to ${wait_s}s for GitHub Pages to serve the new ${path}index.html"
deadline=$((SECONDS + wait_s))
served=false
# Each request and each pause is cut to the time left, so the wait never runs past PURGE_WAIT.
left() { local n=$((deadline - SECONDS)); ((n < $1)) || n=$1; ((n > 1)) || n=1; echo "$n"; }
while ((SECONDS < deadline)); do
  got=$(curl -sk --max-time "$(left 20)" --resolve "$host:443:$ip" \
    "https://$host${path}index.html?purge=$RANDOM$SECONDS" | sha256sum | cut -d' ' -f1) || true
  if [[ "$got" == "$want" ]]; then served=true; break; fi
  ((SECONDS < deadline)) || break
  sleep "$(left 10)"
done
if $served; then
  log "GitHub Pages serves the new build"
else
  echo "::warning::GitHub Pages did not serve the new ${path}index.html within ${wait_s}s; purging anyway, so Cloudflare may cache the old page again until its TTL runs out"
fi

# The token goes in through a here-string, never on the command line.
response=$(curl -sS --max-time 30 -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/purge_cache" \
  -H @- -H "Content-Type: application/json" --data '{"purge_everything":true}' \
  <<< "Authorization: Bearer $CLOUDFLARE_API_TOKEN") || die "the purge request failed"
if [[ "$(jq -r '.success' <<< "$response" 2>/dev/null)" != "true" ]]; then
  die "Cloudflare did not purge the cache: $(jq -c '.errors' <<< "$response" 2>/dev/null || echo 'unreadable response')"
fi
log "purged the Cloudflare cache for the zone"
