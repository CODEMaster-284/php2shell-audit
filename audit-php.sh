#!/usr/bin/env bash
# audit-php.sh v2 - check PHP installs against the Oct 21 2026 "PHP2Shell" fixes
# (CVE-2026-109618, CVE-2026-109619).
#
# Patched upstream versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35
#
# Usage:
#   ./audit-php.sh                 # audit this machine
#   ./audit-php.sh hosts.txt       # audit many servers over SSH (one user@host per line)
#   ./audit-php.sh --docker        # audit PHP inside RUNNING containers
#   ./audit-php.sh --images        # also audit local Docker images (runs `php -v` in each,
#                                  #   with --network none; covers stopped containers' images)
#   ./audit-php.sh --help
#
# Run as root where possible: without it, some binaries and the process check
# only see your own files/processes.
#
# Status meanings:
#   PATCHED       version is at or above the upstream fixed release
#   BACKPORT-OK   version looks old, but the distro changelog mentions the CVEs
#   VULNERABLE    below the fixed release and no backport found - update now
#   UNSUPPORTED   branch older than 8.2; no fix exists, upgrade the branch
#   UNKNOWN       couldn't classify (e.g. a newer branch) - check php.net
#   STALE         a running process still uses a PHP binary/library that was
#                 replaced on disk - restart the service to load the fix
#   CHECK         mod_php present; update the matching package and restart Apache
#
# Exit codes: 0 = nothing urgent, 1 = usage/environment error,
#             2 = at least one VULNERABLE or STALE finding.

set -u

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "bash 4+ is required (on macOS: brew install bash)." >&2
  exit 1
fi

CVES="CVE-2026-109618 CVE-2026-109619"
declare -A FIXED=( ["8.5"]="8.5.12" ["8.4"]="8.4.27" ["8.3"]="8.3.36" ["8.2"]="8.2.35" )
declare -A COUNT=()
STATUS=""; NOTE=""

# ---------- helpers ----------

# Print a finding and count it.
report() {  # status version path [note]
  COUNT[$1]=$(( ${COUNT[$1]:-0} + 1 ))
  printf '%-12s %-8s %s  %s\n' "$1" "$2" "$3" "${4:-}"
}

# Pull a PHP version out of `php -v` / `frankenphp version` output.
extract_version() {
  local out="$1" v
  v=$(printf '%s\n' "$out" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)
  [ -z "$v" ] && v=$(printf '%s\n' "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  printf '%s' "$v"
}

# Version flag differs for frankenphp.
version_output() {  # binary-path
  local b="$1"
  case "${b##*/}" in
    frankenphp*) "$b" version 2>/dev/null | head -2 ;;
    *)           "$b" -v 2>/dev/null | head -1 ;;
  esac
}

# Does the distro changelog for the package owning $1 mention our CVEs?
backport_found() {
  local f="$1" pkg c
  if command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$pkg" ]; then
    for c in $CVES; do
      zcat -f /usr/share/doc/"$pkg"/changelog.Debian.gz 2>/dev/null | grep -q "$c" && return 0
    done
  fi
  if command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$f" 2>/dev/null | head -1) && [ -n "$pkg" ]; then
    for c in $CVES; do
      rpm -q --changelog "$pkg" 2>/dev/null | grep -q "$c" && return 0
    done
  fi
  return 1
}

# Sets STATUS and NOTE for a version. $2 (optional) is a host path for backport lookup.
classify() {
  local ver="$1" path="${2:-}" branch fixed
  branch=${ver%.*}
  fixed=${FIXED[$branch]:-}
  NOTE=""
  if [ -n "$fixed" ]; then
    if [ "$(printf '%s\n%s\n' "$ver" "$fixed" | sort -V | head -1)" = "$fixed" ]; then
      STATUS="PATCHED"
    elif [ -n "$path" ] && backport_found "$path"; then
      STATUS="BACKPORT-OK"; NOTE="changelog mentions fix; restart services to load it"
    else
      STATUS="VULNERABLE"; NOTE="update to >= $fixed"
    fi
  else
    case "$branch" in
      5.*|7.*|8.0|8.1) STATUS="UNSUPPORTED"; NOTE="EOL branch - move to 8.2+ (8.4/8.5 preferred)" ;;
      *)               STATUS="UNKNOWN";     NOTE="check php.net/security" ;;
    esac
  fi
}

# ---------- local audit ----------
local_audit() {
  local bins=() name p f b real ver m
  declare -A SEEN=()

  shopt -s nullglob

  for name in php php-fpm php-cgi lsphp frankenphp; do
    p=$(command -v "$name" 2>/dev/null) && bins+=("$p")
  done

  bins+=(
    /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/sbin/php[0-9]*-fpm
    /usr/local/bin/php* /usr/local/sbin/php-fpm* /usr/local/bin/frankenphp
    /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/lsphp
    /opt/cpanel/ea-php*/root/usr/sbin/php-fpm
    /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/bin/lsphp /opt/alt/php*/usr/sbin/php-fpm
    /usr/local/lsws/lsphp*/bin/lsphp
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm
  )

  for b in "${bins[@]}"; do
    [ -f "$b" ] && [ -x "$b" ] || continue
    real=$(readlink -f "$b" 2>/dev/null || echo "$b")
    [ -n "${SEEN[$real]:-}" ] && continue
    SEEN[$real]=1

    ver=$(extract_version "$(version_output "$real")")
    [ -z "$ver" ] && continue

    classify "$ver" "$real"
    report "$STATUS" "$ver" "$real" "$NOTE"
  done

  # Apache mod_php modules (version isn't read directly, so just flag them)
  for m in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
           /usr/lib/httpd/modules/libphp*.so; do
    [ -f "$m" ] && report "CHECK" "-" "$m" "mod_php present - update the matching php package and restart Apache"
  done

  shopt -u nullglob

  [ ${#SEEN[@]} -eq 0 ] && echo "No PHP binaries found."
  stale_check
  return 0
}

# Running processes still using a PHP binary/library that was replaced on disk.
stale_check() {
  [ -d /proc/self ] || return 0
  [ "$(id -u)" -ne 0 ] && echo "note: not root - process check only sees your own processes"

  local d pid exe base
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    base=${exe##*/}
    case "$base" in
      php*|lsphp*|frankenphp*)
        case "$exe" in
          *"(deleted)") report "STALE" "-" "pid $pid  $exe" "binary replaced after start - restart the service" ;;
        esac ;;
      httpd*|apache2*)
        if grep -qE 'libphp[^ ]*\.so.*\(deleted\)' "$d/maps" 2>/dev/null; then
          report "STALE" "-" "pid $pid  $exe" "mod_php library replaced after start - restart Apache"
        fi ;;
    esac
  done
}

# ---------- docker audit ----------
docker_audit() {  # [--images]
  local with_images="${1:-}" c b arg out ver img
  command -v docker >/dev/null 2>&1 || { echo "docker not found"; return 1; }

  while read -r c; do
    [ -z "$c" ] && continue
    for b in php php-fpm php-cgi frankenphp; do
      arg="-v"; [ "$b" = "frankenphp" ] && arg="version"
      out=$(docker exec "$c" sh -c "command -v $b >/dev/null 2>&1 && $b $arg 2>/dev/null | head -2" 2>/dev/null)
      ver=$(extract_version "$out")
      [ -z "$ver" ] && continue
      classify "$ver" ""
      report "$STATUS" "$ver" "container:$c ($b)" "$NOTE"
    done
  done < <(docker ps --format '{{.Names}}')

  if [ "$with_images" = "--images" ]; then
    echo "--- local images (covers stopped containers) ---"
    while read -r img; do
      case "$img" in ''|*"<none>"*) continue ;; esac
      for b in php php-fpm; do
        out=$(timeout 30 docker run --rm --network none --entrypoint "$b" "$img" -v 2>/dev/null | head -1)
        ver=$(extract_version "$out")
        [ -z "$ver" ] && continue
        classify "$ver" ""
        report "$STATUS" "$ver" "image:$img ($b)" "$NOTE"
      done
    done < <(docker images --format '{{.Repository}}:{{.Tag}}' | sort -u)
  else
    echo "(stopped containers and unused images are not checked; add --images)"
  fi

  echo
  echo "Fixed versions: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
  echo "Fix = rebuild from an updated base image (e.g. php:8.4.27 or newer), then redeploy."
  echo "Tip: grep your Dockerfiles for 'FROM php' and 'FROM .*php' to find stale bases."
  return 0
}

summary() {
  local k out=""
  for k in PATCHED BACKPORT-OK VULNERABLE UNSUPPORTED UNKNOWN STALE CHECK; do
    [ -n "${COUNT[$k]:-}" ] && out="$out $k=${COUNT[$k]}"
  done
  echo
  echo "Summary:${out:- no PHP found}"
  if [ -n "${COUNT[VULNERABLE]:-}" ] || [ -n "${COUNT[STALE]:-}" ]; then
    echo "ACTION NEEDED: update VULNERABLE installs and restart services for STALE ones."
    return 2
  fi
  return 0
}

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- entry points ----------
case "${1:-}" in
  -h|--help) usage; exit 0 ;;

  --local)   # used internally over SSH
    local_audit; summary; exit $? ;;

  --docker)
    docker_audit "${2:-}" || exit 1
    summary; exit $? ;;

  --images)
    docker_audit --images || exit 1
    summary; exit $? ;;
esac

if [ -n "${1:-}" ]; then
  if [ ! -f "$1" ]; then
    echo "Unknown option or missing hosts file: $1" >&2
    exit 1
  fi
  overall=0
  while read -r host; do
    case "$host" in ''|\#*) continue ;; esac
    echo "=== $host"
    ssh -o ConnectTimeout=8 -o BatchMode=yes "$host" 'bash -s -- --local' < "$0" 2>&1
    rc=$?
    case $rc in
      0) ;;
      2) overall=2 ;;
      *) echo "  (could not connect or run on $host, exit $rc)"; [ $overall -eq 0 ] && overall=1 ;;
    esac
  done < "$1"
  exit $overall
fi

echo "=== $(hostname)"
local_audit
summary
exit $?