#!/usr/bin/env bash
# audit-php.sh - check PHP installs against the Oct 21 2026 "PHP2Shell" fixes
# (CVE-2026-109618, CVE-2026-109619).
#
# Patched upstream versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35
#
# Usage:
#   ./audit-php.sh                 # audit this machine
#   ./audit-php.sh hosts.txt       # audit many servers over SSH (one user@host per line)
#   ./audit-php.sh --docker        # audit PHP inside running Docker containers
#
# Status meanings:
#   PATCHED       version is at or above the upstream fixed release
#   BACKPORT-OK   version looks old, but the distro changelog mentions the CVEs
#   VULNERABLE    below the fixed release and no backport found - update now
#   UNSUPPORTED   branch older than 8.2; no fix known, upgrade the branch
#   UNKNOWN       couldn't classify (e.g. a newer branch) - check php.net
#
# Note: the CLI version is not always what your web server runs. This script
# also looks for php-fpm binaries. mod_php (Apache) is flagged separately.

set -u

CVES="CVE-2026-109618 CVE-2026-109619"
declare -A FIXED=( ["8.5"]="8.5.12" ["8.4"]="8.4.27" ["8.3"]="8.3.36" ["8.2"]="8.2.35" )

# ---------- local audit ----------
local_audit() {
  local bins=() seen="" b real ver branch fixed owner status note

  for name in php php-fpm php-cgi frankenphp; do
    p=$(command -v "$name" 2>/dev/null) && bins+=("$p")
  done
  for glob in \
    /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/sbin/php[0-9]*-fpm \
    /usr/local/bin/php* /usr/local/sbin/php-fpm* \
    /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm; do
    for f in $glob; do [ -x "$f" ] && [ -f "$f" ] && bins+=("$f"); done
  done

  for b in "${bins[@]}"; do
    real=$(readlink -f "$b" 2>/dev/null || echo "$b")
    case " $seen " in *" $real "*) continue ;; esac
    seen="$seen $real"

    ver=$("$real" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -z "$ver" ] && continue
    branch=${ver%.*}
    fixed=${FIXED[$branch]:-}
    note=""

    if [ -n "$fixed" ]; then
      if [ "$(printf '%s\n%s\n' "$ver" "$fixed" | sort -V | head -1)" = "$fixed" ]; then
        status="PATCHED"
      elif backport_found "$real"; then
        status="BACKPORT-OK"; note="changelog mentions fix; restart services to load it"
      else
        status="VULNERABLE"; note="update to >= $fixed"
      fi
    else
      case "$branch" in
        5.*|7.*|8.0|8.1) status="UNSUPPORTED"; note="EOL branch - move to 8.2+ (8.4/8.5 preferred)" ;;
        *)               status="UNKNOWN";     note="check php.net/security" ;;
      esac
    fi
    printf '%-12s %-8s %s  %s\n' "$status" "$ver" "$real" "$note"
  done

  # Apache mod_php modules (the version isn't read directly, so just flag them)
  for m in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
           /usr/lib/httpd/modules/libphp*.so; do
    [ -f "$m" ] && printf '%-12s %-8s %s  %s\n' "CHECK" "-" "$m" \
      "mod_php present - update the matching php package and restart Apache"
  done

  [ ${#bins[@]} -eq 0 ] && echo "No PHP binaries found."
  return 0
}

# Does the distro changelog for the package owning $1 mention our CVEs?
backport_found() {
  local f="$1" pkg
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

# ---------- entry points ----------
if [ "${1:-}" = "--local" ]; then   # used internally over SSH
  local_audit; exit 0
fi

if [ "${1:-}" = "--docker" ]; then
  command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
  docker ps --format '{{.Names}}' | while read -r c; do
    out=$(docker exec "$c" sh -c 'for b in php php-fpm; do command -v $b >/dev/null 2>&1 && $b -v 2>/dev/null | head -1; done' 2>/dev/null)
    [ -n "$out" ] && printf '== container: %s\n%s\n' "$c" "$out"
  done
  echo
  echo "Compare against fixed versions: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
  echo "Fix = rebuild the image from an updated base, then redeploy."
  exit 0
fi

if [ -n "${1:-}" ] && [ -f "$1" ]; then
  while read -r host; do
    case "$host" in ''|\#*) continue ;; esac
    echo "=== $host"
    ssh -o ConnectTimeout=8 -o BatchMode=yes "$host" 'bash -s -- --local' < "$0" 2>&1 \
      || echo "  (could not connect or run on $host)"
  done < "$1"
  exit 0
fi

echo "=== $(hostname)"
local_audit
