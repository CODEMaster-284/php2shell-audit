# php2shell-audit

A Bash script that checks whether your PHP installs are patched against the **PHP2Shell** flaws, two critical unauthenticated remote code execution vulnerabilities fixed on October 21, 2026.

- CVE-2026-109618: RCE via out-of-memory corruption
- CVE-2026-109619: RCE via stale global state

It only reads version information and process metadata. It never changes anything on your systems (see [Docker image scanning](#docker-image-scanning) for the one opt-in exception).

## Patched versions

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

The PHP team says there are no complete mitigations. Updating is the only safe fix.

## Requirements

- Bash 4 or newer (on macOS: `brew install bash`)
- Run as **root** where possible. Without root, some binaries and other users' processes can't be inspected, and the script tells you so.
- Linux for the stale-process check (it reads `/proc`). The version checks also work in Git Bash on Windows.

## Usage

```bash
# Audit this machine
bash audit-php.sh

# Audit many servers over SSH (one user@host per line, key-based login)
bash audit-php.sh hosts.txt

# Audit PHP inside running Docker containers
bash audit-php.sh --docker

# Also audit local Docker images (covers stopped containers)
bash audit-php.sh --images

# Show usage
bash audit-php.sh --help
```

## What it checks

- `php`, `php-fpm`, `php-cgi`, `lsphp` and `frankenphp` binaries
- cPanel (`ea-php*`), Alt-PHP (`/opt/alt/php*`), LiteSpeed (`/usr/local/lsws/lsphp*`), Plesk and Remi PHP paths
- Apache `mod_php` modules (flagged for a manual update)
- Distro changelogs (dpkg/rpm) for backported fixes
- Running processes that still use a PHP binary or `libphp` replaced on disk (stale after an update)
- PHP inside running Docker containers, and optionally local Docker images

## Reading the results

| Status | Meaning |
|--------|---------|
| PATCHED | At or above the fixed version |
| BACKPORT-OK | Version looks old, but the distro changelog mentions the CVEs. Restart services to load the fix |
| VULNERABLE | Below the fixed version. Update now |
| UNSUPPORTED | Branch older than 8.2. No fix exists, so upgrade to a supported branch |
| STALE | A running process still uses a replaced PHP binary or library. Restart the service |
| CHECK | `mod_php` present. Update the matching package and restart Apache |
| UNKNOWN | Couldn't classify. Check php.net |

The script ends with a summary line, for example `Summary: PATCHED=4 UNSUPPORTED=12`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Nothing urgent |
| 1 | Usage or environment error (for example, an unknown option or Docker missing) |
| 2 | At least one `VULNERABLE` or `STALE` finding |

In hosts-file mode, the script exits 2 if any host had such a finding, and 1 if a host could not be reached and nothing urgent was found elsewhere.

## Docker image scanning

`--docker` inspects only **running** containers, using `docker exec`. Stopped containers and unused images still carry their PHP version, so use `--images` to cover them.

`--images` runs `php -v` and `php-fpm -v` inside each local image with `--network none` and a 30-second timeout. This executes the binary in each image, so only use it on images you trust. For that reason it is opt-in.

To find stale bases in your own projects, search your Dockerfiles:

```bash
grep -rn --include=Dockerfile* -E 'FROM .*php' .
```

## After patching

1. Update PHP through your package manager (or rebuild your Docker image from an updated base such as `php:8.4.27` or newer).
2. **Restart PHP-FPM, LiteSpeed or Apache.** A patched package does nothing until the running processes reload. The `STALE` check helps confirm this.
3. Run the script again to confirm.
4. Review recent logs for unusual requests, especially multipart file uploads.

## Limitations

- The script reads versions from binaries. It does not test whether a server or site is exploitable.
- The CLI version may differ from the version your web server runs. The script checks `php-fpm`, `lsphp` and `mod_php`, but confirm against your actual web server setup.
- Container and image versions can't be checked against distro changelogs, so a Debian- or Ubuntu-packaged PHP with a backported fix may show as `VULNERABLE`. Verify those manually.
- `mod_php` is flagged but its version isn't read directly.
- The process check requires `/proc` and root to see every user's processes.
- Always confirm against the official advisory at php.net.

## Disclaimer

Provided as-is, with no warranty. Apart from the opt-in `--images` mode, the script only reads version information and changes nothing on your systems. Review the code before running it on production servers.

## License

MIT