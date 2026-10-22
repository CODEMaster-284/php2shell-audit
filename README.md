# php2shell-audit

A read-only Bash script that checks whether your PHP installs are patched against the **PHP2Shell** flaws, two critical unauthenticated remote code execution vulnerabilities fixed on October 21, 2026.

- CVE-2026-109618: RCE via out-of-memory corruption
- CVE-2026-109619: RCE via stale global state

## Patched versions

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

The PHP team says there are no complete mitigations. Updating is the only safe fix.

## Usage

```bash
# Audit this machine
bash audit-php.sh

# Audit many servers over SSH (one user@host per line, key-based login)
bash audit-php.sh hosts.txt

# Audit PHP inside running Docker containers
bash audit-php.sh --docker
```

## What it checks

- `php`, `php-fpm`, `php-cgi` and `frankenphp` binaries
- cPanel, Plesk and Remi PHP paths
- Apache `mod_php` modules (flagged for a manual update)
- Distro changelogs (dpkg/rpm) for backported fixes

## Reading the results

| Status | Meaning |
|--------|---------|
| PATCHED | At or above the fixed version |
| BACKPORT-OK | Version looks old, but the distro changelog mentions the CVEs. Restart services to load the fix |
| VULNERABLE | Below the fixed version. Update now |
| UNSUPPORTED | Branch older than 8.2. Upgrade to a supported branch |
| CHECK | `mod_php` present. Update the matching package and restart Apache |
| UNKNOWN | Couldn't classify. Check php.net |

## After patching

1. Update PHP through your package manager (or rebuild your Docker image from an updated base).
2. **Restart PHP-FPM or Apache.** A patched package does nothing until the running processes reload.
3. Run the script again to confirm.
4. Review recent logs for unusual requests.

## Limitations

- The script reads versions from binaries. It does not test whether a server is exploitable.
- The CLI version may differ from the version your web server runs, so check your FPM or Apache setup.
- Always confirm against the official advisory at php.net.

## Disclaimer

Provided as-is, with no warranty. The script only reads version information and changes nothing on your systems. Review the code before running it on production servers.

## License

MIT
