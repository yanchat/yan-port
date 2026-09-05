# Local certificate trust

YanPort intentionally serves exact `.localhost` routes over HTTPS. Caddy issues
the leaf certificates from its private local certificate authority (CA), and
YanPort's first-machine cutover installs that root into the Linux system trust
store. A valid route therefore depends on several independent conditions:

1. Caddy is reachable and presents a certificate.
2. The leaf chains to Caddy's active root.
3. The requested hostname appears in the leaf's DNS SAN extension.
4. The active root is the same certificate installed in the effective system
   trust store.
5. The client application uses that trust store or has received the root by
   another explicit mechanism.
6. The application's configured loopback upstream is listening.

`yan-port trust status` reports these conditions separately. An unavailable
upstream does not mean the certificate is invalid, and a certificate accepted
by `curl` does not prove that an isolated browser profile accepts it.

`yan-port doctor` includes the same trust diagnostics in its report. Missing or
stale system trust, active-root mismatches, certificate-chain or hostname
failures, TLS failures, and Caddy admin-socket errors are problems. A stopped
upstream and uncertainty about embedded-browser trust are warnings, so they do
not make an otherwise healthy `doctor` result fail.

## Inspect and export the active CA

Inspect every registered route:

```bash
yan-port trust status
yan-port trust status --json
```

Inspect one exact registered route:

```bash
yan-port trust status --host studio.example.localhost
```

YanPort fetches the public root certificate through Caddy's permissioned Unix
admin socket. It reports the on-disk path for diagnosis, but it does not weaken
the permissions on Caddy's private data directory or read private keys.

Export the active public root for an explicit import:

```bash
yan-port trust export --output ./yan-port-root.crt
```

An exact canonical root-only PEM is an idempotent success. A file containing
different bytes—even the same certificate followed by another certificate, a
private key, or trailing data—is refused unless `--force` is given. YanPort
writes replacements atomically and refuses symbolic links. Always compare the
printed SHA-256 fingerprint with `trust status` before importing the
certificate elsewhere.

When no HTTPS routes are registered, YanPort reports trust as not applicable
and does not query Caddy's lazy PKI endpoint. Apply the first route before
exporting the active root.

## Repair Linux system trust

If `trust status` reports a missing or stale system anchor, export the active
root, verify its fingerprint, and deliberately replace the YanPort anchor:

```bash
yan-port trust export --output ./yan-port-root.crt
sudo install -o root -g root -m 0644 \
  ./yan-port-root.crt \
  /usr/local/share/ca-certificates/yan-port-local-root.crt
sudo update-ca-certificates
yan-port trust status
```

System-trust inspection and repair support the Debian-style Linux layout used
by YanPort's native-Caddy deployment; macOS and Windows trust stores are
unsupported.

## Chrome and Chromium

Chrome and Chromium certificate verification has changed across releases and
distributions. A system-trusted private CA may still be unavailable to a
particular application or managed profile. First confirm that YanPort reports a
healthy leaf, SAN, chain, and system store. Then use the browser's supported
certificate-management interface to import the exported root into the exact
profile that needs it, and restart the browser.

Some Linux Chromium-family applications use an NSS SQLite database. Only when
the application's documentation identifies an exact existing profile database,
inspect it before changing it:

```bash
profile=/exact/path/to/profile
test -f "${profile}/cert9.db"
certutil -L -d "sql:${profile}"
```

After checking the active fingerprint and confirming that any existing
`YanPort Local CA` entry is not a conflicting stale certificate, a manual import
is:

```bash
certutil -A \
  -d "sql:${profile}" \
  -n "YanPort Local CA" \
  -t "C,," \
  -a \
  -i ./yan-port-root.crt
certutil -L -d "sql:${profile}" -n "YanPort Local CA" -a
```

Do not run this against guessed paths or every profile. YanPort does not
discover or modify NSS/browser profiles. Refer to the
[NSS `certutil` documentation](https://nss-crypto.org/reference/security/nss/legacy/tools/certutil/index.html)
for the database and trust-flag contract.

## Electron and Codex

Electron embeds Chromium, and an application can use separate sessions or
custom certificate verification. Electron documents both the verification
result and per-session verification hook in its
[session API](https://www.electronjs.org/docs/latest/api/session). The Electron
application owner—not YanPort—must decide whether and how a session consumes a
private development CA.

Codex's in-app browser can reject a local CA even when system tools accept it.
YanPort does not assume a stable internal Codex profile path. Use the exported
root only with a supported, explicitly identified import mechanism, restart the
application after changing trust, or use the direct HTTP fallback while
developing. Do not bypass certificate errors globally.

## Containers and CI

Containers and CI jobs are separate trust environments. Export the public root
and add it to the image or job's documented CA store, or point that client's
explicit CA-file setting at the export. Do not mount Caddy's admin socket or
private data directory into a container merely to obtain the certificate.

Trusting a local development CA in a reusable public image broadens trust more
than intended. Prefer a development-only image layer or a job-scoped secret/artifact,
and remove it from production builds.

## Direct HTTP fallback

When browser-profile trust cannot be configured, connect directly to the
application's leased loopback port:

```text
http://localhost:<port>
```

This bypasses YanPort routing and TLS. It is useful for diagnosis and local
review, but it has a different origin from the canonical HTTPS hostname, so
cookies, secure-context APIs, CORS behavior, redirects, and stored browser state
may differ. The HTTPS route remains the canonical development URL.

The Caddy endpoints used by YanPort are documented in the
[Caddy API](https://caddyserver.com/docs/api).
