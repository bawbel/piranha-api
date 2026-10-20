# redirect-worker

A Cloudflare Worker that answers for the retired host `api.piranha.bawbel.io`.

The hosted PiranhaDB API was stopped. Released scanner wheels print
`https://api.piranha.bawbel.io/records/AVE-...` in findings and cannot be changed, and older
bawbel-mcp releases call that host at runtime. This Worker keeps those links working.

**Status: not deployed.** This folder is the code and its tests. Until the steps below are done
in the Cloudflare dashboard, the old host still has no DNS record and every old link fails.

## What it does

| Request path | Response |
|---|---|
| `/records` or `/records/...` | `301` to `https://api.aveproject.org` with the same path and query |
| anything else | `302` to `https://github.com/bawbel/piranha-api` |

Examples:

```text
/records/AVE-2026-00002          301  https://api.aveproject.org/records/AVE-2026-00002
/records?limit=1                 301  https://api.aveproject.org/records?limit=1
/health, /docs, /scan, /stats/*  302  https://github.com/bawbel/piranha-api
```

Both destinations are constants in `worker.js`. Nothing in the request (host, header, query)
chooses where a redirect goes, so the Worker is not an open redirect. The tests try twelve
open-redirect shapes and check that every result stays on the two destinations. The 302 is a
302 so the fallback can move later. Write endpoints that used to exist (`/feedback/*`,
`/scan`, `/registry-scan/ingest`) are retired; a client that posts to them now lands on the
repository.

Clients: `urllib` follows these redirects. `httpx` does not unless you pass
`follow_redirects=True`.

## Why a Worker and not a redirect rule

Redirect Rules need Cloudflare to terminate TLS for the hostname. The free Universal
certificate covers the apex and one level (`*.bawbel.io`), and `api.piranha.bawbel.io` is two
levels deep, so HTTPS would fail before any rule ran. Cloudflare's Workers documentation says a
Workers Custom Domain generates a certificate for the exact hostname, including multi-level
subdomains, with no separate Advanced Certificate Manager subscription.

## Tests

```bash
cd redirect-worker
node --test        # Node 18 or later, no dependencies
```

CI runs the same command on pull requests that touch this folder.

## Deploy (maintainer, Cloudflare dashboard)

1. **Check the DNS tab for `api.piranha`.** On 2026-10-20 a public DNS query returned
   NXDOMAIN for CNAME, A and AAAA, and there is no wildcard on bawbel.io, so none should exist.
   The query shows only what resolves, so look at the dashboard too. If a record exists, delete
   it first: a Custom Domain cannot be created over a CNAME, and a CNAME to a deprovisioned host
   is a takeover route into anything that fetches from this hostname.
2. Workers & Pages, Create, Worker. Name it `piranha-redirect`. Replace the sample code with the
   contents of `worker.js` (the file has only a default export, so it pastes as is). Deploy.
3. In the Worker: Settings, Domains & Routes, Add, Custom Domain, enter
   `api.piranha.bawbel.io`. Cloudflare creates the DNS record and the certificate.
4. Check the Workers free-plan daily request limit on the account. Old links will generate
   far fewer requests than the limit.

## Verify

Certificate issuance can take a few minutes. Check each one at a time.

```bash
# the certificate covers the hostname (subject and issuer lines, no handshake error)
curl -sv -o /dev/null https://api.piranha.bawbel.io/ 2>&1 | grep -iE 'subject:|issuer:|SSL certificate verify'

# a single record follows through to the AVE API
curl -sIL https://api.piranha.bawbel.io/records/AVE-2026-00002 | grep -iE '^(HTTP|location)'
# expect: 301 to https://api.aveproject.org/records/AVE-2026-00002, then the API's own status

# the list call older bawbel-mcp releases make
curl -sIL 'https://api.piranha.bawbel.io/records?limit=1' | grep -iE '^(HTTP|location)'

# everything else lands on the repository
curl -sI https://api.piranha.bawbel.io/health | grep -iE '^(HTTP|location)'
# expect: 302 to https://github.com/bawbel/piranha-api
```

The last status of the record check is the AVE API's. The redirect is correct even when that
API is down: on 2026-10-20 it returned 500 at the root and 503 on `/records`.

## Roll back

Delete the Custom Domain from the Worker. The generated certificate stays until it is removed
by hand under SSL/TLS, Edge Certificates.

## After it is deployed

Only then can this repository's README say that old links redirect (see PIR-1 in the ecosystem
runbook: do not claim it before the verify steps above pass).
