# Deploying agent-police

The service runs as one container behind a reverse proxy you already operate.
It publishes no HTTP port — the proxy reaches it over a shared docker network.
UDP/53 is the only published port, and only if you run DNS canaries.

Everything site-specific lives in `.env`, which is not committed. Start from
`.env.example`.

## 1. Configure

```bash
cp .env.example .env
$EDITOR .env
```

At minimum set `AGENT_POLICE_IMAGE`, `AGENT_POLICE_CANARY_BASE` and
`AGENT_POLICE_PROXY_NETWORK`. Leave the DNS variables empty until step 3.

## 2. Run

**Do not build on the host that serves it.** A build competes with production
traffic for CPU, disk and memory. Images are built and tested in CI
(`.github/workflows/ci.yml`); `docker-compose.yml` has no `build:` section, so
`--build` cannot be triggered by accident.

```bash
docker compose pull
docker compose up -d
docker compose ps
```

Pin a specific image instead of `latest` when you want a known artifact:

```bash
AGENT_POLICE_IMAGE=ghcr.io/<owner>/agent-police:sha-<commit> docker compose up -d
```

Rollback is the same command with the previous tag. The volume is untouched,
so canary history survives.

### What guarantees the image was tested

Two independent checks:

1. CI runs `pytest -q` on **3.12 and 3.14** — the interpreter the image ships
   and the one the project is developed on. This exists because a suite
   passing on one said nothing about production running the other.
2. The image's own first stage re-runs the suite on `python:3.12-slim` during
   the build and fails the build if it fails. The runtime stage copies a
   marker out of that stage, which is what stops BuildKit pruning it away — so
   the guarantee travels with the image, not just with the pipeline.

```bash
docker compose exec agent-police cat /app/.tests-passed
```

Both need outbound DNS: one guard test resolves a real public hostname to
prove the SSRF check admits it. Building without DNS needs `SKIP_TESTS=1`,
which forfeits guarantee 2 — only do that after running the suite yourself.

## 3. The reverse-proxy site

`deploy/Caddyfile.snippet` holds two additive blocks. Adapt the hostname to
match `AGENT_POLICE_CANARY_BASE`, then:

```bash
CF=/path/to/your/Caddyfile
CADDY=your-caddy-container

cp "$CF" "$CF.bak-$(date +%Y%m%dT%H%M%S)"
cat deploy/Caddyfile.snippet >> "$CF"

docker exec "$CADDY" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec "$CADDY" caddy reload   --config /etc/caddy/Caddyfile --adapter caddyfile
```

The snippet deliberately routes `/c/*` on **plain HTTP** to the app instead of
redirecting it. A canary callback is evidence; a caller that never follows the
redirect to HTTPS would otherwise go unrecorded.

Verify, then roll back by restoring the backup and reloading if needed:

```bash
curl -s https://security.example.com/api/health
```

### Do not put the collector behind a WAF or bot protection

Serve the collector hostname as a **DNS-only** record, not through a CDN proxy.

Bot Fight Mode, Browser Integrity Check and WAF managed rules all target
exactly the client profile a canary needs to record: automated, odd or absent
user-agent, coming from scanner infrastructure, fetching a URL nobody should
know. Measured on one deployment, a CDN proxy silently dropped 1 callback in 8
from a clean-reputation IP — real harvesting infrastructure has worse
reputation, so the loss would be higher.

A proxy also terminates TLS, so JA3/JA4 fingerprints — the signal that
correlates scattered hits to one operator — never reach the collector.

If the collector must sit behind a proxy, at least exempt `/c/*` from bot
protection and caching. Caller attribution already prefers `CF-Connecting-IP`
over `X-Forwarded-For`, because most proxies *append* to XFF and a
caller-supplied leftmost entry would otherwise be recorded as the source.

## 4. DNS canaries (optional)

HTTP canaries work as soon as step 3 is done. DNS canaries additionally catch
scanners that resolve a harvested hostname without ever fetching it — a wider
net, but weaker attribution: a DNS hit shows the recursive resolver, never the
party that asked it.

They need the canary zone delegated to this host:

```
c.example.com.    IN  NS  ns-canary.example.com.
ns-canary         IN  A   <SERVER_IPV4>        ; DNS-only, never proxied
```

The NS target must resolve to this host. A CDN-proxied name resolves to the
CDN's anycast addresses, which do not run this collector.

Then fill in the DNS variables in `.env`, open the port, and restart:

```bash
ufw allow 53/udp comment "agent-police canary DNS"
docker compose up -d
```

Order matters: leave `AGENT_POLICE_CANARY_DNS` empty until the delegation is
live and UDP/53 is reachable. With a zone configured but unreachable, the
provider issues DNS canaries that can never fire — worse than falling back to
HTTP ones, because nothing reports the gap.

Verify:

```bash
# Unknown tokens answer NXDOMAIN; that is correct.
dig +short test.c.example.com @<SERVER_IPV4>

# The apex answers NOERROR/NODATA, never NXDOMAIN. Under RFC 8020 an NXDOMAIN
# at the apex denies the whole subtree, and compliant resolvers would stop
# asking about the token names the zone exists for.
dig +noall +comments c.example.com @<SERVER_IPV4> | grep status

# The delegation itself, through the public chain.
dig +short NS c.example.com @1.1.1.1
```

## What the service holds

| Data | Where | Lifetime |
|---|---|---|
| API keys submitted for an audit | worker thread memory only | the audit |
| Audit reports | process memory | 30 minutes |
| Canary tokens and hits | SQLite in the volume | until purged |
| Prompts, responses, request bodies | nowhere | never stored |

`agentpolice/server/jobs.py` implements those claims and
`tests/test_server.py::TestAuditFlow` checks them, including an assertion that
a submitted key never appears in any response.

## Guards

- `agentpolice/server/guard.py` rejects non-public targets before an audit
  starts: no loopback, private, link-local (cloud metadata) or bare-IP hosts.
- `RouterClient(require_public_peer=True)` re-checks the address the socket
  actually landed on for every response, closing DNS rebinding.
- Per-IP budgets: 5 audits, 30 preflights, 120 inspections per hour.
- At most 6 audits in flight across all visitors.
