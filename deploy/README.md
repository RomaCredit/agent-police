# Deploying agent-police on this host

The service runs as its own container on the existing `romaapicom_hub-net`
network and is reached through the existing `hub-caddy`. Nothing in
`docker-compose.hub.yml` is modified.

## 1. The container

**Do not build on this host.** It serves production traffic for other
services; a build competes for its CPU, disk and memory. Images are built and
tested in CI (`.github/workflows/ci.yml`) and pulled here. `docker-compose.yml`
has no `build:` section, so `--build` cannot be triggered by accident.

```bash
cd /root/agent-police
docker compose pull
docker compose up -d
docker ps --filter name=agent-police
```

Pin a specific image instead of `latest` when you want a known artifact:

```bash
AGENT_POLICE_IMAGE=ghcr.io/<owner>/agent-police:sha-<commit> \
  docker compose pull && docker compose up -d
```

### What guarantees the image was tested

Two independent checks, both in CI:

1. A `test` job runs `pytest -q` on **3.12 and 3.14** - the interpreter the
   image ships and the one the project was developed on. This exists because a
   suite passing on 3.14 said nothing about production running 3.12.
2. The image's own first stage re-runs the suite on `python:3.12-slim` during
   the build and fails the build if it fails. The runtime stage copies a
   marker out of it, which is what stops BuildKit pruning the stage away, so
   the guarantee travels with the image rather than with the pipeline.

```bash
# What the build concluded, read from the running container.
docker exec agent-police cat /app/.tests-passed
```

Both need outbound DNS: one guard test resolves `api.anthropic.com` to prove
the SSRF check admits a real public host. Building somewhere without DNS needs
`SKIP_TESTS=1`, which forfeits guarantee 2 - only do that after running the
suite yourself.

### Runtime shape

It publishes no HTTP ports. Caddy reaches it at `agent-police:8080` over the
shared network; only UDP/53 is published, because the canary zone is delegated
straight to this host. State is one SQLite file of canary tokens and hits in
the `agent-police_agent_police_data` volume — no keys, no prompts, no report
bodies.

### Rollback

```bash
AGENT_POLICE_IMAGE=ghcr.io/<owner>/agent-police:sha-<previous> \
  docker compose up -d
```

The volume is untouched by a rollback, so canary history survives.

## 2. The Caddy site (needs applying)

`deploy/Caddyfile.snippet` holds the two blocks to append to
`/root/romaapi.com/caddy/Caddyfile.hub`. Both are additive.

```bash
CF=/root/romaapi.com/caddy/Caddyfile.hub
cp "$CF" "$CF.bak-$(date +%Y%m%dT%H%M%S)"
cat /root/agent-police/deploy/Caddyfile.snippet >> "$CF"

# Validate before touching the running config.
docker exec hub-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

# Apply without dropping connections.
docker exec hub-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

Verify:

```bash
curl -s https://security.romaapi.com/api/health
curl -s -o /dev/null -w '%{http_code}\n' https://security.romaapi.com/
```

Rollback: restore the backup and reload.

## 3. DNS canaries (optional, needs a DNS record)

HTTP canaries (`https://security.romaapi.com/c/<token>`) work as soon as step 2
is done. DNS canaries catch scanners that resolve a harvested hostname without
ever completing a request — a strictly wider net.

They need the canary zone delegated to this host. **The delegation target must
be a DNS-only name.** `security.romaapi.com` is proxied through Cloudflare and
resolves to Cloudflare anycast addresses, which do not run this collector, so
it cannot be used as the nameserver.

In the Cloudflare dashboard for `romaapi.com` -> DNS -> Records:

| Type | Name        | Value / Target          | Proxy status          |
|------|-------------|-------------------------|-----------------------|
| A    | `ns-canary` | `116.203.216.59`        | **DNS only** (grey)   |
| NS   | `c`         | `ns-canary.romaapi.com` | n/a                   |

Then open UDP/53 and turn it on:

```yaml
# docker-compose.yml
    environment:
      AGENT_POLICE_CANARY_DNS: c.romaapi.com
      AGENT_POLICE_DNS_A: "116.203.216.59"
    ports:
      - "53:53/udp"
```

```bash
ufw allow 53/udp comment "agent-police canary DNS"
docker compose up -d

# Unknown tokens answer NXDOMAIN; that is correct.
dig +short test.c.romaapi.com @116.203.216.59
# The apex answers NOERROR/NODATA, never NXDOMAIN: under RFC 8020 an NXDOMAIN
# at the apex would deny the whole subtree and stop resolvers asking about
# token names at all.
dig +noall +comments c.romaapi.com @116.203.216.59 | grep status
# Once delegation has propagated, this must resolve through the public chain:
dig +short <a-planted-token>.c.romaapi.com
```

### Cloudflare and the HTTP canary

`/c/*` is served through the Cloudflare proxy. Bot protection or a WAF rule
that challenges an automated client would swallow a canary callback, which is
exactly the evidence the collector exists to capture. Add a Cloudflare
configuration rule for `security.romaapi.com/c/*` that disables Bot Fight Mode,
Browser Integrity Check and caching, so every fetch reaches the collector.

Caller attribution already prefers `CF-Connecting-IP` over `X-Forwarded-For`,
because most proxies *append* to XFF and a caller-supplied leftmost entry would
otherwise be recorded as the source of a hit.

Until the NS record exists, leave `AGENT_POLICE_CANARY_DNS` empty:
`LocalCanaryProvider` then issues HTTP canaries instead, so nothing silently
fails to fire.

## What the service holds

| Data | Where | Lifetime |
|---|---|---|
| API keys submitted for an audit | worker thread memory only | the audit |
| Audit reports | process memory | 30 minutes |
| Canary tokens and hits | SQLite in the volume | until purged |
| Prompts, responses, request bodies | nowhere | never stored |

`agentpolice/server/jobs.py` and `tests/test_server.py::TestAuditFlow` are
where those claims are implemented and checked.

## Guards

- `agentpolice/server/guard.py` rejects non-public targets before an audit
  starts: no loopback, private, link-local (cloud metadata) or bare-IP hosts.
- `RouterClient(require_public_peer=True)` re-checks the address the socket
  actually landed on for every response, closing DNS rebinding.
- Per-IP budgets: 5 audits, 30 preflights, 120 inspections per hour.
- At most 6 audits in flight across all visitors.
