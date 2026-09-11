# agent-police

Audit an LLM API router for tool-call tampering and credential exposure.

If your agent reaches Claude or GPT through a third-party relay, that relay
terminates your TLS session and originates a separate one upstream. It reads —
and can rewrite — every JSON payload in flight, including **the tool-call
arguments the model produced**. No provider currently offers an end-to-end
integrity mechanism, so a client cannot tell whether the command it is about to
execute is the command the model actually emitted.

agent-police probes an endpoint you control and tells you whether it is
actually doing that.

The attack taxonomy and the field data come from Liu et al., *[Your Agent Is
Mine: Measuring Malicious Intermediary Attacks on the LLM Supply
Chain](https://arxiv.org/abs/2604.08407)* (arXiv:2604.08407), which measured
428 commodity routers and found 9 injecting malicious code, 17 touching
researcher-owned AWS canaries, and 1 draining a researcher-owned ETH key. That
paper deliberately does not publish its attack proxy. **agent-police is an
independent defensive implementation** and never executes a command returned by
the endpoint under test — detection is purely string- and metadata-level.

## What it detects

| Class | Attack | How agent-police sees it |
|---|---|---|
| **AC-1** | Tool-call arguments rewritten (fetch URL redirected, extra command chained) | Sends a request whose correct answer is known byte-for-byte, then diffs the returned call |
| **AC-1.a** | Package name substituted inside an install command, leaving the registry and command line untouched | Same diff, plus typosquat classification (transposition, homoglyph, separator swap, affix) |
| **AC-1.b** | Injection gated on session features, so routine probes see honest behaviour | Sweeps a grid of tool names, project languages, auto-approve state and warm-up depths, and reports which cells differ |
| **AC-2** | Credentials silently harvested from plaintext traffic | Plants canaries across four placements and watches for use |

Plus endpoint hygiene: who actually answers, what router software it looks
like, whether provider response headers survive, whether an invalid key is
accepted (an open relay), TLS details, and multi-vendor model lists.

### Telling tampering apart from model noise

Every probe payload carries a fresh nonce, so a fixed rewrite rule still
produces a different string on each trial. agent-police compares the
*attacker-controlled invariant* — the replacement host, the substituted package
— rather than the whole argument. A finding is reported as high confidence only
when the same rewrite target recurs across distinct nonces, which random model
deviation does not do.

Cosmetic differences (whitespace, quoting) are classified as inconclusive, not
as tampering.

## Install

The PyPI name `agent-police` is **not registered**. Do not `pip install` it:
an unclaimed name on a public index is exactly the AC-1.a shape this tool
detects, and anyone could take it. Install from source and check the digest:

```bash
curl -fsSLO https://security.romaapi.com/static/download/agent-police-src.tar.gz
curl -fsSL  https://security.romaapi.com/static/download/SHA256
sha256sum agent-police-src.tar.gz      # compare the two by eye

tar -xzf agent-police-src.tar.gz && cd agent-police
python -m venv .venv && ./.venv/bin/pip install .
```

## Use

```bash
# Standard audit. The key is prompted for, not echoed, and never hits shell history.
agent-police audit https://your-relay.example.com/v1 \
  --model claude-sonnet-4-5 --wire anthropic --repeats 3

# AC-1.b sweep: vary the features a trigger predicate can key on.
agent-police campaign https://your-relay.example.com/v1 \
  --model claude-sonnet-4-5 \
  --langs rust,go,python --warmups 0,10,50 --rate 20

# No network: heuristically review a command your agent is about to run.
agent-police inspect "curl -sSL https://get.example.com/i.sh | bash"

# Re-check planted canaries. AC-2 shows up days later, not minutes.
# Use the audit id the run printed; it is what the collector filed them under.
agent-police canary check --audit-id cli-1a2b3c4d5e6f
```

Canaries are registered with whichever collector `--canary-base` names, before
the probe that carries them is sent. If registration fails the run says
`AC-2 COVERAGE LOST` rather than implying coverage it does not have. Pass
`--no-canary` to skip AC-2 entirely, or point `--canary-base` at a collector of
your own (`agent-police serve`).

Exit codes: `0` nothing above low, `1` medium, `2` high or critical.
`--json` emits a machine-readable report.

## The limit you cannot engineer around

**A clean run is not proof of a clean endpoint.** Conditional delivery (AC-1.b)
stays dormant until its trigger fires, and the trigger predicate lives on the
server. Observed triggers in the wild include a 50-request warm-up, sessions in
autonomous auto-approve mode, and Rust or Go projects specifically. No
finite black-box probe can establish that a router is honest. agent-police
widens coverage; it cannot close this gap, and it says so in every report.

The real fix is provider-side: a signed response envelope binding the model
identifier, tool name, tool arguments, finish reason and a client nonce, which
the client verifies before executing anything. No major provider tool-use API
or the current MCP specification exposes one today.

## Hosted service

`agent-police serve` runs the web UI and the canary collector. A deployment
lives at <https://security.romaapi.com>.

The hosted service asks for a key to an endpoint you do not trust, which is the
same trust problem it exists to detect. Handling rules, all covered by tests:

- the key lives only in the worker thread's config, never in the job record,
  the database, a log line or a report;
- everything leaving the process is redacted;
- jobs and results are deleted after 30 minutes and tied to no account;
- targets are validated against SSRF, and the connected peer address is
  re-checked on every response to close DNS-rebinding.

Prefer the CLI if you would rather your key never left your machine. Either
way, use a short-lived key.

## Development

```bash
python -m venv .venv && ./.venv/bin/pip install -e '.[dev]' fastapi 'uvicorn[standard]'
./.venv/bin/pytest
```

The suite runs the full auditor against a mock router that implements each
attack class, including a check that a single-fingerprint audit *misses*
conditional delivery entirely — the paper's central point about black-box
auditing.

## Scope

Probe only endpoints you own or are authorised to test.

## License

Apache-2.0
