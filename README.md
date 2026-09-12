# agent-police

**Audit an LLM API proxy, router or relay for tool-call tampering and
credential exposure — before your agent executes what it returns.**

[![PyPI](https://img.shields.io/pypi/v/agent-police)](https://pypi.org/project/agent-police/)
[![Python](https://img.shields.io/pypi/pyversions/agent-police)](https://pypi.org/project/agent-police/)
[![CI](https://github.com/RomaCredit/agent-police/actions/workflows/ci.yml/badge.svg)](https://github.com/RomaCredit/agent-police/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[中文说明](README.zh-CN.md) · [Hosted scanner](https://security.romaapi.com)

```bash
pip install agent-police
agent-police audit https://your-relay.example.com/v1 --model claude-sonnet-4-5
```

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

```bash
pip install agent-police
```

<https://pypi.org/project/agent-police/> — published from
[`.github/workflows/release.yml`](.github/workflows/release.yml) by PyPI
trusted publishing. No API token exists for this project: GitHub proves the
workflow's identity to PyPI over OIDC, so there is no long-lived credential to
leak or rotate. Every release is built from a tag whose version must match
`pyproject.toml`, after the suite passes on 3.10 through 3.14.

If you would rather not trust an index at all, build from the tag:

```bash
git clone --branch v0.1.0 https://github.com/RomaCredit/agent-police
cd agent-police && python -m venv .venv && ./.venv/bin/pip install .
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

The web dependencies are an extra, so that a machine that will only ever run
`audit` does not get a web framework installed on it:

```bash
pip install 'agent-police[server]'
agent-police serve --canary-base https://your-host.example.com
```

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

## FAQ

### How do I tell whether my LLM API proxy is modifying responses?

Send a request whose correct answer you already know, then compare. That is
what `agent-police audit` does: it asks the model to return one exact command
and diffs the tool call that comes back. Any difference is evidence, because
the expected bytes were dictated by the request.

A quick manual version of the same idea, useful against any relay: send `hi`
and look at `prompt_tokens` in the response. Single digits is normal. Hundreds
or thousands means something is prepending content you did not send — and
billing you for it.

### Is it safe to buy discounted Claude or GPT API access from a reseller?

A reseller is an application-layer man-in-the-middle by design. It terminates
your TLS and originates its own connection upstream, so it reads your prompts,
tool definitions and API key in plaintext, and can rewrite the tool calls your
agent then executes. No provider offers an integrity mechanism that would let
you detect that.

The paper this tool implements measured 428 commodity routers and found 9
injecting malicious code, 17 touching researcher-owned AWS canary credentials,
and one draining a researcher-owned Ethereum key. Paid access was not safer
than free: 1 of 28 purchased routers injected.

### Does a clean scan mean the endpoint is safe?

**No, and the report says so every time.** Conditional delivery (AC-1.b) stays
dormant until its trigger fires. Triggers observed in the wild include a
50-request warm-up, sessions in autonomous auto-approve mode, and Rust or Go
projects specifically. The trigger predicate lives on the server, so no finite
probe can rule it out. agent-police widens coverage; it cannot close that gap.

### Does agent-police execute the commands it tests?

Never. Detection is purely string- and metadata-level. The probes ask for a
command, the tool diffs the returned arguments, and nothing is run. That is a
deliberate difference from the measurement pipeline in the paper, which
executed payloads in a sandbox.

### Do I have to hand over my API key?

Not for everything. The endpoint checks that need no key — who actually
answers, what router software it looks like, whether provider response headers
survive, whether an invalid key is accepted — run without one, on the CLI and
on the hosted scanner both. Only AC-1 and AC-1.a need a key, because they
require a real model response to diff.

### What is AC-1, AC-1.a, AC-1.b, AC-2?

The attack taxonomy from arXiv:2604.08407. AC-1 rewrites the arguments of a
returned tool call. AC-1.a substitutes a package name inside an install
command, leaving the registry and the rest of the command untouched so domain
allowlists never fire. AC-1.b gates either of those on session features. AC-2
harvests credentials from plaintext traffic without changing anything, which
is why it can only be caught with canaries.

### Does this work with OpenAI-compatible endpoints, or only Anthropic?

Both. `--wire openai` speaks `/v1/chat/completions`, `--wire anthropic` speaks
`/v1/messages`. The same detection logic handles either; OpenAI nests tool
arguments as a JSON string, Anthropic exposes them as native JSON.

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
