"""agent-police: audit LLM API routers for tampering and credential exposure.

The tool probes a router endpoint you are authorised to test and reports on the
four attack classes described in "Your Agent Is Mine" (arXiv:2604.08407):

  AC-1    response-side tool-call payload injection
  AC-1.a  dependency-targeted injection (package substitution)
  AC-1.b  conditional delivery (trigger-gated injection)
  AC-2    passive secret exfiltration

plus supply-chain hygiene checks drawn from Anthropic's September 2026 threat
report (stolen API keys as loot/compute/cover, relay identification).

agent-police never executes a tool call returned by the endpoint under test.
Detection is purely string- and metadata-level.
"""

__version__ = "0.2.0"
