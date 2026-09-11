# Stage 1 - run the suite on the interpreter the service will actually use.
#
# Development happens in a host venv that may be on a different Python than
# this image. A green suite there says nothing about the version in
# production, so the build runs the tests itself and fails if they fail.
#
# Network note: tests/test_server.py resolves api.anthropic.com to prove the
# SSRF guard admits a real public host, so this stage needs DNS. Docker builds
# have network by default; behind an offline builder, run the suite on the
# host instead and build with --build-arg SKIP_TESTS=1.
FROM python:3.12-slim AS test

ARG SKIP_TESTS=0
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

COPY pyproject.toml README.md ./
COPY agentpolice ./agentpolice
COPY tests ./tests

RUN pip install --no-cache-dir ".[dev]" "uvicorn[standard]" fastapi \
 && if [ "$SKIP_TESTS" = "1" ]; then \
        echo "SKIPPED $(date -u +%FT%TZ)" > /src/.tests-passed; \
    else \
        pytest -q && echo "PASSED $(date -u +%FT%TZ)" > /src/.tests-passed; \
    fi


# Stage 2 - the runtime image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY agentpolice ./agentpolice

# Copying from the test stage is what forces it to run: BuildKit prunes stages
# nothing depends on, so without this line the tests would be silently skipped
# on any builder that does stage pruning.
COPY --from=test /src/.tests-passed /app/.tests-passed

# Ship the source the site offers for download, so the CLI path in the UI is
# real. The PyPI name is deliberately not used: it is unregistered, and telling
# people to pip install an unclaimed name is the very supply-chain shape this
# tool exists to detect.
RUN mkdir -p /app/agentpolice/server/static/download \
 && tar -czf /app/agentpolice/server/static/download/agent-police-src.tar.gz \
      --transform 's,^,agent-police/,' pyproject.toml README.md agentpolice \
 && sha256sum /app/agentpolice/server/static/download/agent-police-src.tar.gz \
      | cut -d" " -f1 > /app/agentpolice/server/static/download/SHA256 \
 && pip install --no-cache-dir . "uvicorn[standard]" fastapi \
 && useradd --system --uid 10001 --home /app police \
 && mkdir -p /data && chown police:police /data

USER police

ENV AGENT_POLICE_AUTOAPP=1 \
    AGENT_POLICE_DB=/data/canaries.db \
    AGENT_POLICE_CANARY_BASE=https://security.romaapi.com \
    FORWARDED_ALLOW_IPS=*

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health',timeout=4).status==200 else 1)"

CMD ["uvicorn", "agentpolice.server.app:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header", "--log-level", "info"]
