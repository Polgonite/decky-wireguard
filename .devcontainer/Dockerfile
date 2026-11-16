FROM golang:1.24-bookworm AS actionlint
RUN go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git python3 python3-venv shellcheck \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/linters \
    && /opt/linters/bin/pip install --no-cache-dir \
        pre-commit==4.2.0 ruff==0.11.13

COPY --from=actionlint /go/bin/actionlint /usr/local/bin/actionlint
ENV PATH="/opt/linters/bin:${PATH}"
USER node
