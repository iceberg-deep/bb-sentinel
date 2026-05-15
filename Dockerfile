FROM golang:1.22-bookworm AS tools
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV GOBIN=/out/bin
RUN mkdir -p /out/bin \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/tomnomnom/hacks/inscope@latest

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/bin/ /usr/local/bin/

WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY src /app/src
COPY config /app/config

# Warm nuclei templates so the first scan does not block on a download.
RUN nuclei -update-templates -silent || true

ENV BB_PROGRAMS_CONFIG=/app/config/programs.yaml \
    BB_GLOBAL_CONFIG=/app/config/global.yaml

ENTRYPOINT ["python", "-m", "src.main"]
