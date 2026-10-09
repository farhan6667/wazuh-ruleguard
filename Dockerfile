FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/farhan6667/wazuh-ruleguard" \
      org.opencontainers.image.description="Test Wazuh 4.x detection rules with JSON scenarios and compare runs." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Syed Farhan Ahmed (SFA), NexaForge"

WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in ./
COPY ruleguard ./ruleguard
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 app \
    && rm -rf /src

USER app
WORKDIR /work
ENTRYPOINT ["ruleguard"]
CMD ["--help"]
