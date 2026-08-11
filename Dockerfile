# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m venv /opt/netbox-diode-unifi

COPY pyproject.toml README.md ./
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/pip \
    /opt/netbox-diode-unifi/bin/pip install --upgrade pip setuptools wheel && \
    /opt/netbox-diode-unifi/bin/pip install .

FROM python:3.12-slim AS runtime

ENV PATH="/opt/netbox-diode-unifi/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/netbox-diode-unifi /opt/netbox-diode-unifi

USER 1000:1000

ENTRYPOINT ["netbox-diode-unifi"]
