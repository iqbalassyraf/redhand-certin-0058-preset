# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY pyproject.toml LICENSE README.md ./
COPY src ./src
COPY presets ./presets

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip wheel --no-deps --wheel-dir /wheels . \
    && /opt/venv/bin/pip install --no-cache-dir /wheels/*.whl


FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --system --gid 10001 redhand \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin redhand

COPY --from=builder /opt/venv /opt/venv

RUN mkdir -p /app/data \
    && chown -R 10001:10001 /app/data

WORKDIR /app/data

USER 10001:10001

ENTRYPOINT ["redhand-shield"]
CMD ["gateway", "--help"]
