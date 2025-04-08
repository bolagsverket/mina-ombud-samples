# syntax=docker/dockerfile:1.10.0
ARG DOCKER_HUB_PROXY_REPOSITORY=""
FROM ${DOCKER_HUB_PROXY_REPOSITORY}library/python:3.11-alpine AS build

RUN python -m venv /venv/ \
    && /venv/bin/python -m venv /venv.dev

WORKDIR /build
COPY src/ pyproject.toml ./

RUN --mount=type=secret,id=PIP_CONFIG_FILE \
    --mount=type=secret,id=PIP_CERT --mount=type=secret,id=PIP_TRUSTED_HOST,env=PIP_TRUSTED_HOST \
    --mount=type=secret,id=PIP_INDEX,env=PIP_INDEX --mount=type=secret,id=PIP_INDEX_URL,env=PIP_INDEX_URL \
    for e in PIP_CERT PIP_CONFIG_FILE; do \
      [ ! -e /run/secrets/$e ] || eval "export $e=/run/secrets/$e"; \
    done; \
    for e in PIP_INDEX PIP_INDEX_URL PIP_TRUSTED_HOST; do \
      eval "[ -n \"\$$e\" ] || unset $e"; \
    done; \
    env | grep PIP ; \
    set -e; \
    /venv/bin/pip install .[server]; \
    /venv.dev/bin/pip install .[dev];

COPY tests/ ./tests
COPY data/ ./data

ARG SKIP_ITS=false
RUN /venv.dev/bin/pytest

FROM ${DOCKER_HUB_PROXY_REPOSITORY}library/python:3.11-alpine
ENV PATH=/venv/bin:$PATH \
    MINA_OMBUD_SAMPLE_DATA=/data
COPY --from=build /venv /venv
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN mkdir /data && chown 1000 /data
USER 1000
COPY --chown=1000:1000 /data /data
ENTRYPOINT ["/docker-entrypoint.sh"]
