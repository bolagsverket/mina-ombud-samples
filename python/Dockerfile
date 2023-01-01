FROM python:3.9-alpine as build
ARG DISABLE_SSL_TRUST=0
ARG VENV=/venv

RUN python -m venv ${VENV}/

WORKDIR /build
COPY src/ pyproject.toml ./
RUN pipargs="--disable-pip-version-check"; \
  if [ ${DISABLE_SSL_TRUST} -ne 0 ]; then \
    pipargs="$pipargs --trusted-host pypi.python.org --trusted-host pypi.org"; \
  fi;  \
  ${VENV}/bin/pip install $pipargs .[server]

FROM python:3.9-alpine
ENV PATH=/venv/bin:$PATH \
    MINA_OMBUD_SAMPLE_DATA=/data
COPY --from=build /venv /venv
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN mkdir /data && chown 1000 /data
USER 1000
COPY --chown=1000:1000 /data /data
ENTRYPOINT ["/docker-entrypoint.sh"]
