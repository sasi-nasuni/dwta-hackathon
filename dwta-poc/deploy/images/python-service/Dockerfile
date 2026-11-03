# One image definition for every Python service; pick the service with --target.
# Build context: repository root.
FROM python:3.14-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DWTA_SPECS_DIR=/opt/dwta/specs
WORKDIR /opt/dwta
COPY packages/dwta-core packages/dwta-core
RUN pip install packages/dwta-core
COPY specs specs

FROM base AS collector
COPY services/collector services/collector
RUN pip install services/collector
ENTRYPOINT ["dwta-collector"]

FROM base AS db
COPY packages/dwta-ledger packages/dwta-ledger
RUN pip install packages/dwta-ledger

FROM db AS ledger-migrate
ENTRYPOINT ["dwta-ledger"]
CMD ["migrate"]

FROM db AS classifier
COPY services/classifier services/classifier
RUN pip install "services/classifier[ai]"
ENTRYPOINT ["dwta-classifier"]

FROM db AS matcher
COPY services/matcher services/matcher
RUN pip install services/matcher
ENTRYPOINT ["dwta-matcher"]

FROM db AS incident
COPY services/incident services/incident
RUN pip install services/incident
ENTRYPOINT ["dwta-incident"]
CMD ["serve"]
