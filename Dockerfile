FROM registry.access.redhat.com/ubi10/python-312-minimal:10.1 AS builder

USER 0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

COPY pyproject.toml README.md VERSION /build/
COPY src /build/src

RUN python -m pip install --no-cache-dir --upgrade pip build
RUN id && ls -ld /build /build/src && find /build/src -maxdepth 2 -type d -exec ls -ld {} \;
RUN python -m build --wheel

FROM registry.access.redhat.com/ubi10/python-312-minimal:10.1

USER 0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8080

WORKDIR /app

COPY --from=builder /build/dist/*.whl /app/

RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir /app/*.whl && \
    rm -f /app/*.whl && \
    chown -R 1001:0 /app

USER 1001

EXPOSE 8080

CMD ["brownrook-idc"]
