FROM registry.access.redhat.com/ubi10/python-312-minimal:10.1 AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

COPY pyproject.toml README.md /build/
COPY src /build/src

RUN pip install --no-cache-dir --upgrade pip build && \
    python -m build --wheel

FROM registry.access.redhat.com/ubi10/python-312-minimal:10.1

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8080

WORKDIR /app

COPY --from=builder /build/dist/*.whl /app/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /app/*.whl && \
    rm -f /app/*.whl

EXPOSE 8080

CMD ["brownrook-idc"]
