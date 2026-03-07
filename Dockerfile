FROM registry.access.redhat.com/ubi10/python-312-minimal:10.1

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8080

WORKDIR /app

COPY --chown=1001:0 pyproject.toml README.md /app/
COPY --chown=1001:0 src /app/src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

EXPOSE 8080

CMD ["brownrook-idc"]
