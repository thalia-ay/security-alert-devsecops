# ─── Stage 1: dependencias ────────────────────────────────────
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY src/requirements.txt .
# Instalacao deterministica: versoes fixas + verificacao de hash
RUN pip install --require-hashes --prefix=/install -r requirements.txt

# ─── Stage 2: imagem final (runtime) ──────────────────────────
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Aplica correcoes de seguranca do SO base e remove o pip da imagem final
# (nao e necessario em runtime e reduz a superficie de ataque)
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && pip uninstall -y pip setuptools wheel 2>/dev/null || true

# Usuario nao-root dedicado
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid appgroup --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=root:root src/ .

# Somente os diretorios de dados (banco SQLite e avatars) sao graváveis pelo app
RUN mkdir -p /app/instance /app/static/img/avatars \
    && chown -R appuser:appgroup /app/instance /app/static/img/avatars

USER appuser
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4).status == 200 else 1)"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "app:app"]
