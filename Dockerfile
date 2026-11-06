# TANKI ONLINE — серверная сборка для Amvera/Koyeb/Render (и любого Docker-хостинга)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data \
    STATIC_DIR=. \
    TRUST_PROXY=1 \
    RESTART_HOURS=6

WORKDIR /app

# не-root пользователь — безопасность
RUN useradd --create-home --uid 10001 tanki \
 && mkdir -p /data \
 && chown -R tanki:tanki /app /data

COPY --chown=tanki:tanki config.json ./
COPY --chown=tanki:tanki server.py ./
COPY --chown=tanki:tanki game.html ./
COPY --chown=tanki:tanki admin.html ./
COPY --chown=tanki:tanki sound/ ./sound/

USER tanki

EXPOSE 8080

# Koyeb/докер-хостинги шлют SIGTERM — сервер сохраняет data/ и закрывает WS
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%d/health'%int(os.environ.get('PORT',8080)),timeout=3)" || exit 1

CMD ["python", "server.py"]
