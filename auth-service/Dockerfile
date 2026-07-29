FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AUTH_DB_PATH=/data/auth.db

RUN mkdir -p /data && chmod 700 /data

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ ./app/

RUN groupadd --system --gid 10002 authapp \
 && useradd  --system --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin authapp \
 && chown -R authapp:authapp /app /data

USER authapp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
