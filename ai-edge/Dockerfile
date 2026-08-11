FROM python:3.11-slim
WORKDIR /edge
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py wallet_auth.py ./
# Drop privileges. /edge/state pre-exists owned by `edge` so the wallet-state
# volume (docker-compose.wallet.yml) inherits writable ownership on first
# mount — a root-owned mountpoint would make SQLite fail at startup.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin edge \
    && mkdir -p /edge/state && chown edge /edge/state
USER edge
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
