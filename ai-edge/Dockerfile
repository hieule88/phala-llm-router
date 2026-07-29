FROM python:3.11-slim
WORKDIR /edge
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
# Drop privileges.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin edge
USER edge
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
