# Imagem do Magnus Monitor (painel web + alertas).
# O .env NÃO entra na imagem: o docker-compose.yml injeta ele em tempo de execução.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/monitor.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py demo.py ./
COPY static/ static/

# Histórico (SQLite) fica em /data, montado como volume.
RUN useradd --create-home magnusmon && mkdir -p /data && chown -R magnusmon:magnusmon /app /data
USER magnusmon

EXPOSE 8088

CMD ["python", "monitor.py"]
