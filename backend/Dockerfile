FROM python:3.11-slim

WORKDIR /app

# System deps for scapy/pcap and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libpcap0.8-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

EXPOSE 8000

CMD ["python", "-m", "app.main"]


