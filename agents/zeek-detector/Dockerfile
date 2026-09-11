FROM python:3.11-slim

WORKDIR /app/agents/zeek-detector

COPY agents/zeek-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Self-contained on purpose: no agents/shared. The pipeline is vendored under
# pipeline/ and the store is storage.py; nothing here reaches Athena or Manifold.
COPY agents/zeek-detector/main.py .
COPY agents/zeek-detector/storage.py .
COPY agents/zeek-detector/pipeline/ ./pipeline/
# Finding -> hunt playbook links (shared with the web-server; see the file).
COPY threathunt-catalog/finding-playbook-map.json ./finding-playbook-map.json

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8007

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8007"]
