FROM python:3.11-slim

WORKDIR /app/agents/root-cause

# Install dependencies
COPY agents/root-cause/requirements.txt .
COPY agents/shared/requirements.txt /app/shared/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r /app/shared/requirements.txt

# Copy shared module (parents[2]/shared = /app/shared)
COPY agents/shared/ /app/shared/

# Copy agent source + migrations
COPY agents/root-cause/main.py .
COPY agents/root-cause/migrations/ migrations/

EXPOSE 8006

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
