FROM python:3.11-slim

WORKDIR /app/agents/deter

# Install dependencies
COPY agents/deter/requirements.txt .
COPY agents/shared/requirements.txt /app/shared/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r /app/shared/requirements.txt

# Copy shared module (parents[2]/shared = /app/shared)
COPY agents/shared/ /app/shared/

# Copy agent source. safe_pool.py is the agent's data policy and must ship with
# it — main.py imports it by bare name from this directory.
COPY agents/deter/main.py .
COPY agents/deter/safe_pool.py .

EXPOSE 8006

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
