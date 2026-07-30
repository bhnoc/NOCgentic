FROM python:3.11-slim

WORKDIR /app/agents/root-cause

# Install dependencies
COPY agents/root-cause/requirements.txt .
COPY agents/shared/requirements.txt /app/shared/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r /app/shared/requirements.txt

# Copy shared module (parents[2]/shared = /app/shared)
COPY agents/shared/ /app/shared/

# Copy agent source. The recall migration ships inside agents/shared/migrations/
# (copied above with agents/shared/), so no separate migration COPY is needed.
COPY agents/root-cause/main.py .

EXPOSE 8006

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
