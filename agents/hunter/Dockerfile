FROM python:3.11-slim

WORKDIR /app/agents/hunter

# Install dependencies
COPY agents/hunter/requirements.txt .
COPY agents/shared/requirements.txt /app/shared/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r /app/shared/requirements.txt

# Copy shared module (parents[2]/shared = /app/shared)
COPY agents/shared/ /app/shared/

# Copy agent source
COPY agents/hunter/main.py .
COPY agents/hunter/hunt_templates.py .

EXPOSE 8010

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
