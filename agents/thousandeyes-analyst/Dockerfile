FROM python:3.11-slim

WORKDIR /app/agents/thousandeyes-analyst

# Install dependencies
COPY agents/thousandeyes-analyst/requirements.txt .
COPY agents/shared/requirements.txt /app/shared/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r /app/shared/requirements.txt

# Copy shared module (parents[2]/shared = /app/shared)
COPY agents/shared/ /app/shared/

# Copy agent source
COPY agents/thousandeyes-analyst/main.py .

EXPOSE 8004

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]
