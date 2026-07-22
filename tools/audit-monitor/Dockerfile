FROM python:3.11-slim

WORKDIR /app

COPY tools/audit-monitor/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY tools/audit-monitor/app.py ./app.py
COPY tools/audit-monitor/static ./static

EXPOSE 8787

ENV AUDIT_HOST=0.0.0.0 \
    AUDIT_PORT=8787 \
    AUDIT_ROOT_PATH=/bh/1337/thetraces

CMD ["python", "app.py"]
