FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmilter-dev \
    sendmail-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY gateway/milter/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY gateway/milter/guardian_milter.py /app/guardian_milter.py

EXPOSE 8891
CMD ["python", "-u", "/app/guardian_milter.py"]
