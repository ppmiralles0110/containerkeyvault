FROM python:3.11-slim

# non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirement files and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application
COPY . /app

# Ensure non-root user owns files
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080
ENV PORT=8080

# Use gunicorn for production-grade server
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app", "--workers", "2"]
