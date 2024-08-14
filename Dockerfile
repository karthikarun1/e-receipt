# Use your existing base image
FROM python:3.12-slim

# Install curl and other dependencies
RUN apt-get update && apt-get install -y curl

# Copy and install your application
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set the health check using the dynamic port
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/health_check || exit 1

# Run the application
CMD ["python", "app.py"]
