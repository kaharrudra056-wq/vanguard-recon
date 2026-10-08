# Base lightweight Python image
FROM python:3.12-slim

# Maintainer / Metadata
LABEL maintainer="Cybersecurity Portfolio"
LABEL description="VanguardRecon - Attack Surface Discovery & CVE Intelligence Framework"

# Avoid python bytecode & buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose web dashboard port
EXPOSE 8000

# Default entrypoint: launch dashboard server
ENTRYPOINT ["python", "-m", "vanguard"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
