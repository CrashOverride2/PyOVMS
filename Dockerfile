# Build stage for Tailwind CSS
FROM node:20-alpine AS tailwind-builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node dependencies
RUN npm ci

# Copy static files and tailwind config
COPY tailwind.config.js ./
COPY app/static ./app/static
COPY app/templates ./app/templates

# Build Tailwind CSS
RUN npm run build


# Python dependency build stage — keeps gcc/libpq-dev out of the runtime image
#
# 3.12 matches the --python-version that requirements.txt is compiled for, install.sh,
# and the CI workflows. Both stages must stay on the same minor version: pip installs to
# /install/lib/python3.X/site-packages and the runtime stage copies that tree to
# /usr/local, so a mismatch produces an image whose imports all fail at startup.
FROM python:3.12-slim AS python-builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Final runtime stage — no build toolchain, no root process.
# Keep this minor version identical to the builder stage above.
FROM python:3.12-slim

WORKDIR /app

# Runtime-only system libraries (libpq for psycopg2)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from build stage
COPY --from=python-builder /install /usr/local

# Create non-root user before copying files
RUN groupadd -r ovms && useradd -r -g ovms -d /app -s /sbin/nologin ovms

# Copy application code
COPY . .

# Copy built Tailwind CSS from builder stage
COPY --from=tailwind-builder /app/app/static/css/main.css ./app/static/css/main.css

# Create data directory and transfer ownership to non-root user
RUN mkdir -p /app/data && chown -R ovms:ovms /app

# Expose ports
# 8000: FastAPI HTTP
# 6867: OVMS V2 TCP plain
# 6870: OVMS V2 TCP SSL
EXPOSE 8000 6867 6870

# Set environment variables
ENV PYTHONUNBUFFERED=1

USER ovms

# Run the application
CMD ["python", "run.py"]
