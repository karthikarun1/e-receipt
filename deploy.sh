#!/bin/bash

# Exit on error
set -e

# Build the Docker image
echo "Building Docker image..."
docker-compose build

# Stop and remove existing containers
echo "Stopping and removing existing containers..."
docker-compose down

# Start the containers
echo "Starting containers..."
docker-compose up -d

echo "Deployment complete!"
