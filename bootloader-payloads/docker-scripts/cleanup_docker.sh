#!/bin/bash

# Script to clean up Docker containers and images for fresh testing
# Usage: ./cleanup_docker.sh

set -e

echo "=== Docker Cleanup Script for SiemensS7-Bootloader ==="

# Define image and container names used in the extraction scripts
IMAGE_NAME="siemens-s7-payloads-enhanced"

echo "Cleaning up containers and images..."

# Remove images
echo "Removing Docker images..."
docker rmi "$IMAGE_NAME" 2>/dev/null || echo "Image $IMAGE_NAME not found"

# Optional: Clean up any dangling images and build cache
echo "Cleaning up dangling images and build cache..."
docker image prune -f
docker builder prune -f

echo ""
echo "=== Cleanup Complete ==="
echo "All SiemensS7-Bootloader related containers and images have been removed."
echo "You can now test the build process from scratch."
echo ""
echo "To rebuild and extract payloads, run:"
echo "  ./extract_payloads.sh"