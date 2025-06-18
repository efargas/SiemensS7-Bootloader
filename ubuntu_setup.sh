#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Update package lists
sudo apt-get update

# Install essential packages for development and specific tools
echo "Installing essential packages: build-essential, git, curl, socat, and ARM cross-compiler..."
sudo apt-get install -y \
    build-essential \
    git \
    curl \
    socat \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi

# Install Python 2.7, pip for Python 2, and python-virtualenv
# These are needed for the project's Python scripts and environment management
echo "Installing Python 2.7, pip, and virtualenv..."
sudo apt-get install -y \
    python2.7 \
    python-pip \
    python-virtualenv

echo "-------------------------------------------------------------------"
echo "Setup complete."
echo "Remember to create and activate your Python 2.7 virtual environment"
echo "and install dependencies from requirements.txt using pip."
echo "-------------------------------------------------------------------"

# Clean up downloaded package files
sudo apt-get clean
echo "Cleaned up apt cache."
