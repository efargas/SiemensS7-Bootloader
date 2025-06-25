#!/bin/bash
set -e

echo "Updating package lists..."
sudo apt-get update

echo "Installing system packages..."
sudo apt-get install -y \
    build-essential \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    clang=1:6.0-41~exp5~ubuntu1 \
    make \
    socat \
    python2.7 \
    python-pip \
    git \
    libffi-dev \
    libssl-dev \
    python2.7-dev \
    virtualenv \
    binutils \
    gcc \
    binutils-arm-linux-gnueabi \
    gcc-arm-linux-gnueabi

echo "Adding current user to dialout group for serial access..."
sudo usermod -aG dialout $USER

echo "Creating Python 2 virtualenv for pwntools..."
cd ~
virtualenv -p python2.7 s7env
source ~/s7env/bin/activate

echo "Upgrading pip in virtualenv..."
pip install --upgrade pip

echo "Installing pwntools for Python 2..."
pip install 'pwntools'

echo "Setup complete!"
echo "To activate your Python 2 environment in the future, run:"
echo "  source ~/s7env/bin/activate"