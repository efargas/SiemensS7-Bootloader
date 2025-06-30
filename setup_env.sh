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
    gcc-arm-linux-gnueabi \
    python3 \
    python3-venv

echo "Creating Python 3 virtual environment..."
#mkdir ~/venv3
#python3 -m venv ~/venv3

echo "Activating Python 3 virtual environment and install dependencies..."
#source ~/venv3/bin/activate

echo "Upgrading pip3 in virtualenv..."
#pip3 install --upgrade pip

echo "Installinq requirements for Python 3 on virtualenv..."
#pip3 install -r requirements-py3.txt

echo "Deactivating Python 3 virtualenv..."
#deactivate

echo "Creating Python 2 virtual environment..."
virtualenv -p python2.7 ~/venv2
#python2 -m virtualenv ~/venv2

echo "Activating Python 2 virtual environment and install dependencies..."
source ~/venv2/bin/activate

echo "Upgrading pip2 in virtualenv..."
pip2 install --upgrade pip

echo "Installinq requirements for Python 2 on virtualenv..."
pip2 install -r requirements-py2.txt

echo "Deactivating Python 2 on virtualenv..."
deactivate

# Set up update-alternatives
sudo update-alternatives --install /usr/bin/python python /usr/bin/python2 1
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 2

echo "Setup complete."
echo "To switch between Python versions, use: sudo update-alternatives --config python"
echo "To activate the Python 3 virtual environment, run: . ~/venv3/bin/activate"
echo "To activate the Python 2 virtual environment, run: . ~/venv2/bin/activate"
