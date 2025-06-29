#!/bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y python2 python3 python3-venv python-is-python3

# Create Python 3 virtual environment
python3 -m venv venv3

# Activate Python 3 virtual environment and install dependencies
. venv3/bin/activate
pip install -r requirements-py3.txt
deactivate

# Create Python 2 virtual environment
python2 -m virtualenv venv2

# Activate Python 2 virtual environment and install dependencies
. venv2/bin/activate
pip install -r requirements-py2.txt
deactivate

# Set up update-alternatives
sudo update-alternatives --install /usr/bin/python python /usr/bin/python2 1
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 2

echo "Setup complete."
echo "To switch between Python versions, use: sudo update-alternatives --config python"
echo "To activate the Python 3 virtual environment, run: . venv3/bin/activate"
echo "To activate the Python 2 virtual environment, run: . venv2/bin/activate"
