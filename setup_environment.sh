#!/bin/bash

# This script installs the .NET 8.0 SDK on Debian/Ubuntu-based systems.

# Update package lists
sudo apt-get update

# Install dependencies
sudo apt-get install -y wget software-properties-common

# Add Microsoft package signing key and repository
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

# Install .NET SDK
sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0
