FROM ubuntu:18.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    clang \
    gcc-arm-none-eabi \
    gcc-arm-linux-gnueabi \
    #python2.7 \
    #python-pip \
    git \
    wget && \
    rm -rf /var/lib/apt/lists/*

    # Download and install ARM toolchain
WORKDIR /tmp

# Copy the payloads and build script
COPY . .

# Build the payloads and collect them
RUN ./build_and_collect.sh

# Create a volume mount point for easy extraction
VOLUME ["/app/compiled_output"]