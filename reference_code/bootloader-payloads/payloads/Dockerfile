FROM ubuntu:18.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y wget bzip2 make build-essential clang

# Download and install ARM toolchain
WORKDIR /tmp
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2018q2/gcc-arm-none-eabi-7-2018-q2-update-linux.tar.bz2 && \
    tar -xjvf gcc-arm-none-eabi-7-2018-q2-update-linux.tar.bz2 -C /usr/local && \
    rm gcc-arm-none-eabi-7-2018-q2-update-linux.tar.bz2

# Add toolchain to PATH
ENV PATH="/usr/local/gcc-arm-none-eabi-7-2018-q2-update/bin:${PATH}"

# Create a directory for the payloads
WORKDIR /app

# Copy the payloads and build script
COPY . .

# Build the payloads and collect them
RUN ./build_and_collect.sh

# Create a volume mount point for easy extraction
VOLUME ["/app/compiled_output"]