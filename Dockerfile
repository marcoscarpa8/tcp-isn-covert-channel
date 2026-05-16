FROM kathara/base

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake pkg-config \
    libpcap-dev libpcre2-dev libpcre3-dev \
    zlib1g-dev liblzma-dev libssl-dev \
    libhwloc-dev libluajit-5.1-dev \
    libunwind-dev flex bison libfl-dev \
    autoconf automake libtool \
    git ca-certificates \
    libmnl-dev libnetfilter-queue-dev \
    libdumbnet-dev \
    python3 python3-scapy \
    tcpdump ethtool \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Build and install libdaq
RUN cd /tmp && \
    git clone --depth 1 https://github.com/snort3/libdaq.git && \
    cd libdaq && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/libdaq

# Build and install snort3
RUN cd /tmp && \
    git clone --depth 1 https://github.com/snort3/snort3.git && \
    cd snort3 && \
    ./configure_cmake.sh --prefix=/usr/local && \
    cd build && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/snort3

# Verify installation
RUN snort --version
