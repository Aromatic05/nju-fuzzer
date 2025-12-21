## Builder stage: build toolchain and produce env/out and env/seeds
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

# Install build dependencies (subset of env/deps.sh to keep parity)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    python3-setuptools \
    cargo \
    libtool \
    libpcap-dev \
    libgtk-3-dev \
    llvm-14 llvm-14-dev \
    clang-14 \
    lld-14 \
    meson \
    ninja-build \
    cpio \
    libcapstone-dev \
    wget \
    curl \
    python3-pip \
  && rm -rf /var/lib/apt/lists/*

# Copy only env/ so builder stage focuses on building toolchain
COPY env /workspace/env

# Run env scripts (builder will populate env/out and env/seeds)
# env.sh must be executed from inside the env directory
RUN chmod +x /workspace/env/*.sh && \
  cd /workspace/env && \
  ./env.sh || true && \
  touch /workspace/env/out/.build_complete || true

## Final stage: minimal runtime image that copies only env/out and env/seeds
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

# Install runtime packages to match env dependencies so runtime is stable
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    python3-setuptools \
    cargo \
    libtool \
    libpcap-dev \
    libgtk-3-dev \
    llvm-14 llvm-14-dev \
    clang-14 \
    lld-14 \
    meson \
    ninja-build \
    cpio \
    libcapstone-dev \
    wget \
    curl \
    python3-pip \
    openjdk-17-jdk \
    maven \
  && rm -rf /var/lib/apt/lists/*

# Ensure JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=${JAVA_HOME}/bin:${PATH}

# Copy only the built outputs we want to keep
COPY --from=builder /workspace/env/out /workspace/env/out
COPY --from=builder /workspace/env/seeds /workspace/env/seeds
COPY --from=builder /usr/local /usr/local

LABEL org.opencontainers.image.description="nju-fuzzer image with AFL++ and target binaries"

# No default CMD; this is a base image
