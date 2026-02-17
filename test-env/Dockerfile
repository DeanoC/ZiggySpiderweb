# Minimal Debian test environment for ZiggySpiderweb
FROM debian:bookworm-slim

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    jq \
    sqlite3 \
    libsecret-tools \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    nano \
    vim \
    htop \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create test user (to simulate real user environment)
RUN useradd -m -s /bin/bash -G sudo spiderweb \
    && echo "spiderweb ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up working directory
WORKDIR /home/spiderweb

# Copy install script for testing (will be overwritten by curl in real usage)
COPY install.sh /tmp/install.sh
RUN chmod +x /tmp/install.sh

# Create required directories
RUN mkdir -p /home/spiderweb/.local/bin \
    /home/spiderweb/.config/spiderweb \
    /home/spiderweb/.spiderweb-ltm

# Set ownership
RUN chown -R spiderweb:spiderweb /home/spiderweb

# Switch to test user
USER spiderweb

# Set up PATH
ENV PATH="/home/spiderweb/.local/bin:${PATH}"

# Default to bash shell
CMD ["/bin/bash"]
