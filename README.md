# Spiderweb 🕸️

[![CI](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml/badge.svg)](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **AI agent gateway + Acheron-based distributed RPC filesystem** for multi-node, tool-capable agents. Built in Zig, Linux-only.

## Vision

Spiderweb’s goal is to make agents work across machines and services **as if they were navigating a filesystem**. Instead of bespoke APIs, agents get a unified WorldFS where chat, tools, files, and remote services are just paths. This makes multi-node workspaces, device services, and project context feel native and composable.

In short: **a gateway + distributed RPC filesystem that turns the world into paths**.

If that resonates, start with:
- `docs/overview.md`
- `docs/README.md`

The docs tree is intentionally minimal and code-grounded. Older RFC/migration notes were removed once the single-websocket worldfs transport became the shipped behavior.

## Quick Start

### Automated Install (Recommended for Debian/Ubuntu)

```bash
# One-line install - downloads, builds, configures, and runs
curl -fsSL https://raw.githubusercontent.com/DeanoC/Spiderweb/main/install.sh -o /tmp/install.sh
chmod +x /tmp/install.sh
/tmp/instaill.sh
```

This script will:
1. Check and install dependencies (Zig, secret-tool, jq, etc.)
2. Clone and build Spiderweb
3. Prompt for AI provider and API key
4. Configure secure credential storage
5. Provision Mother system agent scaffold
6. Start the server

### Manual Install

```bash
# Clone and build
git clone --recurse-submodules https://github.com/DeanoC/Spiderweb.git
cd Spiderweb
# If you already cloned without submodules:
git submodule update --init --recursive
zig build

# Store provider key in secure credential backend (Linux: secret-tool)
./zig-out/bin/spiderweb-config config set-key sk-... openai

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000
```
