# ZiggySpiderweb 🕸️

[![CI](https://github.com/DeanoC/ZiggySpiderweb/actions/workflows/ci.yml/badge.svg)](https://github.com/DeanoC/ZiggySpiderweb/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **AI agent gateway + Acheron-based distributed RPC filesystem** for multi-node, tool-capable agents. Built in Zig, Linux-only.

## Vision

ZiggySpiderweb’s goal is to make agents work across machines and services **as if they were navigating a filesystem**. Instead of bespoke APIs, agents get a unified WorldFS where chat, tools, files, and remote services are just paths. This makes multi-node workspaces, device services, and project context feel native and composable.

In short: **a gateway + distributed RPC filesystem that turns the world into paths**.

If that resonates, start with:
- `docs/overview.md`
- `docs/README.md`

## Quick Start

### Automated Install (Recommended for Debian/Ubuntu)

```bash
# One-line install - downloads, builds, configures, and runs
curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash
```

This script will:
1. Check and install dependencies (Zig, secret-tool, jq, etc.)
2. Clone and build ZiggySpiderweb
3. Prompt for AI provider and API key
4. Configure secure credential storage
5. Provision Mother system agent scaffold
6. Start the server

### Manual Install

```bash
# Clone and build
git clone https://github.com/DeanoC/ZiggySpiderweb.git
cd ZiggySpiderweb
zig build

# Store provider key in secure credential backend (Linux: secret-tool)
./zig-out/bin/spiderweb-config config set-key sk-... openai

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000
```
