# ZiggySpiderweb Documentation

This folder contains the maintained docs for Spiderweb. Files are grouped by topic; older design notes have been refreshed and moved under `docs/design/`.

## Start Here
- `../README.md` - build, install, and quick usage
- `overview.md` - vision, architecture, protocols, configuration, and FS runtime examples
- `protocols/control-agent-session.md` - unified-v2 control handshake, agent discovery, and session control
- `protocols/acheron-worldfs.md` - Acheron WorldFS layout and service contracts
- `runtime/tool-system.md` - provider-driven tool loop and tool constraints

## Architecture & Design
- `design/architecture.md` - current runtime architecture and threading model
- `design/projects.md` - project model and workspace topology as implemented
- `design/filesystem.md` - distributed FS runtime and node/mount flow
- `design/filesystem-sources.md` - source adapters and routing behavior
- `design/agents/agent-design.md` - agent identity + registry model
- `design/agents/agent-loop.md` - runtime/agent loop mechanics
- `design/agents/brain-tools.md` - tool naming and dispatch
- `design/agents/memory.md` - memory schemas + Acheron paths
- `design/agents/hatch.md` - bootstrap/hatching behavior
- `design/glossary.md` - shared terminology

## Protocols
- `protocols/control-agent-session.md`
- `protocols/node-service-catalog.md`
- `protocols/acheron-worldfs.md`
- `protocols/unified-v2-fs-migration.md`

## Runtime & Policy
- `runtime/agent-project-policy.md`
- `runtime/tool-system.md`
- `runtime/service-inventory.md`

## Security
- `security/auth-session-safety.md`
- `security/secret-visibility.md`
- `security/review-policy.md`

## Operations
- `operations/first-agent-bootstrap.md`
- `operations/multi-node-runtime-harness.md`
- `operations/node-pairing-approval.md`
- `operations/node-service-watch-alerting.md`
- `operations/unified-v2-release-checklist.md`

If you find drift, update the doc and add a short “Source” or “Implementation” note pointing to the relevant Zig files.
