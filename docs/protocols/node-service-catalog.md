# Node Service Catalog Spec

The service catalog describes node-exported namespace services and their mount metadata. It is the control-plane source used to project `/nodes/<node_id>/services/*` and dynamic mount roots in Acheron WorldFS.

## Control Operations

- `control.node_service_upsert`
- `control.node_service_get`
- `control.node_service_watch`
- `control.node_service_unwatch`
- `control.node_service_event` (server push)

## `control.node_service_upsert`

### Request fields

- `node_id` (`string`, required)
- `node_secret` (`string`, required)
- `platform` (`object`, optional)
  - `os` (`string`, optional)
  - `arch` (`string`, optional)
  - `runtime_kind` (`string`, optional)
- `labels` (`object<string,string>`, optional)
- `services` (`array`, optional)

Each service entry:

- `service_id` (`string`, required)
- `kind` (`string`, required)
- `version` (`string`, default `"1"`)
- `state` (`string`, required)
- `endpoints` (`array<string>`, required, absolute paths)
- `capabilities` (`object`, optional, default `{}`)
- `mounts` (`array<object>`, optional, default `[]`)
  - `mount_id` (`string`, required)
  - `mount_path` (`string`, required, absolute path)
  - `state` (`string`, optional; defaults to service state)
- `ops` (`object`, optional, default `{}`)
  - `invoke` (`string`, optional)
  - `paths.invoke` (`string`, optional)
- `runtime` (`object`, optional, default `{}`)
- `permissions` (`object`, optional, default `{}`)
- `schema` (`object`, optional, default `{}`)
- `help_md` (`string`, optional)

### Example

```json
{
  "node_id": "node-2",
  "node_secret": "secret-...",
  "platform": { "os": "linux", "arch": "amd64", "runtime_kind": "native" },
  "labels": { "site": "hq-west", "tier": "edge" },
  "services": [
    {
      "service_id": "camera",
      "kind": "camera",
      "version": "1",
      "state": "online",
      "endpoints": ["/nodes/node-2/camera"],
      "capabilities": { "still": true },
      "mounts": [
        {
          "mount_id": "camera",
          "mount_path": "/nodes/node-2/camera",
          "state": "online"
        }
      ],
      "ops": { "model": "namespace", "style": "plan9" },
      "runtime": { "type": "native_proc", "abi": "namespace-driver-v1" },
      "permissions": { "default": "deny-by-default" },
      "schema": { "model": "namespace-mount" },
      "help_md": "Camera namespace driver"
    }
  ]
}
```

## `control.node_service_get`

Request fields:
- `node_id` (`string`, required)

Response fields:
- `node_id`
- `node_name`
- `platform`
- `labels`
- `services`

## `control.node_service_watch`

Subscribes to catalog events. Server responds with `control.node_service_event` frames for upserts and changes.

## Validation Notes

- Service IDs and kinds are identifier-safe strings.
- Service IDs must be unique within a single upsert payload.
- `endpoints` must be absolute-style paths.
- `capabilities` must be a JSON object.
- `mounts`, when present, must use absolute `mount_path` values.
- `ops`, `runtime`, `permissions`, and `schema` must be JSON objects.
- `ops.invoke` / `ops.paths.invoke`, when provided, override the default `control/invoke.json` resolve path.

## WorldFS Permission Projection

`/nodes/<node_id>/services/*` visibility for non-admin sessions evaluates service `permissions` metadata:

- `allow_roles` (`array<string>`, optional)
- `default` (`string`, optional)
- `require_project_token` / `project_token_required` (`bool`, optional)

Admin sessions bypass service permission filtering.

## Workspace Mount Gating

`control.workspace_status` applies invoke-policy checks to mount projection for non-admin actors:

- If a mount maps to an invoke-capable service, it is omitted unless
  - project access policy allows `invoke`
  - service `permissions` allow the actor

## `spiderweb-fs-node` Provider Mapping

When `spiderweb-fs-node` runs in control daemon mode (`--control-url`), it auto-upserts service metadata:

- FS provider (enabled by default):
  - `service_id`: `fs`
  - `kind`: `fs`
  - endpoint: `/nodes/<node_id>/fs`
  - capabilities: `rw`, `export_count`
  - mounts: `/nodes/<node_id>/fs`
- Terminal provider (`--terminal-id <id>`):
  - `service_id`: `terminal-<id>`
  - `kind`: `terminal`
  - endpoint: `/nodes/<node_id>/terminal/<id>`
  - capabilities: `pty=true`, `terminal_id`, `invoke=true`
  - ops: `invoke=control/invoke.json` (`paths.exec` alias)
  - runtime: `native_proc` (`entry=internal-terminal-invoke`)
  - mounts: `/nodes/<node_id>/terminal/<id>`
- Extra namespace services (from `--service-manifest` / `--services-dir`):
  - appended after built-in providers
  - validated for shape and duplicates before publish

Use `--no-fs-service` to disable FS service advertisement and `--label <key=value>` to attach node labels.

Implementation pointers:
- `src/fs_node_service.zig`
- `src/node_service_catalog.zig`
- `src/server_piai.zig`
