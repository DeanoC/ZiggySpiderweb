# Node Service Catalog Spec (v2)

The service catalog describes node-exported namespace services and their
mount metadata. This is the control-plane source used to project
`/nodes/<node_id>/services/*` and dynamic mount roots in Acheron WorldFS.

## Control Operations

- `control.node_service_upsert`
- `control.node_service_get`

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
  - `invoke` (`string`, optional):
    - invoke target used for `invoke_path` discovery in `/agents/self/services/SERVICES.json`
    - world-absolute (for example `/nodes/<node_id>/tool/main/custom/exec.json`) or service-relative (for example `control/invoke.json`)
  - `paths.invoke` (`string`, optional):
    - alias for `invoke` when grouping operation paths under `paths`
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
    },
    {
      "service_id": "terminal",
      "kind": "terminal",
      "version": "1",
      "state": "degraded",
      "endpoints": ["/nodes/node-2/terminal/1"],
      "capabilities": { "pty": true },
      "mounts": [
        {
          "mount_id": "terminal-1",
          "mount_path": "/nodes/node-2/terminal/1",
          "state": "degraded"
        }
      ],
      "ops": { "model": "namespace", "style": "plan9", "interactive": true },
      "runtime": { "type": "builtin", "abi": "namespace-driver-v1" },
      "permissions": { "default": "deny-by-default", "device": "terminal" },
      "schema": { "model": "namespace-mount" },
      "help_md": "Builtin terminal namespace driver"
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

## Validation Notes

- Service IDs and kinds are identifier-safe strings.
- Service IDs must be unique within one upsert payload.
- `endpoints` must be absolute-style paths.
- `capabilities` must be a JSON object.
- `mounts`, when present, must be an array of objects with absolute
  `mount_path` values.
- `ops`, `runtime`, `permissions`, and `schema` must be JSON objects.
- `ops.invoke` / `ops.paths.invoke`, when provided, must be strings to override
  `invoke_path` projection; invalid types fall back to `/control/invoke.json`.

## WorldFS Permission Projection

`/nodes/<node_id>/services/*` visibility for non-admin sessions evaluates
service `permissions` metadata:

- `allow_roles` (`array<string>`, optional):
  - when present, non-admin visibility requires `"user"` (or `"all"` / `"*"`)
- `default` (`string`, optional):
  - `"deny"` / `"deny-by-default"` hides the service for non-admin sessions
    when no user role allow-list is present
- `require_project_token` / `project_token_required` (`bool`, optional):
  - when true, non-admin visibility requires a bound `project_token`

Admin sessions bypass service permission filtering.

## `spiderweb-fs-node` Provider Mapping

When `spiderweb-fs-node` runs in control daemon mode (`--control-url`), it auto-upserts service metadata:

- FS provider (enabled by default):
  - `service_id`: `fs`
  - `kind`: `fs`
  - endpoint: `/nodes/<node_id>/fs`
  - capabilities: `rw`, `export_count`
  - mounts: `/nodes/<node_id>/fs`
- Terminal provider (repeat `--terminal-id <id>`):
  - `service_id`: `terminal-<id>`
  - `kind`: `terminal`
  - endpoint: `/nodes/<node_id>/terminal/<id>`
  - capabilities: `pty=true`, `terminal_id`
  - mounts: `/nodes/<node_id>/terminal/<id>`
- Extra namespace services (from `--service-manifest` / `--services-dir`):
  - appended to the upsert payload after built-in providers
  - validated for shape and duplicate `service_id`s before publish

Use `--no-fs-service` to disable FS service advertisement and `--label <key=value>` to attach node labels.
