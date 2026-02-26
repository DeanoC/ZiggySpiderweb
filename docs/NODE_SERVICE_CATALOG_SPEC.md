# Node Service Catalog Spec (v1)

The service catalog describes non-mount capabilities available on a node.

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
      "capabilities": { "still": true }
    },
    {
      "service_id": "terminal",
      "kind": "terminal",
      "version": "1",
      "state": "degraded",
      "endpoints": ["/nodes/node-2/terminal/1"],
      "capabilities": { "pty": true }
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

## `spiderweb-fs-node` Provider Mapping

When `spiderweb-fs-node` runs in control daemon mode (`--control-url`), it auto-upserts service metadata:

- FS provider (enabled by default):
  - `service_id`: `fs`
  - `kind`: `fs`
  - endpoint: `/nodes/<node_id>/fs`
  - capabilities: `rw`, `export_count`
- Terminal provider (repeat `--terminal-id <id>`):
  - `service_id`: `terminal-<id>`
  - `kind`: `terminal`
  - endpoint: `/nodes/<node_id>/terminal/<id>`
  - capabilities: `pty=true`, `terminal_id`

Use `--no-fs-service` to disable FS service advertisement and `--label <key=value>` to attach node labels.
