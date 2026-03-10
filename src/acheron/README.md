# Acheron Layer

This folder contains Spiderweb-owned Acheron glue.

It is responsible for:

- session namespace projection
- control-plane integration
- filesystem-style routing and mounting
- standalone namespace client mounting for `spiderweb-fs-mount`
- client/protocol helpers used by the Acheron surface

It is not the authoritative node runtime implementation.
That lives in `deps/spider-protocol/src/spiderweb_node/`.

If a change is about generic node hosting, namespace drivers, or shared runtime behavior, prefer updating the shared protocol runtime instead of growing this folder.

The mount client now has two modes:

- routed workspace mode: explicit `/v2/fs` endpoint routing via `--workspace-url`
- full namespace mode: unified websocket attach via `--namespace-url`, with a hybrid resolver that sends mounted workspace exports through the routed FS client and leaves the rest on the attached Acheron session tree
