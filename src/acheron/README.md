# Acheron Layer

This folder contains Spiderweb-owned Acheron glue.

It is responsible for:

- session namespace projection
- control-plane integration
- filesystem-style routing and mounting
- client/protocol helpers used by the Acheron surface

It is not the authoritative node runtime implementation.
That lives in `deps/spider-protocol/src/spiderweb_node/`.

If a change is about generic node hosting, namespace drivers, or shared runtime behavior, prefer updating the shared protocol runtime instead of growing this folder.
