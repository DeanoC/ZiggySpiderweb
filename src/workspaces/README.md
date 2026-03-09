# Workspace Layer

This folder contains workspace-scoped topology and policy code.

It is responsible for:

- workspace policy loading
- default workspace visibility/mount rules
- project-scoped node and path views used by Acheron projection

Keep workspace semantics here instead of scattering them through Acheron session code where possible.
