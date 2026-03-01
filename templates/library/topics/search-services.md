# Search Services

Spiderweb exposes two search-oriented agent namespaces:

- `/agents/self/web_search`
- `/agents/self/search_code`

Both support:

- direct operation write: `control/search.json`
- generic envelope write: `control/invoke.json`
- runtime tracking: `status.json`, `result.json`

Practical guidance:

1. Use `search_code` first for repository-local facts and code navigation.
2. Use `web_search` for external/current information.
3. Keep search payloads narrow (target path/domain/query scope) to reduce noise.
4. Read and validate `result.json` before deciding follow-up actions.
5. On failure, check `status.json` and `result.error` fields before retrying.

For predictable workflows, keep search queries stable and only broaden scope if
the first pass does not produce enough evidence.
