# Memory

Each brain has its own active memory but shares its LTM with all other brains.
Every memory has a unique, immutable id (MemId). 

NOTE:
As every memory is backed by LTM, this means that a brain can see all other brains active memory, however there is no guarantee of synchronization between brains.

## Active Memory
A memory in active memory is **always** seen by the LLM
Therefore no read is required for a brain to 'see' and 'process' something in active memory.

## Core System Prompt Memory
The previous ROM concept is now represented as normal memories with valid `MemId`s.
These core memories are assembled into the model `system_prompt` each cycle.
They include:
- `CORE.md` base instructions (loaded first, rendered as plain markdown without `mem_id` prefix)
- system/core runtime guidance (previous ROM content)
- personality/identity guidance memories
- a final dynamic info board (real-time runtime metadata, regenerated per provider call, not persisted)

Core memories use flags instead of tier/type:
- `unevictable` keeps them in active memory
- `write_protected` prevents mutation by memory tools (where enabled)

## LTM
LTM memory is stored in a database and has search and similarity functions.
It is versioned, with a Copy On Write policy. 
By default, searches etc. are only on the latest version, however, the brain can ask to see historical versions (a similar feature was part of the VAX OS adding a :version number to any file retrieved a particular version)


## Working Active Memory
All active memories are backed by LTM; active memory is effectively an in-context working set.
The cost and effectiveness of active memory for LLM processing favours keeping it small; however too small breaks useful work.

## MemID
Each actual memory has a unique identifier that is the same in active memory or LTM. It has an optional version number (without it the latest is used).
Each MemID automatically consists of the agent and sub brain id. Together with a unique name suggested by the brain (it may be modified from the suggestion when the memory is created to stay unique)
Each MemId starts and ends with an EOT (End Of Text) character, allowing it to be easily parsed in text (for display the EOT is removed)

Example: `EOTZiggy:Brain67:WhatIDidTuesday:201EOT`
- Agent = Ziggy
- SubBrain = Brain67
- Name = WhatIDidTuesday
- Version = 201
