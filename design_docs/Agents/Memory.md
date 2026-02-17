# Memory

Each brain has its own active memory but shares its LTM with all other brains.
Every memory has a unique, immutable id (MemId). 

NOTE:
As every memory is backed by LTM, this means that a brain can see all other brains active memory, however there is no guarantee of synchronization between brains.

## Active Memory
A memory in active memory is **always** seen by the LLM
Therefore no read is required for a brain to 'see' and 'process' something in active memory.

## ROM
ROM can never be changed by memory tools. 
It is always active and cannot be modified or saved.
ROM is read-only for the brain, but may be modified by the system. 
This will be reflected in the next agent cycle.
A key use of this is to provide 'real-time' information to the brain.

## LTM
LTM memory is stored in a database and has search and similarity functions.
It is versioned, with a Copy On Write policy. 
By default, searches etc. are only on the latest version, however, the brain can ask to see historical versions (a similar feature was part of the VAX OS adding a :version number to any file retrieved a particular version)


## RAM
All RAM memories are also backed by LTM, it is effectively a cache with the additional feature that it is in the LLM's context.
The cost and effectiveness of RAM for the LLM processing favours keeping it small; however too small break the ability to do useful work.

## MemID
Each actual memory has a unique identifier that is the same in RAM or LTM. It has a optional version number (without it the latest is used).
Each MemID automatically consists of the agent and sub brain id. Together with a unique name suggested by the brain (it may be modified from the suggestion when the memory is created to stay unique)
Each MemId starts and ends with an EOT (End Of Text) character, allowing it to be easily parsed in text (for display the EOT is removed)

Example: `EOTZiggy:Brain67:WhatIDidTuesday:201EOT`
- Agent = Ziggy
- SubBrain = Brain67
- Name = WhatIDidTuesday
- Version = 201