# Glossary

Agent - an AI with a primary brain (the personality) and sub-brains (the workers)
World - everything outside of the agent included users

primary brain - the personality and main interface and driver of the AI

sub brains - the workers deployed by the primary brain to do complex/long running things

Active Memory - the in-context memory set visible to the LLM

Core Memory - memory used to construct the model system prompt (replaces ROM)
CORE.md - base core instructions template, loaded first into system prompt memory

LTM - long term memory, a mixture of disk files + database

Memory - Active Memory + long term memory (LTM)

Memory flags - per-memory controls such as `unevictable` and `write_protected`

Memory load - Loading memory from LTM into Active Memory

Memory save - Persisting Active Memory updates to LTM

Memory mutate - Changing the value of a memory in Active Memory (unless write protected)

MemId - an idempotent identifier to a memory location + optional version

Agent Loop - a infinite sequence of decisions and tool uses

Tool Use - a single decision made by the agent

Tool Use List - a list of tools to use for this cycle, these are sequential and used in order

Brain Tools - tools that are part of the brain own system

World Tools - tools that are not part of the brain own system and affect the world

Tools - Brain Tools + World Tools
