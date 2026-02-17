# Glossary

Agent - an AI with a primary brain (the personality) and sub-brains (the workers)
World - everything outside of the agent included users

primary brain - the personality and main interface and driver of the AI

sub brains - the workers deployed by the primary brain to do complex/long running things

RAM – the modifiable part of the LLM context memory

ROM - a read-only part of the LLM context memory

LTM - long term memory, a mixture of disk files + database

Active Memory = RAM + ROM

Memory - Active Memory + long term memory (LTM)

Memory load - Moving memory from LTM to RAM

Memory save - Moving memory from RAM to LTM

Memory mutate - Changing the value of a memory in RAM 

MemId - an idempotent identifier to a memory location + optional version

Agent Loop - a infinite sequence of decisions and tool uses

Tool Use - a single decision made by the agent

Tool Use List - a list of tools to use for this cycle, these are sequential and used in order

Brain Tools - tools that are part of the brain own system

World Tools - tools that are not part of the brain own system and affect the world

Tools - Brain Tools + World Tools

