# Agent Loop
Each agent has a loop per brain (primary or sub-brain), this is something like the traditional LLM chat loop.
At each iteration of the loop, 
- the brain will examine its active memory (Observe)
- select which tools to use to affect itself or the world (Mutate)
- load the results of the tools into RAM (Results)
- repeat

Tools can be a mix of Brain Tools and World Tools, allowing an agent to change its own state and the world.
This allows it to learn and adapt to the environment and manage its own memory.

Tool results are themselves memories, which in many cases the agent will evict and store in LTM. 
This allows the agent to learn from its own experiences and solves the tombstone problem on eviction.
A memory eviction returns the MemId of the eviction which the agent may choose to mutate into its own index if important.

## Time
To the agent time does not pass between each loop (without us providing an external clock in its context).
This means that from a synchronisation point of view, each loop iteration provides a perfect point to update disks etc.

## State Machine
The agent loop runs a state machine, with hooks at every step. Each hook may have multiple subscribers.
This allows the system to perform actions before and after each state in an iteration.

States:
- Observe
- Mutate
- Results

PreObserve is a key step as it allows each hook to mutate the ROM (e.g. feeding real time data in to the ROM)
PostResults is the where a disk/reconcilation step can occur.
Using various hooks allows single step debugging, data validation and agent level logging.
