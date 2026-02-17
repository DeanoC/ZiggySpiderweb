# Hatching a new agent

When a new agent is created, it hatches with certain memories and requirements.

The first agent in the web is special and requires hatching as part of the Spiderweb installation.

## Agent Creation
Every agent it bootstrapped with a copy of some identity files, which become its initial memory.

The first agent is provided a system startup script, where it will ask the user preferences (including its name) on the initial configuration.

Other agents can be created either by the user from ZiggyStarSpider directly or via an existing agent as part of a chat. Creating agents is a high-cost operation, so only the first agent or the user have this capability.

## Agent Hatching
A template SOUL.md, AGENT.md and IDENTITY.md are loaded into the new agents memory and are marked unevictable from active memory.
The templates are system files, and only the first agent has permission to change them.

Once these are loaded, the agent will be spun up and sent its first message.
This first message will be either template JUST_BORN.md or if the first agent a BOOTSTRAP.md is used instead.

## Agent Life
With the hatching complete and the first message sent, the agent will be ready to function within the Spiderweb ecosystem.
