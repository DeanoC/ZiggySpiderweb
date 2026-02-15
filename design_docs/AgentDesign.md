# ZiggySpider* Agent Design

## 1. System Overview
ZiggySpider* uses a **Hierarchical Brain Model**. Agents are not monolithic entities but orchestrated swarms composed of one **Primary Brain** and multiple **Sub-Brains**.

### 1.1 Hierarchical Structure
*   **Primary Brain (Orchestrator):** The user-facing personality and decision-maker. It manages goals, delegates to sub-brains, and maintains the primary dialogue.
*   **Sub-Brains (Workers):** Specialized units assigned to specific tasks (e.g., coding, research, system monitoring). They report results back to the Primary Brain.

## 2. Memory Architecture
Memory is divided into three tiers to balance immediate context (RAM) with long-term knowledge.

### 2.1 RAM (Active Context)
*   **Definition:** The volatile AI context window.
*   **Mechanism:** Iteratively updated by both the Primary Brain and the **Memory Manager** sub-brain.
*   **Data Integrity:** Every object in RAM has a unique `MemoryID`.
*   **Operations:** `LOAD(MemoryID)`, `EVICT(MemoryID)`, `UPDATE(MemoryID)`, `SUMMARIZE(MemoryID)`.

### 2.2 Long-Term Memory (LTM)
*   **Storage:** Distributed across a relational database (structured logs), text files (project notes), and vector embeddings (semantic search).
*   **Access:** Shared across all brains in the agent's swarm.

### 2.3 Identity Files (Personality Layer)
Each agent is defined by four specialized Markdown files that dictate behavior:
1.  `SOUL.md`: Core values, ethical boundaries, and communication tone.
2.  `AGENT.md`: Operational workflow rules and "contract" (how it handles tasks).
3.  `IDENTITY.md`: Public-facing avatar, name, and role description.
4.  `USER.md`: Private relationship context and user-specific preferences.

## 3. Specialized Sub-Brains
Standard workers included in every agent deployment:
*   **Heartbeat:** Periodically wakes the agent to check system status, task progress, or external triggers.
*   **Memory Manager:** Continuously optimizes RAM by summarizing old context and moving details to LTM to maintain token efficiency.

---

# Design Feedback & Potential Issues

### 1. Memory Race Conditions
With both the Primary Brain and the Memory Manager (and potentially other Sub-Brains) able to `UPDATE` or `EVICT` RAM data, there is a risk of context "hallucination" or inconsistency.
*   **Risk:** The Primary Brain might refer to a `MemoryID` that the Memory Manager just evicted or summarized mid-thought.
*   **Recommendation:** Implement a simple locking mechanism or a "Proposed Changes" queue for RAM updates.

### 2. Identity Fragmentation
Managing four separate `.md` files (`SOUL`, `AGENT`, `IDENTITY`, `USER`) for a single agent's personality may lead to conflicting instructions.
*   **Risk:** LLMs often struggle when system instructions are spread across too many sources, potentially leading to diluted personality or "mode collapse."
*   **Recommendation:** Ensure a strict hierarchy of "truth" among these files (e.g., `SOUL.md` always overrides `AGENT.md`).

### 3. Orchestration Overhead
The document mentions sub-brains talk to the Primary Brain to "manage and update their actions."
*   **Issue:** If every sub-brain update requires a Primary Brain "turn" (inference), the system will be slow and expensive.
*   **Recommendation:** Define "Soft Workflows" (as seen in `ARCHITECTURE.md`) where sub-brains can update the shared Memory/RAM directly for routine tasks without bothering the Primary Brain.

### 4. MemoryID Discovery
*   **Issue:** How does a brain "know" which `MemoryID` to look up if it has been evicted?
*   **Recommendation:** The Memory Manager should leave "Tombstones" or "Summaries" in RAM that contain the `MemoryID` for the full detail, allowing the Primary Brain to trigger a "Recall" action.
