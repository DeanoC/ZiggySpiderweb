# Projects

Projects are the fundamental block of what is accessible by Agents and what they are working on.

## Overview
Projects provide a structured way to organise and manage tasks, resources, and dependencies for various projects within the system. 
They serve as containers for goals and tasks, allowing agents to focus on specific project goals and collaborate effectively.
They have a workspace that contains all the files and folders used in the project even across multiple machines and source locations.

## Project Data Model
A project is the top-level entity. It is defined by its vision and its configuration of resources.

### Schema: Project
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier for the project. |
| `name` | String | Human-readable name. |
| `vision` | String | High-level description of the project purpose. |
| `status` | Enum | `active`, `completed`, `archived`. |
| `created_at` | Timestamp | Project creation time. |
| `workspace_config` | JSON | List of Source Nodes mapped to this project. |

## Goals & Tasks
Projects follow a hierarchical breakdown of work.

### Schema: Goal
Goals represent major milestones or sub-projects.
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier. |
| `project_id` | UUID | Reference to the parent Project. |
| `parent_goal_id` | UUID? | Optional parent goal for nested hierarchies. |
| `title` | String | Short title of the goal. |
| `description` | String | Detailed success criteria. |
| `status` | Enum | `pending`, `in_progress`, `blocked`, `completed`. |

### Schema: Task
Tasks are granular actions executed by agents.
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier. |
| `goal_id` | UUID | Reference to the parent Goal. |
| `description` | String | What needs to be done. |
| `status` | Enum | `todo`, `doing`, `done`, `failed`. |
| `assigned_agent_id` | String? | The agent currently working on this task. |
| `dependencies` | List[UUID] | IDs of tasks that must be completed first. |

## Workspace
The workspace is what the AI see and interacts with; it consists of a custom FUSE filesystem that is connected to the various distributed sources, producing a seeming normal linux filesystem.
The enabled the AI to have all the usual tools from its linux Spiderweb machine, the primary agent can even install new tools. 
This unified filesystem view avoids the need for user uploading and downloading files that aren't on the Spiderweb machine.

### Workspace Mapping
Each project defines a set of **Sources**. A Source is a combination of a Node (remote machine) and an Export (folder on that machine).

**Source Configuration:**
- `node_id`: The ID of the remote node.
- `export_name`: The name of the export on that node (e.g., "work").
- `mount_path`: Where this export appears in the project workspace (e.g., `src/`, `docs/`).

When an agent is connected to a project, its `/spiderweb/workspace/` directory is dynamically populated based on these mappings.

Example:
Project "GameEngine" workspace:
- Source(Node: `laptop`, Export: `code`) -> `/spiderweb/workspace/src`
- Source(Node: `server`, Export: `assets`) -> `/spiderweb/workspace/assets`
- Source(Node: `spiderweb`, Export: `local`) -> `/spiderweb/workspace/scratch`

### FUSE Implementation Details
The FUSE daemon on the Spiderweb host maintains the project's virtual namespace.
- It routes file operations to the appropriate WebSocket node handlers.
- It enforces isolation: Agents (except Primary) cannot see files outside the project's `/spiderweb/workspace/`.
- It handles path translation between the virtual namespace and the remote node's exports.

## Project State Store
All project data (Projects, Goals, Tasks, WorkspaceConfigs) is persisted in the **Long-term Memory (LTM)** system, specifically in a SQLite-backed store.

### Persistence Requirements
1. **ACID Compliance**: Transactions for goal/task updates to avoid race conditions between agents.
2. **Audit Log**: Every change to project state (e.g., task status change) should be logged with the initiating Agent ID.
3. **Recovery**: On system boot, active projects and their workspaces should be automatically re-mounted.

## Agents & Context
Agents are connected to a specific project at any one time, but may move between projects at the control of the user or the primary agent.
Except for the primary agent, agents are generally restricted to the workspace of the project they are connected to.

### Agent Roles within a Project
1. **PM (Project Manager) Agent**:
    - **One per project**. Usually the Primary Agent or a specialized sub-brain.
    - **Responsibility**: Breaks down Vision into Goals, and Goals into Tasks. Monitors progress. Re-prioritizes based on blockers.
    - **Capabilities**: Full access to the project's workspace. Can spawn/assign Worker agents.
2. **Worker Agents**:
    - **Assigned to specific Tasks**.
    - **Responsibility**: Execute granular actions. Report status (done/failed).
    - **Capabilities**: Restricted to the project workspace. May only have read-only access to certain sources if configured.

### Project Context Switching
When an agent moves to a project:
1. **Environment Variables**: `SPIDERWEB_PROJECT_ID` and `SPIDERWEB_WORKSPACE_ROOT` are set.
2. **Instruction Injection**: The Project Vision and current Goals are injected into the agent's system prompt (Working Memory).
3. **Filesystem Jail**: The agent's file system view is restricted to the project workspace.

## API & Management
The system provides a set of control messages for managing projects.

### Example Messages
- `PROJECT_CREATE(name, vision, workspace_config)`
- `GOAL_ADD(project_id, title, description)`
- `TASK_ASSIGN(task_id, agent_id)`
- `TASK_STATUS_UPDATE(task_id, new_status)`

## Implementation Phases
To build this, the following milestones are suggested for a implementation plan:

1. **Phase 1: Project Metadata Store (Persistence)**
    - Implement SQLite schema for Projects, Goals, and Tasks.
    - Provide a basic CRUD API for project entities.
2. **Phase 2: Project-Aware FUSE Mount**
    - Implement the "Workspace Router" that maps multiple remote node exports into a single virtual directory.
    - Ensure path translation works correctly for all FUSE operations (LOOKUP, OPEN, READ, etc.).
3. **Phase 3: Agent Context & Lifecycle**
    - Implement the logic to "move" an agent into a project.
    - Handle environment variable injection and system prompt updates.
    - Enforce filesystem isolation using the project's virtual workspace.
4. **Phase 4: PM Agent Logic**
    - Integrate the hierarchical breakdown logic into a PM-specialized agent.
    - Enable the agent to monitor task status and re-plan when blocked.
5. **Phase 5: GUI Visualization**
    - Develop the visual Goal/Task tree and progress tracking interface.
    - Add tools for managing workspace source node mappings.

## GUI
The GUI allows users to create, update goals, and access the workspace. Projects are quite heavyweight and often long-running, so the GUI should provide many helpers for the user to manage and see progress.

### GUI Features
- **Project Dashboard**: Visual representation of the Goal/Task tree with progress bars.
- **Workspace Manager**: Drag-and-drop interface for mapping remote nodes to workspace paths.
- **Timeline**: History of agent activities and status changes within the project.
