# Brain Tools
The brain toolset directly affects the agent's current memory and state.
This allows the brain to wait for outside stimuli and control its limited active memory.

Brain Tools are presented to the agent in the same way as other tools. From an action point of view, all tool use is the same.

They are mostly presented as a group name then action in that group. i.e. `wait.for`

## memory - group for memory tools

`memory.load`: takes a MemId and loads it from LTM to RAM

Arguments 
- MemId – the MemId to load from LTM
- Offset – the offset into the MemId to load from
- Length – the length of the MemId to load (0 for all up to a fixed maximum)

Returns 
- return Success<Actual length loaded> or Failure 

`memory.evict`: takes a MemId and evicts from

Arguments 
- MemId – the MemId to evict from RAM to LTM

Returns 
- Success or Failure

`memory.mutate`: modifies a MemId in RAM to the specified value. 

Arguments 
- MemId – the MemId to modify 
- value – the value to set the memory referenced by the MemId to

Returns 
- Success or Failure, MemId if successful.

`memory.create`: creates a new MemId with the specified value.

Arguments 
- name – the name portion that will be used to create the MemId 
- value – the value to set the memory to

Returns 
- Success or Failure, MemId if successful.

`memory.search`: return MemIds and short summaries of matching MemIds.

Arguments 
- `query` (string)
- `type` (Vector | Keyword | Tag)
- `limit` (int).

Returns
- A list of `MemId`s with short snippets/summaries.

## wait - group for wait tools
Waits must have a previous talk.* in the same tool use list
Waits can specify the TalkId returned by a talk.* this can be used to distinguish similar events
The event is cleared once the wait returns it.

`wait.for`: waits for a specified events to occur.

struct Event {
    EventType EventType;
    String Parameter;       // single parameter based on EventType 
    TalkId TalkId;          // optional talkId 0 if not used
}

EventType = [ User | Agent | Time | Hook ]
- User - Parameter is ignored and must be "" 
- Agent - Parameter is an agent's name
- Time - Parameter is a time in seconds (float)
- Hook - Parameter is a hook name (currently not used)

Arguments 
- Events [ `Event` ] 
Returns 
- Success with [ `pair<Event, Result>` ]

## talk - group for talk tools
Talk sends a message to the destination, the do not wait or stop the Agent loop.
All waits must issue a talk.* before they wait for tracking.

They all return a TalkId, which is monotonically increasing and may loop after some time. 0 is never returned.

`talk.user`: speaks a message to the user 

Arguments 
- User currently must be ""
- Message – the message to say

Returns -
- TalkId – semi-unique identifier of this talk message

`talk.agent`: speaks a message to the agent
Arguments 
- Agent – the name of the agent to speak to
- Message – the message to say

Returns -
- TalkId – semi-unique identifier of this talk message

`talk.brain`: speaks a message to a brain Brains can only talk to other brains in the same Agent
Arguments 
- subbrain – name (`primary` to talk to the Agents primary brain)
- Message – the message to say

Returns -
- TalkId – semi-unique identifier of this talk message

`talk.log`: speaks a message to the log

Arguments 
- Severity – the log severity
- Message – the message to say

Returns -
- TalkId – semi-unique identifier of this talk message
