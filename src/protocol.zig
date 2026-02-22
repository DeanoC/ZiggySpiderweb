const ext = @import("ziggy-spider-protocol").protocol;

pub const MessageType = ext.MessageType;
pub const ErrorCode = ext.ErrorCode;
pub const ParsedMessage = ext.ParsedMessage;

pub const parseMessageType = ext.parseMessageType;
pub const parseMessage = ext.parseMessage;
pub const deinitParsedMessage = ext.deinitParsedMessage;

pub const buildConnectAck = ext.buildConnectAck;
pub const buildSessionReceive = ext.buildSessionReceive;
pub const buildAgentProgress = ext.buildAgentProgress;
pub const buildAgentState = ext.buildAgentState;
pub const buildAgentRunAck = ext.buildAgentRunAck;
pub const buildAgentRunState = ext.buildAgentRunState;
pub const buildAgentRunEvent = ext.buildAgentRunEvent;
pub const buildMemoryEvent = ext.buildMemoryEvent;
pub const buildToolEvent = ext.buildToolEvent;
pub const buildDebugEvent = ext.buildDebugEvent;
pub const buildPong = ext.buildPong;
pub const buildError = ext.buildError;
pub const buildErrorWithCode = ext.buildErrorWithCode;
pub const jsonEscape = ext.jsonEscape;
