const shared = @import("spiderweb_node").chat_job_index;

pub const JobState = shared.JobState;
pub const JobIndexError = shared.JobIndexError;
pub const ThoughtFrame = shared.ThoughtFrame;
pub const JobTerminalEventView = shared.JobTerminalEventView;
pub const JobView = shared.JobView;
pub const ChatJobIndex = shared.ChatJobIndex;
pub const deinitThoughtFrames = shared.deinitThoughtFrames;
pub const deinitJobViews = shared.deinitJobViews;
pub const isTerminalState = shared.isTerminalState;
pub const jobStateName = shared.jobStateName;

test {
    _ = shared;
}
