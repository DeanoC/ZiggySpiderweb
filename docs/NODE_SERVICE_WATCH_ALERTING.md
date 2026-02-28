# Node Service Watch Alerting Guide

This guide defines practical alert thresholds for node-service watch telemetry
exported by:

- `control.metrics` (`node_service_watch` JSON object)
- HTTP metrics endpoints:
  - `GET /metrics` (Prometheus text)
  - `GET /metrics.json` (JSON)

## Metric Mapping

`control.metrics` JSON fields:

- `node_service_watch.subscribers.current`
- `node_service_watch.subscribers.peak`
- `node_service_watch.replay.requests_total`
- `node_service_watch.replay.attempted_total`
- `node_service_watch.replay.sent_total`
- `node_service_watch.replay.bytes_total`
- `node_service_watch.fanout.events_total`
- `node_service_watch.fanout.attempted_total`
- `node_service_watch.fanout.sent_total`
- `node_service_watch.fanout.dropped_total`
- `node_service_watch.retained.events`
- `node_service_watch.retained.capacity`
- `node_service_watch.retained.window_ms`

Prometheus metric names:

- `spiderweb_node_service_watch_subscribers`
- `spiderweb_node_service_watch_subscribers_peak`
- `spiderweb_node_service_watch_replay_requests_total`
- `spiderweb_node_service_watch_replay_attempted_total`
- `spiderweb_node_service_watch_replay_sent_total`
- `spiderweb_node_service_watch_replay_bytes_total`
- `spiderweb_node_service_watch_fanout_events_total`
- `spiderweb_node_service_watch_fanout_attempted_total`
- `spiderweb_node_service_watch_fanout_sent_total`
- `spiderweb_node_service_watch_fanout_dropped_total`
- `spiderweb_node_service_watch_retained_events`
- `spiderweb_node_service_watch_retained_capacity`
- `spiderweb_node_service_watch_retained_window_ms`

## Recommended Alerts

Use these as default starting points, then tune for your environment.

1. **Fanout drops detected (critical)**
   - Trigger: `increase(spiderweb_node_service_watch_fanout_dropped_total[5m]) > 0`
   - Meaning: active subscribers are missing pushed events.
   - Action: inspect websocket session churn and subscriber policy scope.

2. **Fanout drop ratio elevated (warning)**
   - Trigger:
     - `increase(spiderweb_node_service_watch_fanout_attempted_total[5m]) > 0`
     - and
       `increase(spiderweb_node_service_watch_fanout_dropped_total[5m]) / increase(spiderweb_node_service_watch_fanout_attempted_total[5m]) > 0.02`
   - Meaning: watch delivery quality is degraded.
   - Action: validate client consumption speed and server load.

3. **Replay send deficit (warning)**
   - Trigger:
     - `increase(spiderweb_node_service_watch_replay_attempted_total[10m]) > 0`
     - and
       `increase(spiderweb_node_service_watch_replay_sent_total[10m]) / increase(spiderweb_node_service_watch_replay_attempted_total[10m]) < 0.95`
   - Meaning: replay requests are not fully served.
   - Action: inspect filter policy and history retention window.

4. **Retention capacity saturation (warning)**
   - Trigger:
     - `spiderweb_node_service_watch_retained_capacity > 0`
     - and
       `spiderweb_node_service_watch_retained_events / spiderweb_node_service_watch_retained_capacity > 0.9`
   - Meaning: replay buffer is near full; old events are churned quickly.
   - Action: increase history capacity if replay expectations require it.

5. **Retention window too small (warning)**
   - Trigger: `spiderweb_node_service_watch_retained_window_ms < 60000`
   - Meaning: less than 60s of replay history currently retained.
   - Action: increase retention settings or reduce event burst noise.

6. **Unexpected watcher surge (info/warning)**
   - Trigger:
     - `spiderweb_node_service_watch_subscribers > N` (environment-specific)
     - or sustained growth in `spiderweb_node_service_watch_subscribers_peak`
   - Meaning: operational behavior changed (new tooling/users/workloads).
   - Action: verify expected clients and policy scope.

## Dashboard Panels

Recommended baseline panels:

1. **Subscribers**
   - current + peak gauges.
2. **Fanout**
   - events/attempted/sent/dropped counters (rate over 5m).
3. **Replay**
   - requests/attempted/sent/bytes counters (rate over 10m).
4. **Retention**
   - retained events vs capacity.
   - retained window (ms).
5. **Derived Ratios**
   - fanout drop ratio.
   - replay send ratio.

## Operational Notes

- `SPIDERWEB_NODE_SERVICE_WATCH_REPLAY_MAX` constrains replay per watch request.
- Role gates:
  - `SPIDERWEB_NODE_SERVICE_WATCH_ALLOW_ADMIN`
  - `SPIDERWEB_NODE_SERVICE_WATCH_ALLOW_USER`
- If drops correlate with reconnect storms, inspect websocket transport and
  authentication churn first.
