# Direct Candidate Path Quality Development Plan

## Objective

Implement quality-aware promotion of direct magicsock candidates on top of
`origin/main`, independently of the direct-path health retirement state
machine. A newly discovered direct path must not replace the current path when
its measured quality is worse.

The implementation must preserve existing Disco CLI behavior, DERP fallback,
peer-relay migration, WireGuard-only peers, and best-address timeout handling.

## Scope

### Included

- A bounded rolling quality window for the path currently in use.
- End-to-end heartbeat sampling when DERP is the current path.
- A short, generation-scoped Disco probe burst for a direct candidate.
- Quality comparison using reachability, loss, latency tail, and jitter.
- Direct preference only when the candidate's measured quality is no worse.
- Cancellation and stale-result isolation when the path or Disco key changes.
- Unit, race, integration, CLI regression, vet, and cross-platform build tests.

### Excluded

- `MagicsockPathHealthMode` or any replacement rollout mode.
- Healthy/suspect/unreachable direct-path state.
- Multi-miss endpoint retirement and hard-failure fallback.
- Global exact-source rejection for ordinary Discovery or CLI Pong messages.
- Changes to peer-relay promotion policy, including same-relay migration.
- Changes to WireGuard-only endpoint selection.

## Behavioral Rules

1. If there is no current path, preserve legacy behavior and immediately allow
   the first usable direct candidate.
2. If a current path exists but has insufficient quality samples, retain it and
   retry when a later candidate trigger arrives.
3. If heartbeat sampling is disabled, preserve legacy direct promotion; a
   candidate must not be withheld forever when no current-path window can be
   populated.
4. Candidate probes must match the exact probed `epAddr`; wrong-source replies
   count as failed quality samples and never enter normal Pong promotion.
5. A candidate that is unreachable or has a higher effective cost is retained
   as a candidate but does not replace the current path.
6. Direct-to-direct switching requires both an absolute and relative material
   improvement.
7. A direct candidate may replace DERP or a peer relay at equal cost, but never
   at a higher cost.
8. The first CLI Disco Pong callback is completed before any quality-based
   promotion decision. Ordinary CLI and Discovery Pong source semantics remain
   unchanged.
9. Peer-relay `udpRelayEndpointReady` behavior remains untouched; same-relay
   migration remains immediate.

## Design

### Quality snapshots

Use a bounded 16-outcome current-path window and a 10-probe candidate burst.
Each snapshot contains:

- reachability;
- sample count and confidence;
- loss rate;
- mean, p50, and p95 RTT;
- mean absolute deviation from p50 as jitter;
- observation time.

The effective cost is based on p50 plus weighted latency tail, jitter, and a
loss penalty. Soft direct-to-direct switching additionally requires absolute
and relative improvement margins.

### Endpoint state

Add only the state needed by candidate quality selection:

- `pathQualityGeneration`;
- `currentPathQuality`;
- `pathQualityEvaluation`.

Changing the selected path resets the rolling monitor. A successful candidate
burst seeds the new monitor in actual completion order.

### Probe lifecycle

Add `pingPathQuality` as an internal Disco ping purpose. Candidate burst Pongs,
timeouts, and send failures are consumed before ordinary Pong processing.
Every probe carries a generation and candidate address. Late results from a
cancelled generation are ignored.

### Integration points

- `heartbeat`: continue monitoring an existing best path and also ping DERP
  when DERP is current. Respect the existing `heartbeatDisabled` behavior.
- `setBestAddrLocked` and reset/Disco-key invalidation: reset or cancel quality
  state as appropriate.
- `handlePongConnLocked`: complete CLI callbacks normally; before an ordinary
  direct candidate is promoted, start or reuse a candidate quality burst.
- `discoPingTimeout` and `forgetDiscoPing`: record candidate burst failures.
- `udpRelayEndpointReady`: no quality gating.

## Test Plan

### Policy tests

- DERP 5 ms versus direct 29 ms: keep DERP.
- DERP 400 ms versus direct 30 ms: switch to direct.
- Equal-cost direct recovery from DERP: switch to direct.
- Direct-to-direct small improvement: keep current.
- Direct-to-direct material improvement: switch.
- Candidate loss and jitter penalties.
- Candidate unreachable and insufficient samples.

### State-machine tests

- Current-path rolling window eviction.
- Candidate mixed success/failure accounting.
- Burst completion-order preservation when seeding the new path.
- Stale generation and cancelled burst results.
- Path change during a burst.
- Candidate endpoint removal during a burst.
- Only one active soft evaluation per endpoint.

### Regression tests

- CLI Disco Pong still invokes its callback.
- Ordinary wrong-source CLI/Discovery behavior is unchanged from `origin/main`.
- Quality Pongs never perform ordinary promotion or update Pong history.
- Peer-relay and same-relay behavior remains unchanged.
- WireGuard-only peers remain unchanged.
- Legacy best-address timeout clearing remains unchanged.

### Commands

```bash
go test ./wgengine/magicsock -run 'Test.*PathQuality' -count=1
go test -race ./wgengine/magicsock -run 'Test.*PathQuality' -count=1
go test ./wgengine/magicsock -count=1
go vet ./wgengine/magicsock
git diff --check
```

Run Linux and Windows amd64 builds according to `BUILD.md` and
`.github/workflows/build.yml`. Verify executable formats and version output.

## Acceptance Criteria

- A slower direct candidate never replaces a faster current path.
- A materially better direct candidate is eventually selected.
- No direct-path health mode or retirement policy is introduced.
- `tailscale ping`, `tailscale ping --icmp`, and `tailscale ping --tsmp` retain
  their existing behavior.
- State remains bounded and stale probe results cannot affect a newer path.
- Targeted tests, race tests, vet, and required builds pass.

## Implementation Status (2026-07-22)

Implemented on `direct-candidate-path-quality` from `origin/main` commit
`71b90de0d`, without `MagicsockPathHealthMode` or direct-path retirement state.

Validation completed:

- Path-quality targeted unit tests: passed.
- Path-quality targeted race tests: passed.
- Full `wgengine/magicsock` package tests: passed.
- `go vet ./wgengine/magicsock`: passed.
- Linux amd64 `tailscale` and `tailscaled`: built as stripped static ELF
  x86-64 executables.
- Windows amd64 `tailscale.exe` and `tailscaled.exe`: built as PE32+ console
  executables.
- Windows amd64 `tailscale-ipn.exe`: built as a PE32+ GUI executable.
