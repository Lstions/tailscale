// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"math/bits"
	"slices"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/tstime/mono"
)

// pathQualityWindowSamples is intentionally small so path selection reacts to
// network changes without retaining much per-peer state.
const pathQualityWindowSamples = 16

const pathQualityMaxBurstSamples = 30

type pathReachability uint8

const (
	pathReachabilityUnknown pathReachability = iota
	pathReachabilityUsable
	pathReachabilityUnreachable
)

// pathQualitySnapshot is a bounded view of one path. It is independent from
// path selection so the decision policy can be tested without sockets or
// timers.
type pathQualitySnapshot struct {
	reachability pathReachability
	samples      uint8
	confidence   uint8
	lossRate     float64
	mean         time.Duration
	p50          time.Duration
	p95          time.Duration
	jitter       time.Duration
	observedAt   mono.Time
}

type pathQualityProfile struct {
	BurstSamples        uint8
	MinSamples          uint8
	MaxAge              time.Duration
	AbsoluteMargin      time.Duration
	RelativeImprovement float64
	TailWeight          float64
	JitterWeight        float64
	LossPenalty         time.Duration
}

var defaultPathQualityProfile = pathQualityProfile{
	BurstSamples:        10,
	MinSamples:          3,
	MaxAge:              45 * time.Second,
	AbsoluteMargin:      25 * time.Millisecond,
	RelativeImprovement: 0.10,
	TailWeight:          0.25,
	JitterWeight:        0.25,
	LossPenalty:         2 * time.Second,
}

// pathQualityMonitor is the rolling quality window for the path currently in
// use. Candidate paths are measured by a short, disposable burst instead.
type pathQualityMonitor struct {
	path         epAddr
	probeBits    uint16
	probeSamples uint8
	latencies    [pathQualityWindowSamples]time.Duration
	latencyCount uint8
	latencyNext  uint8
	lastProbeAt  mono.Time
}

func (m *pathQualityMonitor) reset(path epAddr) {
	*m = pathQualityMonitor{path: path}
}

func (m *pathQualityMonitor) note(success bool, latency time.Duration, at mono.Time) {
	success = success && latency > 0
	m.probeBits <<= 1
	if success {
		m.probeBits |= 1
	}
	m.latencies[m.latencyNext] = 0
	if success {
		m.latencies[m.latencyNext] = latency
	}
	m.latencyNext = (m.latencyNext + 1) % pathQualityWindowSamples
	if m.latencyCount < pathQualityWindowSamples {
		m.latencyCount++
	}
	if m.probeSamples < pathQualityWindowSamples {
		m.probeSamples++
	}
	m.lastProbeAt = at
}

func (m *pathQualityMonitor) snapshot(now mono.Time, p pathQualityProfile) (pathQualitySnapshot, bool) {
	if m == nil || !m.path.ap.IsValid() || m.probeSamples == 0 {
		return pathQualitySnapshot{}, false
	}
	latencies := make([]time.Duration, 0, m.latencyCount)
	for i := range int(m.latencyCount) {
		idx := int(m.latencyNext) - 1 - i
		if idx < 0 {
			idx += pathQualityWindowSamples
		}
		if latency := m.latencies[idx]; latency > 0 {
			latencies = append(latencies, latency)
		}
	}
	return makePathQualitySnapshot(now, m.probeSamples, bits.OnesCount16(m.probeBits), latencies, m.lastProbeAt, p)
}

type pathQualityBurstSample struct {
	success bool
	latency time.Duration
	at      mono.Time
}

// pathQualityBurst preserves completion order so a selected candidate can
// seed the rolling monitor without reconstructing an arbitrary sample order.
type pathQualityBurst struct {
	target      uint8
	completed   uint8
	received    uint8
	latencies   [pathQualityMaxBurstSamples]time.Duration
	samples     [pathQualityMaxBurstSamples]pathQualityBurstSample
	lastProbeAt mono.Time
}

func (b *pathQualityBurst) note(success bool, latency time.Duration, at mono.Time) {
	if b.completed >= b.target {
		return
	}
	success = success && latency > 0
	b.samples[b.completed] = pathQualityBurstSample{success: success, latency: latency, at: at}
	b.completed++
	if success {
		b.latencies[b.received] = latency
		b.received++
	}
	b.lastProbeAt = at
}

func (b *pathQualityBurst) done() bool { return b.target != 0 && b.completed >= b.target }

func (b *pathQualityBurst) snapshot(now mono.Time, p pathQualityProfile) (pathQualitySnapshot, bool) {
	latencies := append([]time.Duration(nil), b.latencies[:b.received]...)
	return makePathQualitySnapshot(now, b.completed, int(b.received), latencies, b.lastProbeAt, p)
}

type pathQualityEvaluation struct {
	generation uint32
	current    epAddr
	candidate  addrQuality
	burst      pathQualityBurst
}

type pathQualityDecision uint8

const (
	pathQualityKeep pathQualityDecision = iota
	pathQualitySwitch
	pathQualityNeedSamples
)

func (s pathQualitySnapshot) valid(now mono.Time, p pathQualityProfile) bool {
	if s.reachability != pathReachabilityUsable || s.samples < p.MinSamples || s.p50 <= 0 || s.observedAt.IsZero() {
		return false
	}
	return now.Sub(s.observedAt) <= p.MaxAge
}

func effectivePathCost(s pathQualitySnapshot, p pathQualityProfile) time.Duration {
	cost := float64(s.p50)
	cost += p.TailWeight * float64(maxDuration(0, s.p95-s.p50))
	cost += p.JitterWeight * float64(s.jitter)
	cost += float64(p.LossPenalty) * s.lossRate
	if cost <= 0 {
		return 0
	}
	return time.Duration(cost)
}

func makePathQualitySnapshot(now mono.Time, samples uint8, successes int, latencies []time.Duration, observedAt mono.Time, p pathQualityProfile) (pathQualitySnapshot, bool) {
	s := pathQualitySnapshot{
		reachability: pathReachabilityUnreachable,
		samples:      samples,
		confidence:   uint8(min(int(samples)*100/pathQualityWindowSamples, 100)),
		observedAt:   observedAt,
	}
	if samples != 0 {
		s.lossRate = 1 - float64(successes)/float64(samples)
	}
	if len(latencies) == 0 {
		fresh := !observedAt.IsZero() && now.Sub(observedAt) <= p.MaxAge
		return s, samples >= p.MinSamples && fresh
	}
	s.reachability = pathReachabilityUsable
	slices.Sort(latencies)
	var total time.Duration
	for _, latency := range latencies {
		total += latency
	}
	s.mean = total / time.Duration(len(latencies))
	s.p50 = latencies[(len(latencies)-1)/2]
	p95Index := (len(latencies)*95+99)/100 - 1
	p95Index = max(0, min(p95Index, len(latencies)-1))
	s.p95 = latencies[p95Index]
	var deviation time.Duration
	for _, latency := range latencies {
		deviation += maxDuration(latency, s.p50) - minDuration(latency, s.p50)
	}
	s.jitter = deviation / time.Duration(len(latencies))
	return s, s.valid(now, p)
}

func comparePathQuality(now mono.Time, current, candidate pathQualitySnapshot, p pathQualityProfile) pathQualityDecision {
	if candidate.reachability == pathReachabilityUnreachable {
		return pathQualityKeep
	}
	if current.reachability == pathReachabilityUnreachable {
		if candidate.valid(now, p) {
			return pathQualitySwitch
		}
		return pathQualityNeedSamples
	}
	if !current.valid(now, p) || !candidate.valid(now, p) {
		return pathQualityNeedSamples
	}

	currentCost := effectivePathCost(current, p)
	candidateCost := effectivePathCost(candidate, p)
	if currentCost <= 0 || candidateCost <= 0 || candidateCost >= currentCost {
		return pathQualityKeep
	}
	if currentCost-candidateCost < p.AbsoluteMargin ||
		float64(candidateCost) > float64(currentCost)*(1-p.RelativeImprovement) {
		return pathQualityKeep
	}
	return pathQualitySwitch
}

func comparePathQualityForPaths(now mono.Time, currentPath epAddr, current pathQualitySnapshot, candidatePath epAddr, candidate pathQualitySnapshot, p pathQualityProfile) pathQualityDecision {
	decision := comparePathQuality(now, current, candidate, p)
	if decision == pathQualityKeep && candidatePath.isDirect() && !currentPath.isDirect() &&
		current.valid(now, p) && candidate.valid(now, p) &&
		effectivePathCost(candidate, p) <= effectivePathCost(current, p) {
		// Prefer direct only when measured quality is no worse. In particular,
		// direct preference must never override a comparison that found the
		// candidate slower than the current DERP or peer-relay path.
		return pathQualitySwitch
	}
	return decision
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (de *endpoint) currentPathLocked() epAddr {
	if de.bestAddr.ap.IsValid() {
		return de.bestAddr.epAddr
	}
	if de.derpAddr.IsValid() {
		return epAddr{ap: de.derpAddr}
	}
	return epAddr{}
}

func (de *endpoint) resetCurrentPathQualityLocked(path epAddr) {
	if !path.ap.IsValid() {
		de.currentPathQuality = nil
		return
	}
	if de.currentPathQuality == nil {
		de.currentPathQuality = new(pathQualityMonitor)
	}
	de.currentPathQuality.reset(path)
}

func (de *endpoint) noteCurrentPathProbeLocked(sp sentPing, success bool, latency time.Duration, at mono.Time) {
	if sp.purpose != pingHeartbeat {
		return
	}
	current := de.currentPathLocked()
	if !current.ap.IsValid() || sp.to != current {
		return
	}
	if de.currentPathQuality == nil || de.currentPathQuality.path != current {
		de.resetCurrentPathQualityLocked(current)
	}
	de.currentPathQuality.note(success, latency, at)
}

// deferDirectCandidateSwitchLocked starts a candidate-only quality burst. The
// current path is sampled continuously by heartbeat and is never burst-probed.
func (de *endpoint) deferDirectCandidateSwitchLocked(candidate addrQuality, now mono.Time) bool {
	if de.heartbeatDisabled || !candidate.isDirect() || de.disco.Load() == nil {
		// Without heartbeat sampling there is no current-path quality window
		// to compare. Preserve the legacy promotion behavior instead of
		// permanently withholding direct connectivity.
		return false
	}
	current := de.currentPathLocked()
	if !current.ap.IsValid() || current == candidate.epAddr {
		return false
	}
	if de.pathQualityEvaluation != nil {
		if de.pathQualityEvaluation.candidate.epAddr == candidate.epAddr &&
			candidate.wireMTU > de.pathQualityEvaluation.candidate.wireMTU {
			de.pathQualityEvaluation.candidate.wireMTU = candidate.wireMTU
		}
		return true
	}
	target := min(defaultPathQualityProfile.BurstSamples, uint8(pathQualityMaxBurstSamples))
	if target == 0 {
		return false
	}
	de.pathQualityGeneration++
	if de.pathQualityGeneration == 0 {
		de.pathQualityGeneration++
	}
	e := &pathQualityEvaluation{
		generation: de.pathQualityGeneration,
		current:    current,
		candidate:  candidate,
	}
	e.burst.target = target
	de.pathQualityEvaluation = e
	for range int(target) {
		de.startPathQualityProbeLocked(candidate.epAddr, now, e.generation)
	}
	return true
}

func (de *endpoint) startPathQualityProbeLocked(candidate epAddr, now mono.Time, generation uint32) {
	epDisco := de.disco.Load()
	if epDisco == nil {
		return
	}
	txid := stun.NewTxID()
	de.sentPing[txid] = sentPing{
		to:                    candidate,
		at:                    now,
		timer:                 time.AfterFunc(pingTimeoutDuration, func() { de.discoPingTimeout(txid) }),
		purpose:               pingPathQuality,
		pathQualityGeneration: generation,
	}
	de.lastSendAny = now
	go de.sendDiscoPing(candidate, epDisco.key, txid, 0, discoVerboseLog)
}

func (de *endpoint) recordPathQualityProbeLocked(sp sentPing, success bool, latency time.Duration, now mono.Time) {
	e := de.pathQualityEvaluation
	if e == nil || sp.pathQualityGeneration == 0 || sp.pathQualityGeneration != e.generation || sp.to != e.candidate.epAddr {
		return
	}
	e.burst.note(success, latency, now)
	if e.burst.done() {
		de.finishPathQualityEvaluationLocked(now)
	}
}

func (de *endpoint) currentPathQualitySnapshotLocked(now mono.Time) (pathQualitySnapshot, bool) {
	current := de.currentPathLocked()
	if de.currentPathQuality == nil || de.currentPathQuality.path != current {
		return pathQualitySnapshot{}, false
	}
	return de.currentPathQuality.snapshot(now, defaultPathQualityProfile)
}

func (de *endpoint) finishPathQualityEvaluationLocked(now mono.Time) {
	e := de.pathQualityEvaluation
	if e == nil || de.currentPathLocked() != e.current {
		de.pathQualityEvaluation = nil
		return
	}
	candidate, candidateOK := e.burst.snapshot(now, defaultPathQualityProfile)
	current, currentOK := de.currentPathQualitySnapshotLocked(now)
	decision := pathQualityKeep
	if candidateOK && currentOK {
		decision = comparePathQualityForPaths(now, e.current, current, e.candidate.epAddr, candidate, defaultPathQualityProfile)
	}
	de.pathQualityEvaluation = nil

	if decision != pathQualitySwitch {
		return
	}
	if de.endpointState[e.candidate.ap] == nil {
		return
	}
	next := e.candidate
	next.latency = candidate.p50
	if de.c != nil {
		de.c.logf("magicsock: disco: node %v %v now using quality-checked direct path %v mtu=%v", de.publicKey.ShortString(), de.discoShort(), next.epAddr, next.wireMTU)
	}
	if de.debugUpdates != nil {
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "pathQuality-bestAddr-update",
			From: de.bestAddr,
			To:   next,
		})
	}
	de.setBestAddrLocked(next)
	de.bestAddrAt = now
	de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
	de.seedCurrentPathQualityLocked(e.candidate.epAddr, &e.burst)
}

func (de *endpoint) seedCurrentPathQualityLocked(path epAddr, burst *pathQualityBurst) {
	de.resetCurrentPathQualityLocked(path)
	if de.currentPathQuality == nil || burst == nil {
		return
	}
	for _, sample := range burst.samples[:burst.completed] {
		de.currentPathQuality.note(sample.success, sample.latency, sample.at)
	}
}

func (de *endpoint) cancelPathQualityEvaluationLocked() {
	if de.pathQualityEvaluation == nil {
		return
	}
	generation := de.pathQualityEvaluation.generation
	de.pathQualityEvaluation = nil
	for txid, sp := range de.sentPing {
		if sp.pathQualityGeneration == generation {
			de.removeSentDiscoPingLocked(txid, sp, discoPingResultUnknown)
		}
	}
}
