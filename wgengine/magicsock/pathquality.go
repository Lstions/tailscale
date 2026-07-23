// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

// This file contains the path-quality state machine.  It deliberately does
// not make path selection decisions from a single probe: heartbeat reachability
// and path admission are separate, bounded mechanisms.

import (
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

const (
	directQualityWindowSamples = 16
	directHeartbeatWindowSize  = 10
	admissionSamples           = 3
	admissionProbeTimeout      = 550 * time.Millisecond
	admissionRetryDelay        = 200 * time.Millisecond
	admissionMaxAttempts       = 2
	pathCandidateCooldown      = 30 * time.Second
	pathProbeQueueMaxWait      = 2 * time.Second
	pathCandidateQueueMax      = 4
	qualityPendingQueueMax     = 256
	qualityActiveEvaluationMax = qualityPendingQueueMax
	qualityActiveTimerMax      = qualityPendingQueueMax * 3 // 2 probe timers + 1 scheduling timer per evaluation
	qualityActiveSendTaskMax   = qualityPendingQueueMax * 2 // one current/candidate pair per round
	qualityProbeRate           = 20.0
	qualityProbeBurst          = 40.0
)

type directPathState uint8

const (
	pathDERPActive directPathState = iota
	pathDirectHealthy
	pathDirectSuspect
	pathDirectProbing
)

func (s directPathState) String() string {
	switch s {
	case pathDirectHealthy:
		return "DirectHealthy"
	case pathDirectSuspect:
		return "DirectSuspect"
	case pathDirectProbing:
		return "DirectProbing"
	default:
		return "DERPActive"
	}
}

type directSendMode uint8

const (
	sendDERPOnly directSendMode = iota
	sendDirectOnly
	sendDirectAndDERP
)

func (m directSendMode) String() string {
	switch m {
	case sendDirectOnly:
		return "direct-only"
	case sendDirectAndDERP:
		return "direct+DERP"
	default:
		return "DERP-only"
	}
}

type pathQualitySample struct {
	success bool
	latency time.Duration
	at      mono.Time
}

type pathQualitySnapshot struct {
	samples    uint8
	successes  uint8
	lossRate   float64
	p50        time.Duration
	p95        time.Duration
	jitter     time.Duration
	observedAt mono.Time
}

type pathQualityMonitor struct {
	path epAddr
	s    [directQualityWindowSamples]pathQualitySample
	n    uint8
	next uint8
	last mono.Time
}

func (m *pathQualityMonitor) reset(path epAddr) {
	*m = pathQualityMonitor{path: path}
}

func (m *pathQualityMonitor) note(success bool, latency time.Duration, at mono.Time) {
	if m == nil {
		return
	}
	success = success && latency > 0
	m.s[m.next] = pathQualitySample{success: success, latency: latency, at: at}
	m.next = (m.next + 1) % directQualityWindowSamples
	if m.n < directQualityWindowSamples {
		m.n++
	}
	m.last = at
}

func (m *pathQualityMonitor) snapshot(now mono.Time) (pathQualitySnapshot, bool) {
	if m == nil || !m.path.ap.IsValid() || m.n < 3 || m.last.IsZero() || now.Sub(m.last) > 45*time.Second {
		return pathQualitySnapshot{}, false
	}
	var lat []time.Duration
	var successes uint8
	for i := range int(m.n) {
		idx := int(m.next) - 1 - i
		if idx < 0 {
			idx += directQualityWindowSamples
		}
		if m.s[idx].success {
			successes++
			lat = append(lat, m.s[idx].latency)
		}
	}
	s := pathQualitySnapshot{
		samples:    m.n,
		successes:  successes,
		lossRate:   1 - float64(successes)/float64(m.n),
		observedAt: m.last,
	}
	if len(lat) == 0 {
		return s, false
	}
	slices.Sort(lat)
	s.p50 = lat[(len(lat)-1)/2]
	p95 := (len(lat)*95 + 99) / 100
	if p95 > len(lat) {
		p95 = len(lat)
	}
	s.p95 = lat[p95-1]
	for _, v := range lat {
		if v > s.p50 {
			s.jitter += v - s.p50
		} else {
			s.jitter += s.p50 - v
		}
	}
	s.jitter /= time.Duration(len(lat))
	return s, true
}

func effectivePathCost(s pathQualitySnapshot) time.Duration {
	return time.Duration(float64(s.p50) + .25*float64(s.p95-s.p50) + .25*float64(s.jitter) + float64(2*time.Second)*s.lossRate)
}

type qualityBurst struct {
	target    uint8
	completed uint8
	successes uint8
	samples   [admissionSamples]pathQualitySample
}

func (b *qualityBurst) reset() { *b = qualityBurst{target: admissionSamples} }

func (b *qualityBurst) note(success bool, latency time.Duration, at mono.Time) {
	if b.completed >= b.target || b.completed >= admissionSamples {
		return
	}
	success = success && latency > 0
	b.samples[b.completed] = pathQualitySample{success: success, latency: latency, at: at}
	b.completed++
	if success {
		b.successes++
	}
}

func (b *qualityBurst) done() bool { return b.target != 0 && b.completed >= b.target }

type pathQualityProbeRole uint8

const (
	qualityCandidate pathQualityProbeRole = iota
	qualityCurrent
)

type pathQualityEvaluation struct {
	generation    uint64
	current       epAddr
	candidate     addrQuality
	previousState directPathState
	paired        bool
	attempt       uint8
	rounds        uint8
	inflight      uint8
	currentB      qualityBurst
	candidateB    qualityBurst
	probeTimer    *qualityTimerSlot
	retryTimer    *qualityTimerSlot
	queueAt       mono.Time
	budgeted      bool
}

// qualityTimerSlot makes every timer created by the path-quality state machine
// participate in the Conn-wide timer bound. The once guard is important when
// a timer callback races with cancellation: exactly one side releases the
// accounting slot.
type qualityTimerSlot struct {
	timer    *time.Timer
	conn     *Conn
	released atomic.Bool
}

func newQualityTimer(c *Conn, d time.Duration, f func()) *qualityTimerSlot {
	return newQualityTimerWithReservation(c, d, false, f)
}

func newQualityTimerWithReservation(c *Conn, d time.Duration, reserved bool, f func()) *qualityTimerSlot {
	if !reserved && c != nil && !c.reserveQualityTimers(1) {
		return nil
	}
	s := &qualityTimerSlot{conn: c}
	s.timer = time.AfterFunc(d, func() {
		s.release()
		f()
	})
	return s
}

func (s *qualityTimerSlot) release() {
	if s == nil || !s.released.CompareAndSwap(false, true) {
		return
	}
	if s.conn != nil {
		s.conn.releaseQualityTimers()
	}
}

func (s *qualityTimerSlot) stop() {
	if s == nil {
		return
	}
	if s.timer == nil || s.timer.Stop() {
		s.release()
	}
}

func (de *endpoint) scheduleQualityTimerLocked(d time.Duration, f func()) *qualityTimerSlot {
	return newQualityTimer(de.c, d, f)
}

func (de *endpoint) currentPathLocked() epAddr {
	if de.bestAddr.ap.IsValid() && (de.pathState != pathDERPActive || de.heartbeatGeneration == 0) {
		return de.bestAddr.epAddr
	}
	if de.derpAddr.IsValid() {
		return epAddr{ap: de.derpAddr}
	}
	return epAddr{}
}

func (de *endpoint) advanceHeartbeatGenerationLocked() {
	de.heartbeatGeneration++
	if de.heartbeatGeneration == 0 {
		de.heartbeatGeneration++
	}
	de.heartbeatSeq = 0
	de.lastHeartbeatSuccess = 0
	de.lastDirectSuccessAt = 0
	de.directFailureStreak = 0
	de.heartbeatResultCount = 0
	de.heartbeatResultNext = 0
	if de.lateHeartbeats == nil {
		de.lateHeartbeats = make(map[stun.TxID]sentPing)
	} else {
		clear(de.lateHeartbeats)
	}
}

func (de *endpoint) noteHeartbeatResultLocked(success bool) {
	de.heartbeatResults[de.heartbeatResultNext] = success
	de.heartbeatResultNext = (de.heartbeatResultNext + 1) % directHeartbeatWindowSize
	if de.heartbeatResultCount < directHeartbeatWindowSize {
		de.heartbeatResultCount++
	}
}

func (de *endpoint) heartbeatWindowFailuresLocked() int {
	n := 0
	for i := range int(de.heartbeatResultCount) {
		if !de.heartbeatResults[i] {
			n++
		}
	}
	return n
}

func (de *endpoint) recordDirectHeartbeatSuccessLocked(sp sentPing, now mono.Time) {
	if sp.purpose != pingHeartbeat || sp.heartbeatGeneration != de.heartbeatGeneration ||
		sp.to != de.bestAddr.epAddr || !sp.to.isDirect() || sp.heartbeatSeq == 0 {
		return
	}
	if sp.heartbeatSeq > de.lastHeartbeatSuccess {
		de.lastHeartbeatSuccess = sp.heartbeatSeq
	}
	if de.lastDirectSuccessAt.IsZero() || now.After(de.lastDirectSuccessAt) {
		de.lastDirectSuccessAt = now
	}
	de.directFailureStreak = 0
	de.noteHeartbeatResultLocked(true)
	de.noteCurrentPathProbeLocked(sp, true, now.Sub(sp.at), now)
	de.transitionPathStateLocked(pathDirectHealthy, "heartbeat-success")
}

func (de *endpoint) recordDirectHeartbeatFailureLocked(sp sentPing, now mono.Time, reason string) {
	if sp.purpose != pingHeartbeat || sp.heartbeatGeneration != de.heartbeatGeneration ||
		sp.to != de.bestAddr.epAddr || !sp.to.isDirect() || sp.heartbeatSeq == 0 ||
		sp.heartbeatSeq <= de.lastHeartbeatSuccess || (!de.lastDirectSuccessAt.IsZero() && !sp.at.After(de.lastDirectSuccessAt)) {
		return
	}
	de.noteHeartbeatResultLocked(false)
	de.noteCurrentPathProbeLocked(sp, false, 0, now)
	de.directFailureStreak++
	if reason == "heartbeat-send-error" || de.directFailureStreak >= 3 ||
		(de.heartbeatResultCount >= directHeartbeatWindowSize && de.heartbeatWindowFailuresLocked() >= 6 &&
			(now.Sub(de.lastDirectSuccessAt) >= trustUDPAddrDuration || de.lastDirectSuccessAt.IsZero())) {
		de.beginDERPActiveLocked(reason)
		return
	}
	de.transitionPathStateLocked(pathDirectSuspect, reason)
}

func (de *endpoint) currentPathQualitySnapshotLocked(now mono.Time) (pathQualitySnapshot, bool) {
	if de.currentPathQuality == nil || de.currentPathQuality.path != de.currentPathLocked() {
		return pathQualitySnapshot{}, false
	}
	s, ok := de.currentPathQuality.snapshot(now)
	if ok && s.observedAt.Add(15*time.Second).Before(now) && de.currentPathLocked().ap.Addr() == tailcfg.DerpMagicIPAddr {
		return pathQualitySnapshot{}, false
	}
	return s, ok
}

func (de *endpoint) noteCurrentPathProbeLocked(sp sentPing, success bool, latency time.Duration, at mono.Time) {
	if sp.purpose != pingHeartbeat || !sp.to.isDirect() || sp.to != de.bestAddr.epAddr {
		return
	}
	if de.currentPathQuality == nil || de.currentPathQuality.path != sp.to {
		de.currentPathQuality = new(pathQualityMonitor)
		de.currentPathQuality.reset(sp.to)
	}
	de.currentPathQuality.note(success, latency, at)
}

func (de *endpoint) deferDirectCandidateSwitchLocked(candidate addrQuality, now mono.Time) bool {
	return de.deferDirectCandidateSwitchAtLocked(candidate, now, 0)
}

func (de *endpoint) deferDirectCandidateSwitchAtLocked(candidate addrQuality, now, queuedAt mono.Time) bool {
	if de.heartbeatDisabled {
		return false
	}
	if de.candidateCooldown == nil {
		de.candidateCooldown = make(map[netip.AddrPort]mono.Time)
	}
	if !candidate.isDirect() || de.disco.Load() == nil || de.endpointState[candidate.ap] == nil {
		return false
	}
	if until := de.candidateCooldown[candidate.ap]; !until.IsZero() && now.Before(until) {
		metricPathCooldownHits.Add(1)
		return true
	}
	delete(de.candidateCooldown, candidate.ap)
	current := de.currentPathLocked()
	if !current.ap.IsValid() || current == candidate.epAddr {
		return false
	}
	if e := de.pathQualityEvaluation; e != nil {
		if e.candidate.ap == candidate.ap {
			if candidate.wireMTU > e.candidate.wireMTU {
				e.candidate.wireMTU = candidate.wireMTU
			}
			return true
		}
		for _, p := range de.pendingQualityCandidates {
			if p.ap == candidate.ap {
				return true
			}
		}
		if len(de.pendingQualityCandidates) >= pathCandidateQueueMax || de.c != nil && !de.c.reserveQualityPending() {
			metricPathQueueDropped.Add(1)
			de.candidateCooldown[candidate.ap] = now.Add(pathCandidateCooldown)
			return true
		}
		de.pendingQualityCandidates = append(de.pendingQualityCandidates, candidate)
		if de.pendingQualityCandidateAt == nil {
			de.pendingQualityCandidateAt = make(map[netip.AddrPort]mono.Time)
		}
		de.pendingQualityCandidateAt[candidate.ap] = now
		return true
	}
	de.pathQualityGeneration++
	if de.c != nil && !de.c.reserveQualityEvaluation() {
		metricPathQueueDropped.Add(1)
		de.candidateCooldown[candidate.ap] = now.Add(pathCandidateCooldown)
		return true
	}
	e := &pathQualityEvaluation{
		generation:    de.pathQualityGeneration,
		current:       current,
		candidate:     candidate,
		previousState: de.pathState,
		queueAt:       queuedAt,
		budgeted:      de.c != nil,
		paired:        !func() bool { _, ok := de.currentPathQualitySnapshotLocked(now); return ok }(),
	}
	if e.queueAt.IsZero() {
		e.queueAt = now
	}
	e.candidateB.reset()
	if e.paired {
		e.currentB.reset()
	}
	de.pathQualityEvaluation = e
	de.transitionPathStateLocked(pathDirectProbing, "candidate-admission")
	de.startPathQualityRoundLocked(e)
	return true
}

func (de *endpoint) startPathQualityRoundLocked(e *pathQualityEvaluation) {
	if de.pathQualityEvaluation != e || e.rounds >= admissionSamples || de.disco.Load() == nil {
		return
	}
	now := mono.Now()
	if e.queueAt.IsZero() {
		e.queueAt = now
	}
	if now.Sub(e.queueAt) > pathProbeQueueMaxWait {
		de.failPathQualityEvaluationLocked(now, "probe-queue-timeout")
		return
	}
	need := 1
	if e.paired {
		need = 2
	}
	if de.c != nil && !de.c.reserveQualityRoundResources(need) {
		if e.probeTimer == nil {
			e.probeTimer = de.scheduleQualityTimerLocked(50*time.Millisecond, func() { de.pathQualityProbeTick(e.generation) })
			if e.probeTimer == nil {
				de.failPathQualityEvaluationLocked(now, "probe-resource-limit")
			}
		}
		return
	}
	if de.c != nil && !de.c.reserveQualityProbesForEndpoint(de, need, now) {
		de.c.releaseQualityRoundResources(need)
		if e.probeTimer == nil {
			e.probeTimer = de.scheduleQualityTimerLocked(50*time.Millisecond, func() { de.pathQualityProbeTick(e.generation) })
			if e.probeTimer == nil {
				de.failPathQualityEvaluationLocked(now, "probe-timer-limit")
			}
		}
		return
	}
	e.rounds++
	e.inflight = 0
	if e.paired {
		if de.startPathQualityPingLocked(e.current, e.generation, qualityCurrent, true) {
			e.inflight++
		}
	}
	if de.startPathQualityPingLocked(e.candidate.epAddr, e.generation, qualityCandidate, true) {
		e.inflight++
	}
	if e.inflight == 0 {
		de.failPathQualityEvaluationLocked(now, "probe-send-limit")
	}
}

func (de *endpoint) pathQualityProbeTick(generation uint64) {
	de.mu.Lock()
	de.startPathQualityRoundLocked(de.pathQualityEvaluationIf(generation))
	de.mu.Unlock()
}

func (de *endpoint) pathQualityEvaluationIf(generation uint64) *pathQualityEvaluation {
	e := de.pathQualityEvaluation
	if e == nil || e.generation != generation {
		return nil
	}
	if e.probeTimer != nil {
		e.probeTimer = nil
	}
	return e
}

func (de *endpoint) startPathQualityPingLocked(to epAddr, generation uint64, role pathQualityProbeRole, resourcesReserved bool) bool {
	epDisco := de.disco.Load()
	if epDisco == nil {
		if resourcesReserved && de.c != nil {
			de.c.releaseQualityRoundResources(1)
		}
		return false
	}
	if de.sentPing == nil {
		de.sentPing = make(map[stun.TxID]sentPing)
	}
	txid := stun.NewTxID()
	now := mono.Now()
	qualityTimer := newQualityTimerWithReservation(de.c, admissionProbeTimeout, resourcesReserved, func() { de.discoPingTimeout(txid) })
	if qualityTimer == nil {
		if resourcesReserved && de.c != nil {
			de.c.releaseQualityRoundResources(1)
		}
		return false
	}
	de.sentPing[txid] = sentPing{
		to: to, at: now, purpose: pingPathQuality, lifecycleGeneration: de.heartbeatGeneration,
		pathQualityGeneration: generation,
		pathQualityProbeRole:  role,
		timer:                 qualityTimer.timer,
		qualityTimer:          qualityTimer,
	}
	de.lastSendAny = now
	go de.sendPathQualityPing(to, epDisco.key, txid, resourcesReserved)
	return true
}

func (de *endpoint) sendPathQualityPing(to epAddr, discoKey key.DiscoPublic, txid stun.TxID, resourcesReserved bool) {
	defer func() {
		if resourcesReserved && de.c != nil {
			de.c.releaseQualitySendTasks()
		}
	}()
	if de.c == nil {
		de.forgetDiscoPing(txid)
		return
	}
	de.sendDiscoPing(to, discoKey, txid, 0, discoVerboseLog)
}

func (de *endpoint) recordPathQualityProbeLocked(sp sentPing, success bool, latency time.Duration, now mono.Time) {
	e := de.pathQualityEvaluation
	if e == nil || sp.pathQualityGeneration != e.generation || e.inflight == 0 {
		return
	}
	if sp.pathQualityProbeRole == qualityCurrent {
		if sp.to != e.current {
			return
		}
		e.currentB.note(success, latency, now)
		if de.currentPathQuality == nil || de.currentPathQuality.path != e.current {
			de.currentPathQuality = new(pathQualityMonitor)
			de.currentPathQuality.reset(e.current)
		}
		de.currentPathQuality.note(success, latency, now)
	} else {
		if sp.to != e.candidate.epAddr {
			return
		}
		e.candidateB.note(success, latency, now)
	}
	e.inflight--
	if e.inflight != 0 {
		return
	}
	if e.rounds < admissionSamples {
		if e.probeTimer == nil {
			e.probeTimer = de.scheduleQualityTimerLocked(50*time.Millisecond, func() { de.pathQualityProbeTick(e.generation) })
			if e.probeTimer == nil {
				de.failPathQualityEvaluationLocked(now, "probe-timer-limit")
			}
		}
		return
	}
	de.finishPathQualityEvaluationLocked(now)
}

func (de *endpoint) finishPathQualityEvaluationLocked(now mono.Time) {
	e := de.pathQualityEvaluation
	if e == nil {
		return
	}
	currentOK := e.currentB.done() && e.currentB.successes == admissionSamples
	if !e.paired {
		_, currentOK = de.currentPathQualitySnapshotLocked(now)
	}
	candidateOK := e.candidateB.done() && e.candidateB.successes == admissionSamples
	if (!candidateOK || !currentOK) && e.attempt+1 < admissionMaxAttempts && ((e.candidateB.successes == 2) || currentOK == false && e.candidateB.successes == admissionSamples) {
		e.attempt++
		if e.probeTimer != nil {
			e.probeTimer.stop()
			e.probeTimer = nil
		}
		if e.retryTimer == nil {
			e.retryTimer = de.scheduleQualityTimerLocked(admissionRetryDelay, func() {
				de.mu.Lock()
				if e2 := de.pathQualityEvaluation; e2 == e {
					e2.retryTimer = nil
					e2.rounds = 0
					e2.inflight = 0
					e2.currentB.reset()
					e2.candidateB.reset()
					de.startPathQualityRoundLocked(e2)
				}
				de.mu.Unlock()
			})
			if e.retryTimer == nil {
				de.failPathQualityEvaluationLocked(now, "retry-timer-limit")
			}
		}
		return
	}
	if !candidateOK || !currentOK {
		de.failPathQualityEvaluationLocked(now, "admission-failed")
		return
	}
	var currentCost time.Duration
	if e.paired {
		currentCost = burstCost(e.currentB)
	} else if s, ok := de.currentPathQualitySnapshotLocked(now); ok {
		currentCost = effectivePathCost(s)
	}
	candidateCost := burstCost(e.candidateB)
	if candidateCost > currentCost || currentCost <= 0 {
		de.failPathQualityEvaluationLocked(now, "candidate-quality-worse")
		return
	}
	if de.endpointState[e.candidate.ap] == nil || de.disco.Load() == nil || de.currentPathLocked() != e.current {
		de.failPathQualityEvaluationLocked(now, "candidate-stale")
		return
	}
	de.pathQualityEvaluation = nil
	if e.budgeted && de.c != nil {
		de.c.releaseQualityEvaluation()
	}
	if e.probeTimer != nil {
		e.probeTimer.stop()
		e.probeTimer = nil
	}
	if e.retryTimer != nil {
		e.retryTimer.stop()
		e.retryTimer = nil
	}
	next := e.candidate
	next.latency = candidateP50(e.candidateB)
	de.setBestAddrLocked(next)
	de.bestAddrAt = now
	de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
	de.transitionPathStateLocked(pathDirectHealthy, "candidate-admitted")
	de.seedCurrentPathQualityLocked(next.epAddr, &e.candidateB)
	de.startNextQualityCandidateLocked(now)
}

func burstCost(b qualityBurst) time.Duration {
	var lat []time.Duration
	for _, s := range b.samples[:b.completed] {
		if s.success {
			lat = append(lat, s.latency)
		}
	}
	if len(lat) == 0 {
		return 0
	}
	slices.Sort(lat)
	p50 := lat[(len(lat)-1)/2]
	p95 := lat[len(lat)-1]
	var jitter time.Duration
	for _, v := range lat {
		if v > p50 {
			jitter += v - p50
		} else {
			jitter += p50 - v
		}
	}
	jitter /= time.Duration(len(lat))
	loss := 1 - float64(b.successes)/float64(max(1, int(b.completed)))
	return time.Duration(float64(p50) + .25*float64(p95-p50) + .25*float64(jitter) + float64(2*time.Second)*loss)
}

func candidateP50(b qualityBurst) time.Duration {
	var lat []time.Duration
	for _, s := range b.samples[:b.completed] {
		if s.success {
			lat = append(lat, s.latency)
		}
	}
	if len(lat) == 0 {
		return 0
	}
	slices.Sort(lat)
	return lat[(len(lat)-1)/2]
}

func (de *endpoint) seedCurrentPathQualityLocked(path epAddr, b *qualityBurst) {
	de.currentPathQuality = new(pathQualityMonitor)
	de.currentPathQuality.reset(path)
	for _, s := range b.samples[:b.completed] {
		de.currentPathQuality.note(s.success, s.latency, s.at)
	}
}

func (de *endpoint) failPathQualityEvaluationLocked(now mono.Time, reason string) {
	e := de.pathQualityEvaluation
	if e == nil {
		return
	}
	if e.probeTimer != nil {
		e.probeTimer.stop()
		e.probeTimer = nil
	}
	if e.retryTimer != nil {
		e.retryTimer.stop()
		e.retryTimer = nil
	}
	if de.candidateCooldown == nil {
		de.candidateCooldown = make(map[netip.AddrPort]mono.Time)
	}
	delete(de.candidateCooldown, e.candidate.ap)
	de.candidateCooldown[e.candidate.ap] = now.Add(pathCandidateCooldown)
	de.cancelPathQualityEvaluationLocked()
	if de.bestAddr.ap.IsValid() {
		if e.previousState == pathDirectSuspect && de.directFailureStreak > 0 {
			de.transitionPathStateLocked(pathDirectSuspect, reason)
		} else {
			de.transitionPathStateLocked(pathDirectHealthy, reason)
		}
	} else {
		de.transitionPathStateLocked(pathDERPActive, reason)
	}
	de.startNextQualityCandidateLocked(now)
}

func (de *endpoint) cancelPathQualityEvaluationLocked() {
	e := de.pathQualityEvaluation
	if e == nil {
		return
	}
	if e.probeTimer != nil {
		e.probeTimer.stop()
		e.probeTimer = nil
	}
	if e.retryTimer != nil {
		e.retryTimer.stop()
		e.retryTimer = nil
	}
	de.pathQualityEvaluation = nil
	if de.c != nil {
		de.c.removeQualityProbeEndpoint(de)
	}
	if e.budgeted && de.c != nil {
		de.c.releaseQualityEvaluation()
	}
	for txid, sp := range de.sentPing {
		if sp.pathQualityGeneration == e.generation {
			de.removeSentDiscoPingLocked(txid, sp, discoPingResultUnknown)
		}
	}
}

func (de *endpoint) clearPendingQualityCandidatesLocked() {
	if de.c != nil {
		for range de.pendingQualityCandidates {
			de.c.releaseQualityPending()
		}
	}
	de.pendingQualityCandidates = nil
	de.pendingQualityCandidateAt = nil
}

func (de *endpoint) startNextQualityCandidateLocked(now mono.Time) {
	if de.pathQualityEvaluation != nil || len(de.pendingQualityCandidates) == 0 {
		return
	}
	next := de.pendingQualityCandidates[0]
	de.pendingQualityCandidates = de.pendingQualityCandidates[1:]
	queuedAt := mono.Time(0)
	if de.pendingQualityCandidateAt != nil {
		queuedAt = de.pendingQualityCandidateAt[next.ap]
		delete(de.pendingQualityCandidateAt, next.ap)
	}
	if de.c != nil {
		de.c.releaseQualityPending()
	}
	de.deferDirectCandidateSwitchAtLocked(next, now, queuedAt)
}

func (de *endpoint) transitionPathStateLocked(next directPathState, reason string) {
	old := de.pathState
	de.pathState = next
	switch next {
	case pathDirectHealthy:
		de.sendMode = sendDirectOnly
	case pathDirectSuspect:
		if de.directFailureStreak >= 2 {
			de.sendMode = sendDirectAndDERP
		} else {
			de.sendMode = sendDirectOnly
		}
	case pathDirectProbing:
		if !de.bestAddr.ap.IsValid() {
			de.sendMode = sendDERPOnly
		}
	case pathDERPActive:
		de.sendMode = sendDERPOnly
	}
	if old == next {
		if reason != "" && reason != "heartbeat-success" && de.debugUpdates != nil {
			de.debugUpdates.Add(EndpointChange{When: time.Now(), What: "path-state-action-" + reason, From: old.String(), To: next.String()})
		}
		return
	}
	metricPathStateTransitions.Add(1)
	if de.debugUpdates != nil {
		de.debugUpdates.Add(EndpointChange{When: time.Now(), What: "path-state-" + reason, From: old.String(), To: next.String()})
	}
	if de.c != nil && old != next {
		de.c.dlogf("magicsock: path state peer=%v %v -> %v reason=%s mode=%s", de.publicKey.ShortString(), old, next, reason, de.sendMode)
	}
}

// beginDERPActiveLocked is only called for a confirmed direct failure.  The
// force discovery below is intentionally not part of clearBestAddrLocked.
func (de *endpoint) beginDERPActiveLocked(reason string) {
	de.cancelPathQualityEvaluationLocked()
	de.clearPendingQualityCandidatesLocked()
	de.cancelBackgroundPingsLocked()
	de.advanceHeartbeatGenerationLocked()
	de.setBestAddrLocked(addrQuality{})
	de.bestAddrAt = 0
	de.trustBestAddrUntil = 0
	de.directFailureStreak = 0
	de.transitionPathStateLocked(pathDERPActive, reason)
	de.recoveryGeneration++
	de.forceRecoveryUsed = false
	de.forceRecoveryDiscoveryLocked(mono.Now())
}

func (de *endpoint) cancelBackgroundPingsLocked() {
	for txid, sp := range de.sentPing {
		switch sp.purpose {
		case pingCLI, pingHeartbeatForUDPLifetime:
			continue
		default:
			de.removeSentDiscoPingLocked(txid, sp, discoPingResultUnknown)
		}
	}
}

func (de *endpoint) forceRecoveryDiscoveryLocked(now mono.Time) {
	if de.forceRecoveryUsed || de.disco.Load() == nil || debugNeverDirectUDP() {
		return
	}
	de.forceRecoveryUsed = true
	de.lastFullPing = now
	for ep, st := range de.endpointState {
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked("force-recovery", ep)
			continue
		}
		st.lastPing = now
		de.startDiscoPingLocked(epAddr{ap: ep}, now, pingRecovery, 0, nil)
	}
	if de.derpAddr.IsValid() {
		go de.c.enqueueCallMeMaybe(de.derpAddr, de)
	}
}

func (de *endpoint) recoveryDiscoveryLocked(now mono.Time) {
	if de.pathState != pathDERPActive || de.disco.Load() == nil || debugNeverDirectUDP() {
		return
	}
	var sentAny bool
	for ep, st := range de.endpointState {
		if st.shouldDeleteLocked() {
			de.deleteEndpointLocked("recovery", ep)
			continue
		}
		if !st.lastPing.IsZero() && now.Sub(st.lastPing) < discoPingInterval {
			continue
		}
		if until := de.candidateCooldown[ep]; !until.IsZero() && now.Before(until) {
			continue
		}
		st.lastPing = now
		de.startDiscoPingLocked(epAddr{ap: ep}, now, pingRecovery, 0, nil)
		sentAny = true
	}
	if sentAny {
		de.lastFullPing = now
	}
}

func (de *endpoint) candidateSourceKnownLocked(ap netip.AddrPort) bool {
	st, ok := de.endpointState[ap]
	return ok && (st.index != indexSentinelDeleted || de.isCallMeMaybeEP[ap])
}

func (de *endpoint) handleWrongSourceLocked(sp sentPing, observed epAddr, now mono.Time) {
	// A CLI ping is diagnostic only. Its callback may report the observed
	// source, but it must not alter path quality, cooldown, trust, or bestAddr.
	if sp.purpose == pingCLI {
		return
	}
	if de.candidateCooldown == nil {
		de.candidateCooldown = make(map[netip.AddrPort]mono.Time)
	}
	if sp.to.isDirect() {
		de.candidateCooldown[sp.to.ap] = now.Add(pathCandidateCooldown)
	}
	if sp.purpose == pingHeartbeat && sp.to == de.bestAddr.epAddr {
		de.recordDirectHeartbeatFailureLocked(sp, now, "wrong-source")
	}
	if !observed.isDirect() || !de.candidateSourceKnownLocked(observed.ap) {
		return
	}
	st := de.endpointState[observed.ap]
	if st.verificationGeneration == de.heartbeatGeneration {
		return
	}
	if de.startCandidateVerificationPingLocked(observed, now) {
		st.verificationGeneration = de.heartbeatGeneration
	}
}

// startCandidateVerificationPingLocked starts the one exact-source check used
// after a wrong-source Pong. The endpoint and disco-key checks are repeated in
// the send task: endpoint deletion and key rotation can happen after this
// function returns but before the goroutine gets scheduled.
func (de *endpoint) startCandidateVerificationPingLocked(to epAddr, now mono.Time) bool {
	if de.c == nil || !to.isDirect() || !de.candidateSourceKnownLocked(to.ap) {
		return false
	}
	epDisco := de.disco.Load()
	if epDisco == nil {
		return false
	}
	if !de.c.reserveQualityRoundResources(1) {
		metricPathQueueDropped.Add(1)
		return false
	}
	if de.sentPing == nil {
		de.sentPing = make(map[stun.TxID]sentPing)
	}
	txid := stun.NewTxID()
	qt := newQualityTimerWithReservation(de.c, pingTimeoutDuration, true, func() { de.discoPingTimeout(txid) })
	if qt == nil {
		de.c.releaseQualityRoundResources(1)
		return false
	}
	generation := de.heartbeatGeneration
	de.sentPing[txid] = sentPing{
		to:                  to,
		at:                  now,
		timer:               qt.timer,
		qualityTimer:        qt,
		purpose:             pingCandidateVerification,
		lifecycleGeneration: generation,
	}
	de.lastSendAny = now
	go func() {
		de.sendCandidateVerificationPing(to, epDisco.key, txid, generation)
		de.c.releaseQualitySendTasks()
	}()
	return true
}

func (de *endpoint) sendCandidateVerificationPing(to epAddr, discoKey key.DiscoPublic, txid stun.TxID, generation uint64) {
	de.mu.Lock()
	sp, ok := de.sentPing[txid]
	currentDisco := de.disco.Load()
	valid := ok && sp.purpose == pingCandidateVerification && sp.to == to &&
		sp.lifecycleGeneration == generation && de.heartbeatGeneration == generation &&
		de.candidateSourceKnownLocked(to.ap) && currentDisco != nil && currentDisco.key == discoKey
	if !valid {
		if ok {
			de.removeSentDiscoPingLocked(txid, sp, discoPingResultUnknown)
		}
		de.mu.Unlock()
		return
	}
	de.mu.Unlock()
	de.sendDiscoPing(to, discoKey, txid, 0, discoVerboseLog)
}

func (de *endpoint) cleanupQualityStateLocked() {
	now := mono.Now()
	for ap, until := range de.candidateCooldown {
		if !now.Before(until) {
			delete(de.candidateCooldown, ap)
		}
	}
}

// reserveQualityProbes implements the Conn-level rate/burst budget.  It never
// waits while holding a Conn or endpoint lock; callers retry from a timer.
func (c *Conn) reserveQualityProbes(n int, now mono.Time) bool {
	return c.reserveQualityProbesForEndpoint(nil, n, now)
}

// reserveQualityProbesForEndpoint gives each endpoint one turn in the Conn
// budget before another turn is granted. The queue is deliberately kept under
// qualityMu and never waits, so timer callbacks remain safe while holding an
// endpoint lock.
func (c *Conn) reserveQualityProbesForEndpoint(de *endpoint, n int, now mono.Time) bool {
	if c == nil || n <= 0 {
		return true
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if de != nil {
		if c.qualityRoundQueued == nil {
			c.qualityRoundQueued = make(map[*endpoint]bool)
		}
		if !c.qualityRoundQueued[de] {
			c.qualityRoundQueued[de] = true
			c.qualityRoundQueue = append(c.qualityRoundQueue, de)
		}
		if len(c.qualityRoundQueue) == 0 || c.qualityRoundQueue[0] != de {
			return false
		}
	}
	if c.qualityLast.IsZero() {
		c.qualityLast = now
		c.qualityTokens = qualityProbeBurst
	}
	d := now.Sub(c.qualityLast).Seconds()
	if d > 0 {
		c.qualityTokens = minFloat(qualityProbeBurst, c.qualityTokens+d*qualityProbeRate)
		c.qualityLast = now
	}
	if c.qualityTokens < float64(n) {
		return false
	}
	c.qualityTokens -= float64(n)
	if de != nil {
		c.qualityRoundQueue = c.qualityRoundQueue[1:]
		delete(c.qualityRoundQueued, de)
	}
	return true
}

func (c *Conn) removeQualityProbeEndpoint(de *endpoint) {
	if c == nil || de == nil {
		return
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityRoundQueued == nil || !c.qualityRoundQueued[de] {
		return
	}
	for i, queued := range c.qualityRoundQueue {
		if queued == de {
			c.qualityRoundQueue = append(c.qualityRoundQueue[:i], c.qualityRoundQueue[i+1:]...)
			break
		}
	}
	delete(c.qualityRoundQueued, de)
}

func (c *Conn) reserveQualityEvaluation() bool {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityActive >= qualityActiveEvaluationMax {
		return false
	}
	c.qualityActive++
	return true
}

func (c *Conn) releaseQualityEvaluation() {
	c.qualityMu.Lock()
	if c.qualityActive > 0 {
		c.qualityActive--
	}
	c.qualityMu.Unlock()
}

func (c *Conn) reserveQualityPending() bool {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityPending >= qualityPendingQueueMax {
		return false
	}
	c.qualityPending++
	return true
}

func (c *Conn) releaseQualityPending() {
	c.qualityMu.Lock()
	if c.qualityPending > 0 {
		c.qualityPending--
	}
	c.qualityMu.Unlock()
}

func (c *Conn) reserveQualityTimers(n int) bool {
	if n <= 0 {
		return true
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityTimers+n > qualityActiveTimerMax {
		return false
	}
	c.qualityTimers += n
	return true
}

func (c *Conn) releaseQualityTimers() {
	c.qualityMu.Lock()
	if c.qualityTimers > 0 {
		c.qualityTimers--
	}
	c.qualityMu.Unlock()
}

func (c *Conn) reserveQualitySendTasks(n int) bool {
	if n <= 0 {
		return true
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualitySendTasks+n > qualityActiveSendTaskMax {
		return false
	}
	c.qualitySendTasks += n
	return true
}

func (c *Conn) releaseQualitySendTasks() {
	c.qualityMu.Lock()
	if c.qualitySendTasks > 0 {
		c.qualitySendTasks--
	}
	c.qualityMu.Unlock()
}

func (c *Conn) reserveQualityRoundResources(n int) bool {
	if n <= 0 || c == nil {
		return true
	}
	if !c.reserveQualityTimers(n) {
		return false
	}
	if !c.reserveQualitySendTasks(n) {
		for i := 0; i < n; i++ {
			c.releaseQualityTimers()
		}
		return false
	}
	return true
}

func (c *Conn) releaseQualityRoundResources(n int) {
	if c == nil || n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		c.releaseQualityTimers()
		c.releaseQualitySendTasks()
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
