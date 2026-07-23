// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func newPathQualityTestEndpoint(current, candidate epAddr, paired bool) (*endpoint, *pathQualityEvaluation) {
	c := &Conn{logf: func(string, ...any) {}}
	de := &endpoint{
		c:                   c,
		bestAddr:            addrQuality{epAddr: current},
		derpAddr:            current.ap,
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		endpointState:       map[netip.AddrPort]*endpointState{candidate.ap: {index: 0}},
		candidateCooldown:   make(map[netip.AddrPort]mono.Time),
		sentPing:            make(map[stun.TxID]sentPing),
	}
	if current.ap.Addr() == tailcfg.DerpMagicIPAddr {
		de.bestAddr = addrQuality{}
		de.derpAddr = current.ap
		de.pathState = pathDERPActive
		de.sendMode = sendDERPOnly
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	e := &pathQualityEvaluation{
		generation:    1,
		current:       current,
		candidate:     addrQuality{epAddr: candidate},
		previousState: de.pathState,
		paired:        paired,
		inflight:      1,
	}
	e.candidateB.reset()
	if paired {
		e.currentB.reset()
		e.inflight = 2
	}
	de.pathQualityEvaluation = e
	return de, e
}

func recordQualityPairRound(de *endpoint, e *pathQualityEvaluation, currentOK, candidateOK bool, at mono.Time) {
	// Record candidate first so the current probe completes the round and may
	// synchronously run the evaluation decision.
	de.recordPathQualityProbeLocked(sentPing{
		pathQualityGeneration: e.generation,
		pathQualityProbeRole:  qualityCandidate,
		to:                    e.candidate.epAddr,
	}, candidateOK, 20*time.Millisecond, at)
	de.recordPathQualityProbeLocked(sentPing{
		pathQualityGeneration: e.generation,
		pathQualityProbeRole:  qualityCurrent,
		to:                    e.current,
	}, currentOK, 400*time.Millisecond, at)
}

func TestPathQualityWindowRetainsDiscreteLoss(t *testing.T) {
	base := mono.Now()
	path := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	m := new(pathQualityMonitor)
	m.reset(path)
	for i := range directQualityWindowSamples {
		m.note(i != 0, 50*time.Millisecond, base.Add(time.Duration(i)*time.Millisecond))
	}
	s, ok := m.snapshot(base.Add(time.Second))
	if !ok {
		t.Fatal("quality window is not usable")
	}
	if s.samples != directQualityWindowSamples || s.successes != directQualityWindowSamples-1 {
		t.Fatalf("window = %+v; want 16 samples and 15 successes", s)
	}
	if got := effectivePathCost(s); got < 100*time.Millisecond {
		t.Fatalf("effective cost = %v; loss penalty was not applied", got)
	}
}

func TestDirectHeartbeatFailureHysteresis(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		lateHeartbeats:      make(map[stun.TxID]sentPing),
	}
	for i := uint64(1); i <= 3; i++ {
		de.recordDirectHeartbeatFailureLocked(sentPing{
			to: addr, at: now.Add(-time.Duration(10-i) * time.Second),
			purpose: pingHeartbeat, heartbeatGeneration: 1, heartbeatSeq: i,
		}, now, "test-timeout")
		switch i {
		case 1:
			if de.pathState != pathDirectSuspect || de.sendMode != sendDirectOnly {
				t.Fatalf("after first failure: state=%v mode=%v", de.pathState, de.sendMode)
			}
		case 2:
			if de.sendMode != sendDirectAndDERP || de.bestAddr.epAddr != addr {
				t.Fatalf("after second failure: state=%v mode=%v best=%v", de.pathState, de.sendMode, de.bestAddr)
			}
		}
	}
	if de.pathState != pathDERPActive || de.sendMode != sendDERPOnly || de.bestAddr.ap.IsValid() {
		t.Fatalf("after confirmation: state=%v mode=%v best=%v", de.pathState, de.sendMode, de.bestAddr)
	}
}

func TestOrdinaryDiscoveryTimeoutDoesNotClearDirectPath(t *testing.T) {
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		trustBestAddrUntil:  mono.Now().Add(-time.Second),
		heartbeatGeneration: 1,
		sentPing: map[stun.TxID]sentPing{txid: {
			to: addr, at: mono.Now().Add(-time.Second), timer: timer,
			purpose: pingDiscovery, lifecycleGeneration: 1,
		}},
	}
	de.discoPingTimeout(txid)
	if de.bestAddr.epAddr != addr {
		t.Fatalf("ordinary discovery timeout cleared bestAddr: %v", de.bestAddr)
	}
}

func TestLateHeartbeatPongRestoresSuspectPath(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
	}
	sp := sentPing{to: addr, at: now.Add(-time.Second), purpose: pingHeartbeat, heartbeatGeneration: 1, heartbeatSeq: 1}
	de.recordDirectHeartbeatFailureLocked(sp, now, "heartbeat-timeout")
	if de.pathState != pathDirectSuspect {
		t.Fatalf("after timeout: %v", de.pathState)
	}
	de.recordDirectHeartbeatSuccessLocked(sp, now.Add(time.Millisecond))
	if de.pathState != pathDirectHealthy || de.directFailureStreak != 0 {
		t.Fatalf("late pong did not restore path: state=%v streak=%d", de.pathState, de.directFailureStreak)
	}
}

func TestAddrForSendLockedUsesFailureHysteresis(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	derp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
	de := &endpoint{
		bestAddr:            addrQuality{epAddr: addr},
		derpAddr:            derp,
		pathState:           pathDirectSuspect,
		sendMode:            sendDirectOnly,
		directFailureStreak: 1,
		trustBestAddrUntil:  now.Add(-time.Second),
		heartbeatGeneration: 1,
	}
	udp, gotDERP, _ := de.addrForSendLocked(now)
	if udp != addr || gotDERP.IsValid() {
		t.Fatalf("first failure selected udp=%v derp=%v", udp, gotDERP)
	}
	de.directFailureStreak = 2
	de.sendMode = sendDirectAndDERP
	udp, gotDERP, _ = de.addrForSendLocked(now)
	if udp != addr || gotDERP != derp {
		t.Fatalf("second failure selected udp=%v derp=%v", udp, gotDERP)
	}
}

func TestWrongSourceDoesNotBecomeCandidate(t *testing.T) {
	now := mono.Now()
	requested := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	observed := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:41641")}
	txid := stun.NewTxID()
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()},
		bestAddr:            addrQuality{epAddr: requested},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		endpointState: map[netip.AddrPort]*endpointState{
			requested.ap: {}, observed.ap: {index: 0},
		},
		sentPing: map[stun.TxID]sentPing{txid: {
			to: requested, at: now.Add(-10 * time.Millisecond), purpose: pingHeartbeat,
			heartbeatGeneration: 1, heartbeatSeq: 1,
		}},
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.mu.Lock()
	de.handleWrongSourceLocked(de.sentPing[txid], observed, now)
	gotBest, gotState, gotPings := de.bestAddr.epAddr, de.pathState, len(de.sentPing)
	de.mu.Unlock()
	if gotBest != requested {
		t.Fatalf("wrong source changed bestAddr to %v", gotBest)
	}
	if gotState != pathDirectSuspect {
		t.Fatalf("wrong source did not record a heartbeat failure: %v", gotState)
	}
	if gotPings != 2 {
		t.Fatalf("verification ping count = %d; want original and one verification", gotPings)
	}
}

func TestPairedAdmissionPrefersLowLatencyDirect(t *testing.T) {
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:41641")}
	de := &endpoint{
		c:             &Conn{logf: func(string, ...any) {}},
		derpAddr:      derp.ap,
		endpointState: map[netip.AddrPort]*endpointState{candidate.ap: {index: 0}},
		sentPing:      make(map[stun.TxID]sentPing),
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 7, current: derp, candidate: addrQuality{epAddr: candidate},
			paired: true, rounds: admissionSamples, inflight: admissionSamples * 2,
		},
	}
	de.pathQualityEvaluation.currentB.reset()
	de.pathQualityEvaluation.candidateB.reset()
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	now := mono.Now()
	for i := range admissionSamples {
		de.recordPathQualityProbeLocked(sentPing{pathQualityGeneration: 7, pathQualityProbeRole: qualityCurrent, to: derp}, true, 400*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
		de.recordPathQualityProbeLocked(sentPing{pathQualityGeneration: 7, pathQualityProbeRole: qualityCandidate, to: candidate}, true, 20*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.epAddr != candidate {
		t.Fatalf("candidate was not admitted: %v", de.bestAddr)
	}
	if de.pathState != pathDirectHealthy || de.sendMode != sendDirectOnly {
		t.Fatalf("admitted path state = %v/%v", de.pathState, de.sendMode)
	}
}

func TestAddrQualityDebugJSONIsExplicit(t *testing.T) {
	b, err := json.Marshal(EndpointChange{From: addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}, latency: 20 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == `{"From":{}}` {
		t.Fatalf("addrQuality was serialized as an empty object: %s", b)
	}
	if !bytes.Contains(b, []byte(`"addr"`)) || !bytes.Contains(b, []byte(`"path"`)) {
		t.Fatalf("debug JSON lacks address/path: %s", b)
	}
}

func TestPathQualityWindowRotationAndStaleness(t *testing.T) {
	base := mono.Now()
	path := epAddr{ap: netip.MustParseAddrPort("192.0.2.9:41641")}
	m := new(pathQualityMonitor)
	m.reset(path)
	for i := 0; i < directQualityWindowSamples; i++ {
		m.note(i != 0, 10*time.Millisecond, base.Add(time.Duration(i)*time.Millisecond))
	}
	s, ok := m.snapshot(base.Add(time.Second))
	if !ok || s.lossRate != 1/float64(directQualityWindowSamples) {
		t.Fatalf("initial snapshot = %+v, ok=%v", s, ok)
	}
	for i := 0; i < directQualityWindowSamples; i++ {
		m.note(true, 10*time.Millisecond, base.Add(time.Duration(i+directQualityWindowSamples)*time.Millisecond))
	}
	s, ok = m.snapshot(base.Add(2 * time.Second))
	if !ok || s.lossRate != 0 || s.samples != directQualityWindowSamples {
		t.Fatalf("rotated snapshot = %+v, ok=%v", s, ok)
	}
	if _, ok := m.snapshot(base.Add(46 * time.Second)); ok {
		t.Fatal("stale quality snapshot remained usable")
	}

	m.reset(path)
	for i := 0; i < 2; i++ {
		m.note(true, 10*time.Millisecond, base.Add(time.Duration(i)*time.Millisecond))
	}
	if _, ok := m.snapshot(base); ok {
		t.Fatal("two samples were accepted as a quality baseline")
	}
}

func TestDeterministicOnePercentHeartbeatLossKeepsDirect(t *testing.T) {
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.10:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		lateHeartbeats:      make(map[stun.TxID]sentPing),
	}
	base := mono.Now()
	for i := uint64(1); i <= 1000; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		sp := sentPing{
			to: addr, at: at.Add(-50 * time.Millisecond), purpose: pingHeartbeat,
			heartbeatGeneration: 1, heartbeatSeq: i,
		}
		if i%100 == 99 {
			de.recordDirectHeartbeatFailureLocked(sp, at, "heartbeat-timeout")
		} else {
			de.recordDirectHeartbeatSuccessLocked(sp, at)
		}
	}
	if de.pathState != pathDirectHealthy || de.sendMode != sendDirectOnly || de.directFailureStreak != 0 {
		t.Fatalf("1%% isolated loss degraded path: state=%v mode=%v streak=%d", de.pathState, de.sendMode, de.directFailureStreak)
	}
}

func TestHeartbeatSixOfTenAfterSilenceEntersDERP(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.11:41641")}
	de := &endpoint{
		c:                    &Conn{logf: func(string, ...any) {}},
		bestAddr:             addrQuality{epAddr: addr},
		pathState:            pathDirectHealthy,
		sendMode:             sendDirectOnly,
		heartbeatGeneration:  1,
		lastDirectSuccessAt:  now.Add(-7 * time.Second),
		heartbeatResultCount: directHeartbeatWindowSize,
		heartbeatResultNext:  9,
	}
	for i := 0; i < 5; i++ {
		de.heartbeatResults[i] = false
	}
	for i := 5; i < 10; i++ {
		de.heartbeatResults[i] = true
	}
	de.recordDirectHeartbeatFailureLocked(sentPing{
		to: addr, at: now.Add(-time.Millisecond), purpose: pingHeartbeat,
		heartbeatGeneration: 1, heartbeatSeq: 1,
	}, now, "heartbeat-timeout")
	if de.pathState != pathDERPActive || de.sendMode != sendDERPOnly {
		t.Fatalf("6/10 failure window did not enter DERP: state=%v mode=%v", de.pathState, de.sendMode)
	}
}

func TestOldHeartbeatTimeoutAfterLateSuccessIsIgnored(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.12:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
	}
	old := sentPing{to: addr, at: now.Add(-time.Second), purpose: pingHeartbeat, heartbeatGeneration: 1, heartbeatSeq: 1}
	newer := old
	newer.heartbeatSeq = 2
	de.recordDirectHeartbeatFailureLocked(old, now, "heartbeat-timeout")
	de.recordDirectHeartbeatSuccessLocked(newer, now.Add(time.Millisecond))
	de.recordDirectHeartbeatFailureLocked(old, now.Add(2*time.Millisecond), "heartbeat-timeout")
	if de.pathState != pathDirectHealthy || de.directFailureStreak != 0 || de.lastHeartbeatSuccess != 2 {
		t.Fatalf("old timeout changed recovered path: state=%v streak=%d last=%d", de.pathState, de.directFailureStreak, de.lastHeartbeatSuccess)
	}
}

func TestGenerationStaleHeartbeatTimeoutAndPongDoNotChangeNewState(t *testing.T) {
	now := mono.Now()
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.13:41641")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 2,
		lateHeartbeats:      make(map[stun.TxID]sentPing),
		sentPing: map[stun.TxID]sentPing{txid: {
			to: addr, at: now.Add(-time.Second), timer: timer, purpose: pingHeartbeat,
			heartbeatGeneration: 1, lifecycleGeneration: 1, heartbeatSeq: 1,
		}},
	}
	de.discoPingTimeout(txid)
	if de.directFailureStreak != 0 || de.pathState != pathDirectHealthy || len(de.lateHeartbeats) != 1 {
		t.Fatalf("stale timeout changed state: state=%v streak=%d late=%d", de.pathState, de.directFailureStreak, len(de.lateHeartbeats))
	}
	de.lateHeartbeats[txid] = sentPing{
		to: addr, at: now.Add(-time.Second), purpose: pingHeartbeat,
		heartbeatGeneration: 1, lifecycleGeneration: 1, heartbeatSeq: 1,
	}
	de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: addr.ap}, nil, addr)
	if de.directFailureStreak != 0 || de.pathState != pathDirectHealthy {
		t.Fatalf("stale pong changed state: state=%v streak=%d", de.pathState, de.directFailureStreak)
	}
}

func TestUnpairedAdmissionRequiresThreeCurrentSamples(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.20:41641")}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.21:41641")}
	de, e := newPathQualityTestEndpoint(current, candidate, false)
	e.attempt = admissionMaxAttempts - 1
	de.currentPathQuality = new(pathQualityMonitor)
	de.currentPathQuality.reset(current)
	for i := 0; i < 2; i++ {
		de.currentPathQuality.note(true, 50*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	e.rounds = admissionSamples
	e.inflight = admissionSamples
	for i := 0; i < admissionSamples; i++ {
		de.recordPathQualityProbeLocked(sentPing{
			pathQualityGeneration: e.generation, pathQualityProbeRole: qualityCandidate, to: candidate,
		}, true, 20*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.epAddr != current || de.pathQualityEvaluation != nil {
		t.Fatalf("two-sample current baseline was admitted: best=%v eval=%v", de.bestAddr, de.pathQualityEvaluation)
	}
	if _, ok := de.candidateCooldown[candidate.ap]; !ok {
		t.Fatal("failed admission did not enter cooldown")
	}
}

func TestPairedAdmissionRetriesTwoOfThreeThenSucceeds(t *testing.T) {
	now := mono.Now()
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.22:41641")}
	de, e := newPathQualityTestEndpoint(derp, candidate, true)
	e.rounds = admissionSamples
	e.inflight = admissionSamples * 2
	for i := 0; i < admissionSamples; i++ {
		recordQualityPairRound(de, e, true, i < admissionSamples-1, now.Add(time.Duration(i)*time.Millisecond))
	}
	if e.attempt != 1 || e.retryTimer == nil || de.pathQualityEvaluation != e {
		t.Fatalf("2/3 candidate did not schedule exactly one retry: attempt=%d retry=%v eval=%v", e.attempt, e.retryTimer != nil, de.pathQualityEvaluation)
	}
	e.retryTimer.stop()
	e.retryTimer = nil
	e.rounds = admissionSamples
	e.inflight = admissionSamples * 2
	e.currentB.reset()
	e.candidateB.reset()
	for i := 0; i < admissionSamples; i++ {
		recordQualityPairRound(de, e, true, true, now.Add(100*time.Millisecond+time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.epAddr != candidate || de.pathState != pathDirectHealthy || de.pathQualityEvaluation != nil {
		t.Fatalf("successful retry did not admit candidate: best=%v state=%v eval=%v", de.bestAddr, de.pathState, de.pathQualityEvaluation)
	}
}

func TestPairedAdmissionFailureEntersCooldownAndKeepsDERP(t *testing.T) {
	now := mono.Now()
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 2)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.23:41641")}
	de, e := newPathQualityTestEndpoint(derp, candidate, true)
	e.attempt = admissionMaxAttempts - 1
	e.rounds = admissionSamples
	e.inflight = admissionSamples * 2
	for i := 0; i < admissionSamples; i++ {
		recordQualityPairRound(de, e, true, false, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.ap.IsValid() || de.pathState != pathDERPActive {
		t.Fatalf("failed candidate changed DERP path: best=%v state=%v", de.bestAddr, de.pathState)
	}
	if until := de.candidateCooldown[candidate.ap]; !until.After(now) {
		t.Fatalf("candidate cooldown = %v, now=%v", until, now)
	}
}

func TestWorseCandidateDoesNotReplaceCurrentPath(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 3)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.24:41641")}
	de, e := newPathQualityTestEndpoint(current, candidate, true)
	e.attempt = admissionMaxAttempts - 1
	e.rounds = admissionSamples
	e.inflight = admissionSamples * 2
	for i := 0; i < admissionSamples; i++ {
		// Candidate is valid but materially slower than the current DERP path.
		de.recordPathQualityProbeLocked(sentPing{pathQualityGeneration: e.generation, pathQualityProbeRole: qualityCandidate, to: candidate}, true, 700*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
		de.recordPathQualityProbeLocked(sentPing{pathQualityGeneration: e.generation, pathQualityProbeRole: qualityCurrent, to: current}, true, 400*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.ap.IsValid() || de.pathState != pathDERPActive {
		t.Fatalf("worse candidate replaced current path: best=%v state=%v", de.bestAddr, de.pathState)
	}
}

func TestCandidateQueueDeduplicatesAndEnforcesPerPeerAndGlobalBounds(t *testing.T) {
	c := &Conn{logf: func(string, ...any) {}}
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.30:41641")}
	de := &endpoint{
		c:                   c,
		bestAddr:            addrQuality{epAddr: current},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		endpointState:       make(map[netip.AddrPort]*endpointState),
		candidateCooldown:   make(map[netip.AddrPort]mono.Time),
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 1, current: current, candidate: addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.99:41641")}},
		},
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	for i := 0; i < pathCandidateQueueMax+1; i++ {
		ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(31 + i)}), 41641)
		de.endpointState[ap] = &endpointState{index: 0}
		de.deferDirectCandidateSwitchLocked(addrQuality{epAddr: epAddr{ap: ap}}, mono.Now())
	}
	first := de.pendingQualityCandidates[0]
	de.deferDirectCandidateSwitchLocked(first, mono.Now())
	if len(de.pendingQualityCandidates) != pathCandidateQueueMax {
		t.Fatalf("pending candidate count=%d, want %d", len(de.pendingQualityCandidates), pathCandidateQueueMax)
	}
	c.qualityMu.Lock()
	gotPending := c.qualityPending
	c.qualityMu.Unlock()
	if gotPending != pathCandidateQueueMax {
		t.Fatalf("global pending count=%d, want %d", gotPending, pathCandidateQueueMax)
	}
	de.deleteEndpointLocked("test", de.pendingQualityCandidates[0].ap)
	c.qualityMu.Lock()
	gotPending = c.qualityPending
	c.qualityMu.Unlock()
	if gotPending != pathCandidateQueueMax-1 {
		t.Fatalf("deleting pending candidate leaked global slot: %d", gotPending)
	}
	de.clearPendingQualityCandidatesLocked()
}

func TestQualityResourceBoundsAndTimerCancellation(t *testing.T) {
	c := &Conn{}
	for i := 0; i < qualityActiveEvaluationMax; i++ {
		if !c.reserveQualityEvaluation() {
			t.Fatalf("evaluation %d was rejected below active limit", i)
		}
	}
	if c.reserveQualityEvaluation() {
		t.Fatal("active evaluation limit was not enforced")
	}
	for i := 0; i < qualityActiveEvaluationMax; i++ {
		c.releaseQualityEvaluation()
	}
	if !c.reserveQualityPending() {
		t.Fatal("pending slot was unexpectedly unavailable")
	}
	c.releaseQualityPending()
	if !c.reserveQualityRoundResources(qualityActiveSendTaskMax + 1) {
		// The request is intentionally too large and must not partially reserve.
	} else {
		t.Fatal("oversized round resource reservation succeeded")
	}
	if c.qualityTimers != 0 || c.qualitySendTasks != 0 {
		t.Fatalf("failed reservation leaked resources: timers=%d tasks=%d", c.qualityTimers, c.qualitySendTasks)
	}
	s := newQualityTimer(c, time.Hour, func() {})
	if s == nil {
		t.Fatal("timer reservation unexpectedly failed")
	}
	if c.qualityTimers != 1 {
		t.Fatalf("active timer count=%d, want 1", c.qualityTimers)
	}
	s.stop()
	if c.qualityTimers != 0 {
		t.Fatalf("stopped timer leaked slot: %d", c.qualityTimers)
	}
}

func TestQualityBudgetIsRaceSafe(t *testing.T) {
	c := &Conn{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if c.reserveQualityEvaluation() {
					c.releaseQualityEvaluation()
				}
				if c.reserveQualityPending() {
					c.releaseQualityPending()
				}
				if c.reserveQualityRoundResources(1) {
					c.releaseQualityRoundResources(1)
				}
			}
		}()
	}
	wg.Wait()
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityActive != 0 || c.qualityPending != 0 || c.qualityTimers != 0 || c.qualitySendTasks != 0 {
		t.Fatalf("budget counters not quiescent: active=%d pending=%d timers=%d tasks=%d", c.qualityActive, c.qualityPending, c.qualityTimers, c.qualitySendTasks)
	}
}

func TestWrongSourceProvenanceAndCLIDoNotPromote(t *testing.T) {
	now := mono.Now()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.40:41641")}
	b := epAddr{ap: netip.MustParseAddrPort("192.0.2.41:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()},
		bestAddr:            addrQuality{epAddr: a},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		endpointState: map[netip.AddrPort]*endpointState{
			a.ap: {}, b.ap: {index: indexSentinelDeleted},
		},
		isCallMeMaybeEP:   make(map[netip.AddrPort]bool),
		candidateCooldown: make(map[netip.AddrPort]mono.Time),
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.mu.Lock()
	defer de.mu.Unlock()
	de.handleWrongSourceLocked(sentPing{to: a, purpose: pingDiscovery}, b, now)
	if _, ok := de.candidateCooldown[a.ap]; !ok {
		t.Fatal("discovery wrong-source did not cool down requested endpoint")
	}
	de.candidateCooldown = make(map[netip.AddrPort]mono.Time)
	de.handleWrongSourceLocked(sentPing{to: a, purpose: pingCLI}, b, now)
	if len(de.candidateCooldown) != 0 || len(de.sentPing) != 0 {
		t.Fatalf("CLI wrong-source modified path state: cooldown=%v sent=%d", de.candidateCooldown, len(de.sentPing))
	}
	de.isCallMeMaybeEP[b.ap] = true
	de.handleWrongSourceLocked(sentPing{to: a, purpose: pingHeartbeat}, b, now)
	if de.endpointState[b.ap].verificationGeneration != 1 {
		t.Fatal("CMM-known observed source did not receive verification request")
	}
	for txid, sp := range de.sentPing {
		de.removeSentDiscoPingLocked(txid, sp, discoPingResultUnknown)
	}
}

func TestCandidateVerificationRechecksLifecycleBeforeSend(t *testing.T) {
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.50:41641")}
	b := epAddr{ap: netip.MustParseAddrPort("192.0.2.51:41641")}
	discoKey := key.NewDisco().Public()
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		heartbeatGeneration: 7,
		endpointState:       map[netip.AddrPort]*endpointState{b.ap: {index: 0}},
		sentPing:            make(map[stun.TxID]sentPing),
	}
	de.disco.Store(&endpointDisco{key: discoKey})
	txid := stun.NewTxID()
	de.sentPing[txid] = sentPing{to: b, purpose: pingCandidateVerification, lifecycleGeneration: 7}
	delete(de.endpointState, b.ap)
	de.sendCandidateVerificationPing(b, discoKey, txid, 7)
	if len(de.sentPing) != 0 {
		t.Fatal("stale verification task remained after endpoint deletion")
	}
	_ = a // Keep the requested/source distinction explicit in this test.
}

func TestHandlePongDiscoveryStartsPairedAdmission(t *testing.T) {
	c := newConn(func(string, ...any) {})
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.60:41641")}
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	de := &endpoint{
		c:                   c,
		nodeID:              1,
		publicKey:           key.NewNode().Public(),
		bestAddr:            addrQuality{},
		derpAddr:            derp.ap,
		pathState:           pathDERPActive,
		sendMode:            sendDERPOnly,
		heartbeatGeneration: 1,
		endpointState:       map[netip.AddrPort]*endpointState{candidate.ap: {index: 0}},
		sentPing:            make(map[stun.TxID]sentPing),
		candidateCooldown:   make(map[netip.AddrPort]mono.Time),
	}
	discoKey := key.NewDisco().Public()
	de.disco.Store(&endpointDisco{key: discoKey})
	c.peerMap.upsertEndpoint(de, key.DiscoPublic{})
	c.mu.Lock()
	c.closed = true // Keep admission bookkeeping, but make asynchronous sends no-op.
	c.mu.Unlock()
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: candidate, at: mono.Now().Add(-20 * time.Millisecond), timer: timer, purpose: pingDiscovery}
	de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: candidate.ap}, nil, candidate)
	de.mu.Lock()
	e := de.pathQualityEvaluation
	if e == nil || !e.paired || e.current != derp || e.candidate.epAddr != candidate || de.pathState != pathDirectProbing {
		de.mu.Unlock()
		t.Fatalf("discovery Pong did not start paired admission: eval=%+v state=%v", e, de.pathState)
	}
	de.cancelPathQualityEvaluationLocked()
	de.mu.Unlock()
}

func TestRecoveryProbeIsImmediateSingleMinimalPacketAndOneShot(t *testing.T) {
	c := &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()}
	c.discoAtomic.Set(key.NewDisco())
	a := netip.MustParseAddrPort("192.0.2.70:41641")
	b := netip.MustParseAddrPort("[2001:db8::70]:41641")
	de := &endpoint{
		c:             c,
		endpointState: map[netip.AddrPort]*endpointState{a: {}, b: {}},
		sentPing:      make(map[stun.TxID]sentPing),
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.mu.Lock()
	c.mu.Lock() // Hold Conn.mu so the asynchronous send tasks cannot remove sentPing before inspection.
	de.forceRecoveryDiscoveryLocked(mono.Now())
	if !de.forceRecoveryUsed || len(de.sentPing) != 2 {
		c.mu.Unlock()
		de.mu.Unlock()
		t.Fatalf("force recovery sent=%d used=%v", len(de.sentPing), de.forceRecoveryUsed)
	}
	for _, sp := range de.sentPing {
		if sp.purpose != pingRecovery || sp.size != 0 {
			c.mu.Unlock()
			de.mu.Unlock()
			t.Fatalf("recovery probe = purpose %v size %d; want minimal recovery", sp.purpose, sp.size)
		}
	}
	de.forceRecoveryDiscoveryLocked(mono.Now())
	if len(de.sentPing) != 2 {
		t.Fatalf("second force recovery created duplicate probes: %d", len(de.sentPing))
	}
	c.mu.Unlock()
	de.cancelBackgroundPingsLocked()
	de.mu.Unlock()
}

func TestRecoveryAndQualityProbeDoNotExpandPMTU(t *testing.T) {
	c := &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()}
	c.peerMTUEnabled.Store(true)
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.71:41641")}
	de := &endpoint{
		c:             c,
		endpointState: map[netip.AddrPort]*endpointState{candidate.ap: {}},
		sentPing:      make(map[stun.TxID]sentPing),
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.mu.Lock()
	c.mu.Lock()
	de.startDiscoPingLocked(candidate, mono.Now(), pingRecovery, 0, nil)
	if len(de.sentPing) != 1 {
		c.mu.Unlock()
		de.mu.Unlock()
		t.Fatalf("recovery probe count=%d, want 1", len(de.sentPing))
	}
	for _, sp := range de.sentPing {
		if sp.purpose != pingRecovery || sp.size != 0 {
			c.mu.Unlock()
			de.mu.Unlock()
			t.Fatalf("recovery probe expanded PMTU: purpose=%v size=%d", sp.purpose, sp.size)
		}
	}
	de.cancelBackgroundPingsLocked()
	c.mu.Unlock()
	de.mu.Unlock()
}

func TestVerificationPongStartsAdmissionWithoutDirectPromotion(t *testing.T) {
	now := mono.Now()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.80:41641")}
	b := epAddr{ap: netip.MustParseAddrPort("[2001:db8::80]:41641")}
	discoKey := key.NewDisco().Public()
	txid := stun.NewTxID()
	c := &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()}
	c.discoAtomic.Set(key.NewDisco())
	de := &endpoint{
		c:                   c,
		bestAddr:            addrQuality{epAddr: a},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 4,
		endpointState:       map[netip.AddrPort]*endpointState{a.ap: {index: 0}, b.ap: {index: 0}},
		sentPing: map[stun.TxID]sentPing{txid: {
			to: b, at: now.Add(-20 * time.Millisecond), purpose: pingCandidateVerification,
			lifecycleGeneration: 4,
		}},
	}
	de.disco.Store(&endpointDisco{key: discoKey})
	de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: b.ap}, nil, b)
	de.mu.Lock()
	defer de.mu.Unlock()
	if de.bestAddr.epAddr != a {
		t.Fatalf("verification Pong directly promoted B: %v", de.bestAddr)
	}
	if de.pathQualityEvaluation == nil || de.pathQualityEvaluation.candidate.ap != b.ap {
		t.Fatalf("verification Pong did not enter B admission: eval=%+v", de.pathQualityEvaluation)
	}
	de.cancelPathQualityEvaluationLocked()
}

func TestPairedProbesUseOneDecisionWindow(t *testing.T) {
	now := mono.Now()
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 4)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.81:41641")}
	de, e := newPathQualityTestEndpoint(derp, candidate, true)
	e.rounds = admissionSamples
	e.inflight = admissionSamples * 2
	for i := 0; i < admissionSamples; i++ {
		recordQualityPairRound(de, e, true, true, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.epAddr != candidate {
		t.Fatalf("paired candidate was not admitted: %v", de.bestAddr)
	}
	var minAt, maxAt mono.Time
	for _, sample := range e.candidateB.samples[:e.candidateB.completed] {
		if minAt == 0 || sample.at.Before(minAt) {
			minAt = sample.at
		}
		if sample.at.After(maxAt) {
			maxAt = sample.at
		}
	}
	if maxAt.Sub(minAt) != 2*time.Millisecond {
		t.Fatalf("candidate burst was not recorded in one decision window: %v", maxAt.Sub(minAt))
	}
}

func TestNonHeartbeatTimeoutsDoNotAdvanceDirectFailureStreak(t *testing.T) {
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.90:41641")}
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		sentPing:            make(map[stun.TxID]sentPing),
	}
	for _, purpose := range []discoPingPurpose{pingDiscovery, pingCLI, pingHeartbeatForUDPLifetime} {
		txid := stun.NewTxID()
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		de.sentPing[txid] = sentPing{
			to: addr, at: mono.Now().Add(-time.Second), timer: timer, purpose: purpose,
			lifecycleGeneration: 1,
		}
		de.discoPingTimeout(txid)
	}
	if de.directFailureStreak != 0 || de.pathState != pathDirectHealthy || de.bestAddr.epAddr != addr {
		t.Fatalf("non-heartbeat timeout changed direct health: streak=%d state=%v best=%v", de.directFailureStreak, de.pathState, de.bestAddr)
	}
}

func TestHeartbeatSendErrorUsesFastFailurePath(t *testing.T) {
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.91:41641")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de := &endpoint{
		c:                   &Conn{logf: func(string, ...any) {}},
		bestAddr:            addrQuality{epAddr: addr},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		sentPing: map[stun.TxID]sentPing{txid: {
			to: addr, at: mono.Now().Add(-time.Second), timer: timer, purpose: pingHeartbeat,
			heartbeatGeneration: 1, lifecycleGeneration: 1, heartbeatSeq: 1,
		}},
	}
	de.forgetDiscoPing(txid)
	if de.directFailureStreak != 0 || de.pathState != pathDERPActive || de.sendMode != sendDERPOnly {
		t.Fatalf("heartbeat send error did not use fast DERP path: streak=%d state=%v mode=%v", de.directFailureStreak, de.pathState, de.sendMode)
	}
}

func TestHeartbeatWrongSourceCountsRequestedPathFailure(t *testing.T) {
	now := mono.Now()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.92:41641")}
	b := epAddr{ap: netip.MustParseAddrPort("192.0.2.93:41641")}
	txid := stun.NewTxID()
	c := &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()}
	c.discoAtomic.Set(key.NewDisco())
	de := &endpoint{
		c:                   c,
		bestAddr:            addrQuality{epAddr: a},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 1,
		endpointState:       map[netip.AddrPort]*endpointState{a.ap: {index: 0}, b.ap: {index: 0}},
		sentPing: map[stun.TxID]sentPing{txid: {
			to: a, at: now.Add(-20 * time.Millisecond), purpose: pingHeartbeat,
			heartbeatGeneration: 1, lifecycleGeneration: 1, heartbeatSeq: 1,
		}},
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: b.ap}, nil, b)
	de.mu.Lock()
	defer de.mu.Unlock()
	if de.bestAddr.epAddr != a || de.pathState != pathDirectSuspect || de.directFailureStreak != 1 {
		t.Fatalf("wrong-source heartbeat did not fail A only: best=%v state=%v streak=%d", de.bestAddr, de.pathState, de.directFailureStreak)
	}
	if de.endpointState[b.ap].verificationGeneration != 1 {
		t.Fatal("wrong-source heartbeat did not request B verification")
	}
	de.cancelPathQualityEvaluationLocked()
}

func TestLifecycleCancellationReleasesQualityResources(t *testing.T) {
	c := &Conn{}
	if !c.reserveQualityEvaluation() {
		t.Fatal("failed to reserve test evaluation")
	}
	de := &endpoint{c: c, candidateCooldown: make(map[netip.AddrPort]mono.Time)}
	e := &pathQualityEvaluation{generation: 11, budgeted: true}
	e.probeTimer = newQualityTimer(c, time.Hour, func() {})
	e.retryTimer = newQualityTimer(c, time.Hour, func() {})
	txid := stun.NewTxID()
	qt := newQualityTimer(c, time.Hour, func() {})
	de.sentPing = map[stun.TxID]sentPing{txid: {pathQualityGeneration: 11, timer: qt.timer, qualityTimer: qt}}
	de.pathQualityEvaluation = e
	de.cancelPathQualityEvaluationLocked()
	c.qualityMu.Lock()
	active, timers, tasks := c.qualityActive, c.qualityTimers, c.qualitySendTasks
	c.qualityMu.Unlock()
	if de.pathQualityEvaluation != nil || len(de.sentPing) != 0 || active != 0 || timers != 0 || tasks != 0 {
		t.Fatalf("cancellation leaked quality resources: eval=%v pings=%d active=%d timers=%d tasks=%d", de.pathQualityEvaluation, len(de.sentPing), active, timers, tasks)
	}
}

func TestProbeTokenBucketHonorsBurstAndRefill(t *testing.T) {
	c := &Conn{}
	now := mono.Now()
	if !c.reserveQualityProbes(int(qualityProbeBurst), now) {
		t.Fatal("initial probe burst was rejected")
	}
	if c.reserveQualityProbes(1, now) {
		t.Fatal("probe budget exceeded configured burst")
	}
	if !c.reserveQualityProbes(1, now.Add(time.Second)) {
		t.Fatal("probe budget did not refill at configured rate")
	}
	if c.reserveQualityProbes(int(qualityProbeBurst), now.Add(time.Second)) {
		t.Fatal("probe budget exceeded refill cap")
	}
}

func TestPendingAndActiveEvaluationGlobalLimits(t *testing.T) {
	c := &Conn{}
	for i := 0; i < qualityPendingQueueMax; i++ {
		if !c.reserveQualityPending() {
			t.Fatalf("pending slot %d was rejected below global limit", i)
		}
	}
	if c.reserveQualityPending() {
		t.Fatal("pending candidate global limit was not enforced")
	}
	for i := 0; i < qualityPendingQueueMax; i++ {
		c.releaseQualityPending()
	}
	for i := 0; i < qualityActiveEvaluationMax; i++ {
		if !c.reserveQualityEvaluation() {
			t.Fatalf("active evaluation %d was rejected below global limit", i)
		}
	}
	if c.reserveQualityEvaluation() {
		t.Fatal("active evaluation global limit was not enforced")
	}
	for i := 0; i < qualityActiveEvaluationMax; i++ {
		c.releaseQualityEvaluation()
	}
}

func TestProbeQueueWaitLimitDropsExpiredEvaluation(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 5)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.120:41641")}
	de, e := newPathQualityTestEndpoint(current, candidate, true)
	e.queueAt = now.Add(-pathProbeQueueMaxWait - time.Millisecond)
	de.startPathQualityRoundLocked(e)
	if de.pathQualityEvaluation != nil || de.pathState != pathDERPActive {
		t.Fatalf("expired queued evaluation was not dropped: eval=%v state=%v", de.pathQualityEvaluation, de.pathState)
	}
	if _, ok := de.candidateCooldown[candidate.ap]; !ok {
		t.Fatal("expired queued candidate did not enter cooldown")
	}
}

func TestTwentyPeerPairReservationsStayWithinConnBudget(t *testing.T) {
	c := &Conn{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.reserveQualityProbes(2, mono.Now()) {
				mu.Lock()
				accepted++
				mu.Unlock()
				if c.reserveQualityRoundResources(2) {
					c.releaseQualityRoundResources(2)
				}
			}
		}()
	}
	wg.Wait()
	if accepted > int(qualityProbeBurst)/2 {
		t.Fatalf("accepted %d paired rounds above Conn burst budget", accepted)
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if c.qualityTimers != 0 || c.qualitySendTasks != 0 {
		t.Fatalf("peer budget test leaked resources: timers=%d tasks=%d", c.qualityTimers, c.qualitySendTasks)
	}
}

func TestProbeBudgetRoundRobinPreventsPeerStarvation(t *testing.T) {
	c := &Conn{}
	e1 := &endpoint{}
	e2 := &endpoint{}
	now := mono.Now()
	c.qualityMu.Lock()
	c.qualityTokens = 0
	c.qualityLast = now
	c.qualityMu.Unlock()
	if c.reserveQualityProbesForEndpoint(e1, 2, now) {
		t.Fatal("peer 1 acquired tokens before budget refill")
	}
	if c.reserveQualityProbesForEndpoint(e2, 2, now) {
		t.Fatal("peer 2 acquired tokens before budget refill")
	}
	c.qualityMu.Lock()
	c.qualityTokens = 4
	c.qualityMu.Unlock()
	if c.reserveQualityProbesForEndpoint(e2, 2, now) {
		t.Fatal("peer 2 was incorrectly allowed to bypass peer 1")
	}
	if !c.reserveQualityProbesForEndpoint(e1, 2, now) {
		t.Fatal("peer 1 did not get its queued round")
	}
	if !c.reserveQualityProbesForEndpoint(e2, 2, now) {
		t.Fatal("peer 2 did not get its queued round")
	}
	c.removeQualityProbeEndpoint(e1)
	c.removeQualityProbeEndpoint(e2)
}

func TestDebugEndpointShowsPathStateAndSendMode(t *testing.T) {
	de := &endpoint{
		bestAddr:    addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.100:41641")}},
		pathState:   pathDirectSuspect,
		sendMode:    sendDirectAndDERP,
		lastSendExt: mono.Now(),
		endpointState: map[netip.AddrPort]*endpointState{
			netip.MustParseAddrPort("192.0.2.100:41641"): {},
		},
	}
	var b bytes.Buffer
	printEndpointHTML(&b, de)
	for _, want := range []string{"DirectSuspect", "direct+DERP", "failureStreak"} {
		if !bytes.Contains(b.Bytes(), []byte(want)) {
			t.Fatalf("debug endpoint output missing %q: %s", want, b.String())
		}
	}
}

func TestPathIdentityChangeAdvancesGenerationAndCancelsAdmission(t *testing.T) {
	c := &Conn{}
	if !c.reserveQualityEvaluation() {
		t.Fatal("failed to reserve evaluation")
	}
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.101:41641")}
	b := epAddr{ap: netip.MustParseAddrPort("192.0.2.102:41641")}
	de := &endpoint{
		c:                   c,
		bestAddr:            addrQuality{epAddr: a},
		pathState:           pathDirectHealthy,
		sendMode:            sendDirectOnly,
		heartbeatGeneration: 9,
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 1, candidate: addrQuality{epAddr: b}, budgeted: true,
		},
		candidateCooldown: make(map[netip.AddrPort]mono.Time),
	}
	de.setBestAddrLocked(addrQuality{epAddr: b})
	c.qualityMu.Lock()
	active := c.qualityActive
	c.qualityMu.Unlock()
	if de.heartbeatGeneration != 10 || de.pathQualityEvaluation != nil || active != 0 {
		t.Fatalf("path identity change did not isolate old evaluation: generation=%d eval=%v active=%d", de.heartbeatGeneration, de.pathQualityEvaluation, active)
	}
}

func TestRecoveryDiscoverySkipsFreshAndCooldownCandidates(t *testing.T) {
	now := mono.Now()
	a := netip.MustParseAddrPort("192.0.2.110:41641")
	b := netip.MustParseAddrPort("192.0.2.111:41641")
	candidate := netip.MustParseAddrPort("192.0.2.112:41641")
	c := &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()}
	c.discoAtomic.Set(key.NewDisco())
	c.closed = true // async sends should return before touching a socket
	de := &endpoint{
		c:             c,
		pathState:     pathDERPActive,
		endpointState: map[netip.AddrPort]*endpointState{},
		sentPing:      make(map[stun.TxID]sentPing),
		candidateCooldown: map[netip.AddrPort]mono.Time{
			candidate: now.Add(pathCandidateCooldown),
		},
	}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	de.endpointState[a] = &endpointState{lastPing: now.Add(-discoPingInterval - time.Second)}
	de.endpointState[b] = &endpointState{lastPing: now}
	de.endpointState[candidate] = &endpointState{lastPing: now.Add(-discoPingInterval - time.Second)}
	de.mu.Lock()
	defer de.mu.Unlock()
	de.recoveryDiscoveryLocked(now)
	if de.lastFullPing != now {
		t.Fatalf("recovery discovery did not record a sent recovery round: %v", de.lastFullPing)
	}
	for _, sp := range de.sentPing {
		if sp.to.ap != a {
			t.Fatalf("recovery discovery probed %v; expected only stale non-cooldown A", sp.to)
		}
		if sp.purpose != pingRecovery || sp.size != 0 {
			t.Fatalf("unexpected recovery probe: purpose=%v size=%d", sp.purpose, sp.size)
		}
	}
	de.cancelBackgroundPingsLocked()
}
