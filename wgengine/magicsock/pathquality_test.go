// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/disco"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/ringlog"
)

func usablePathQuality(now mono.Time, latency time.Duration) pathQualitySnapshot {
	return pathQualitySnapshot{
		reachability: pathReachabilityUsable,
		samples:      10,
		p50:          latency,
		p95:          latency,
		observedAt:   now,
	}
}

func TestComparePathQualityPolicy(t *testing.T) {
	now := mono.Now()
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	directA := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	directB := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}

	for _, tt := range []struct {
		name          string
		currentPath   epAddr
		current       pathQualitySnapshot
		candidatePath epAddr
		candidate     pathQualitySnapshot
		want          pathQualityDecision
	}{
		{
			name:          "faster-DERP-keeps-slower-direct",
			currentPath:   derp,
			current:       usablePathQuality(now, 5*time.Millisecond),
			candidatePath: directA,
			candidate:     usablePathQuality(now, 29*time.Millisecond),
			want:          pathQualityKeep,
		},
		{
			name:          "slow-DERP-switches-to-fast-direct",
			currentPath:   derp,
			current:       usablePathQuality(now, 400*time.Millisecond),
			candidatePath: directA,
			candidate:     usablePathQuality(now, 30*time.Millisecond),
			want:          pathQualitySwitch,
		},
		{
			name:          "equal-direct-upgrade-from-DERP",
			currentPath:   derp,
			current:       usablePathQuality(now, 30*time.Millisecond),
			candidatePath: directA,
			candidate:     usablePathQuality(now, 30*time.Millisecond),
			want:          pathQualitySwitch,
		},
		{
			name:          "small-direct-to-direct-improvement",
			currentPath:   directA,
			current:       usablePathQuality(now, 100*time.Millisecond),
			candidatePath: directB,
			candidate:     usablePathQuality(now, 85*time.Millisecond),
			want:          pathQualityKeep,
		},
		{
			name:          "material-direct-to-direct-improvement",
			currentPath:   directA,
			current:       usablePathQuality(now, 100*time.Millisecond),
			candidatePath: directB,
			candidate:     usablePathQuality(now, 40*time.Millisecond),
			want:          pathQualitySwitch,
		},
		{
			name:          "candidate-unreachable",
			currentPath:   derp,
			current:       usablePathQuality(now, 400*time.Millisecond),
			candidatePath: directA,
			candidate: pathQualitySnapshot{
				reachability: pathReachabilityUnreachable,
				samples:      10,
				observedAt:   now,
			},
			want: pathQualityKeep,
		},
		{
			name:          "candidate-needs-samples",
			currentPath:   derp,
			current:       usablePathQuality(now, 400*time.Millisecond),
			candidatePath: directA,
			candidate: pathQualitySnapshot{
				reachability: pathReachabilityUsable,
				samples:      1,
				p50:          20 * time.Millisecond,
				p95:          20 * time.Millisecond,
				observedAt:   now,
			},
			want: pathQualityNeedSamples,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := comparePathQualityForPaths(now, tt.currentPath, tt.current, tt.candidatePath, tt.candidate, defaultPathQualityProfile)
			if got != tt.want {
				t.Fatalf("decision = %v; want %v (current cost %v, candidate cost %v)", got, tt.want, effectivePathCost(tt.current, defaultPathQualityProfile), effectivePathCost(tt.candidate, defaultPathQualityProfile))
			}
		})
	}
}

func TestComparePathQualityPenalizesLossAndJitter(t *testing.T) {
	now := mono.Now()
	current := usablePathQuality(now, 100*time.Millisecond)
	candidate := usablePathQuality(now, 50*time.Millisecond)
	candidate.p95 = 700 * time.Millisecond
	candidate.jitter = 300 * time.Millisecond
	candidate.lossRate = 0.20
	if got := comparePathQuality(now, current, candidate, defaultPathQualityProfile); got != pathQualityKeep {
		t.Fatalf("lossy, jittery candidate decision = %v; want keep (cost %v > %v)", got, effectivePathCost(candidate, defaultPathQualityProfile), effectivePathCost(current, defaultPathQualityProfile))
	}
}

func TestCurrentPathQualityRollingWindow(t *testing.T) {
	now := mono.Now()
	m := &pathQualityMonitor{path: epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}}
	for i := range pathQualityWindowSamples {
		m.note(true, time.Duration(40+i)*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	for i := range pathQualityWindowSamples {
		m.note(false, 0, now.Add(time.Duration(pathQualityWindowSamples+i)*time.Millisecond))
	}
	s, ok := m.snapshot(now.Add(2*pathQualityWindowSamples*time.Millisecond), defaultPathQualityProfile)
	if !ok {
		t.Fatal("complete failure window should produce an unreachable snapshot")
	}
	if s.reachability != pathReachabilityUnreachable || s.lossRate != 1 || s.mean != 0 {
		t.Fatalf("snapshot = %+v; want unreachable, 100%% loss, no stale RTT", s)
	}
}

func TestCurrentDERPPathQualityIsRecorded(t *testing.T) {
	now := mono.Now()
	derpAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
	de := &endpoint{derpAddr: derpAddr}
	sp := sentPing{to: epAddr{ap: derpAddr}, purpose: pingHeartbeat}
	for i, latency := range []time.Duration{400 * time.Millisecond, 500 * time.Millisecond, 600 * time.Millisecond} {
		de.noteCurrentPathProbeLocked(sp, true, latency, now.Add(time.Duration(i)*time.Second))
	}
	de.noteCurrentPathProbeLocked(sp, false, 0, now.Add(3*time.Second))
	s, ok := de.currentPathQualitySnapshotLocked(now.Add(3 * time.Second))
	if !ok {
		t.Fatal("DERP current-path quality snapshot unavailable")
	}
	if s.mean != 500*time.Millisecond || s.lossRate != 0.25 {
		t.Fatalf("DERP mean/loss = %v/%v; want 500ms/0.25", s.mean, s.lossRate)
	}
}

func TestPathQualityCandidateBurstAccounting(t *testing.T) {
	now := mono.Now()
	b := pathQualityBurst{target: 10}
	for i := range 8 {
		b.note(true, time.Duration(100+i*10)*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	b.note(false, 0, now.Add(8*time.Millisecond))
	b.note(false, 0, now.Add(9*time.Millisecond))
	s, ok := b.snapshot(now.Add(9*time.Millisecond), defaultPathQualityProfile)
	if !ok {
		t.Fatal("candidate burst snapshot unavailable")
	}
	if s.samples != 10 || s.lossRate < 0.19 || s.lossRate > 0.21 || s.mean != 135*time.Millisecond {
		t.Fatalf("samples/loss/mean = %d/%v/%v; want 10/0.2/135ms", s.samples, s.lossRate, s.mean)
	}
}

func TestPathQualityEvaluationSwitchesOnlyToBetterDirect(t *testing.T) {
	for _, tt := range []struct {
		name             string
		currentLatency   time.Duration
		candidateLatency time.Duration
		wantSwitch       bool
	}{
		{name: "worse-direct", currentLatency: 5 * time.Millisecond, candidateLatency: 29 * time.Millisecond},
		{name: "better-direct", currentLatency: 400 * time.Millisecond, candidateLatency: 30 * time.Millisecond, wantSwitch: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := mono.Now()
			derpAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
			candidateAddr := netip.MustParseAddrPort("192.0.2.1:7")
			de := &endpoint{
				c:             &Conn{logf: func(string, ...any) {}},
				derpAddr:      derpAddr,
				endpointState: map[netip.AddrPort]*endpointState{candidateAddr: {}},
			}
			de.resetCurrentPathQualityLocked(epAddr{ap: derpAddr})
			for i := range 10 {
				de.currentPathQuality.note(true, tt.currentLatency, now.Add(time.Duration(i)*time.Millisecond))
			}
			de.pathQualityEvaluation = &pathQualityEvaluation{
				generation: 1,
				current:    epAddr{ap: derpAddr},
				candidate:  addrQuality{epAddr: epAddr{ap: candidateAddr}},
				burst:      pathQualityBurst{target: 10},
			}
			for i := range 10 {
				de.recordPathQualityProbeLocked(sentPing{to: epAddr{ap: candidateAddr}, pathQualityGeneration: 1}, true, tt.candidateLatency, now.Add(time.Duration(i)*time.Millisecond))
			}
			if gotSwitch := de.bestAddr.ap == candidateAddr; gotSwitch != tt.wantSwitch {
				t.Fatalf("switched = %v; want %v; best=%v", gotSwitch, tt.wantSwitch, de.bestAddr)
			}
			if tt.wantSwitch && (de.currentPathQuality == nil || de.currentPathQuality.path.ap != candidateAddr || de.currentPathQuality.probeSamples != 10) {
				t.Fatalf("selected candidate did not seed current monitor: %+v", de.currentPathQuality)
			}
		})
	}
}

func TestPathQualityEvaluationNeedsCurrentSamples(t *testing.T) {
	now := mono.Now()
	derpAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
	candidateAddr := netip.MustParseAddrPort("192.0.2.1:7")
	de := &endpoint{
		c:             &Conn{logf: func(string, ...any) {}},
		derpAddr:      derpAddr,
		endpointState: map[netip.AddrPort]*endpointState{candidateAddr: {}},
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 2,
			current:    epAddr{ap: derpAddr},
			candidate:  addrQuality{epAddr: epAddr{ap: candidateAddr}},
			burst:      pathQualityBurst{target: 10},
		},
	}
	for i := range 10 {
		de.recordPathQualityProbeLocked(sentPing{to: epAddr{ap: candidateAddr}, pathQualityGeneration: 2}, true, 20*time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
	}
	if de.bestAddr.ap.IsValid() {
		t.Fatalf("candidate switched without current-path samples: %v", de.bestAddr)
	}
}

func TestSeedCurrentPathQualityPreservesCompletionOrder(t *testing.T) {
	base := mono.Now()
	path := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	de := new(endpoint)
	b := pathQualityBurst{target: 5}
	b.note(true, 10*time.Millisecond, base)
	b.note(true, 11*time.Millisecond, base.Add(time.Millisecond))
	b.note(false, 0, base.Add(2*time.Millisecond))
	b.note(false, 0, base.Add(3*time.Millisecond))
	b.note(false, 0, base.Add(4*time.Millisecond))

	de.seedCurrentPathQualityLocked(path, &b)
	if de.currentPathQuality == nil || de.currentPathQuality.probeBits != 0b11000 {
		t.Fatalf("seeded monitor = %+v; want completion bits 11000", de.currentPathQuality)
	}
}

func TestPathQualityStaleGenerationAndCancellation(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	de := &endpoint{
		bestAddr: addrQuality{epAddr: current},
		sentPing: make(map[stun.TxID]sentPing),
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 7,
			current:    current,
			candidate:  addrQuality{epAddr: candidate},
			burst:      pathQualityBurst{target: 10},
		},
	}
	de.recordPathQualityProbeLocked(sentPing{to: candidate, pathQualityGeneration: 6}, true, 10*time.Millisecond, now)
	if de.pathQualityEvaluation.burst.completed != 0 {
		t.Fatal("stale generation changed active burst")
	}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: candidate, timer: timer, purpose: pingPathQuality, pathQualityGeneration: 7}
	de.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}})
	if de.pathQualityEvaluation != nil || len(de.sentPing) != 0 {
		t.Fatalf("path change did not cancel evaluation: eval=%+v pings=%d", de.pathQualityEvaluation, len(de.sentPing))
	}
}

func TestPathQualityCandidateRemovalCancelsBurst(t *testing.T) {
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidate := netip.MustParseAddrPort("192.0.2.2:7")
	de := &endpoint{
		bestAddr:      addrQuality{epAddr: current},
		sentPing:      make(map[stun.TxID]sentPing),
		endpointState: map[netip.AddrPort]*endpointState{candidate: {}},
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 4,
			current:    current,
			candidate:  addrQuality{epAddr: epAddr{ap: candidate}},
		},
		debugUpdates: ringlog.New[EndpointChange](4),
	}
	de.deleteEndpointLocked("test", candidate)
	if de.pathQualityEvaluation != nil {
		t.Fatal("candidate removal did not cancel quality burst")
	}
}

func TestPathQualityOnlyOneActiveEvaluation(t *testing.T) {
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidateA := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	candidateB := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}
	e := &pathQualityEvaluation{generation: 9, current: current, candidate: addrQuality{epAddr: candidateA}}
	de := &endpoint{bestAddr: addrQuality{epAddr: current}, pathQualityEvaluation: e}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	if !de.deferDirectCandidateSwitchLocked(addrQuality{epAddr: candidateB}, mono.Now()) {
		t.Fatal("second candidate was not deferred behind active evaluation")
	}
	if de.pathQualityEvaluation != e {
		t.Fatal("second candidate replaced the active evaluation")
	}
}

func TestPathQualityHeartbeatDisabledPreservesLegacyPromotion(t *testing.T) {
	current := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	de := &endpoint{derpAddr: current.ap, heartbeatDisabled: true}
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	if de.deferDirectCandidateSwitchLocked(addrQuality{epAddr: candidate}, mono.Now()) {
		t.Fatal("quality evaluation started while heartbeat sampling was disabled")
	}

	de.heartbeatDisabled = false
	de.pathQualityEvaluation = &pathQualityEvaluation{generation: 3, current: current, candidate: addrQuality{epAddr: candidate}}
	de.setHeartbeatDisabled(true)
	if de.pathQualityEvaluation != nil {
		t.Fatal("enabling heartbeat suppression did not cancel active quality evaluation")
	}
}

func TestPathQualityPongRequiresExactSourceAndSkipsOrdinaryPromotion(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	wrongSource := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de := &endpoint{
		c:             &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()},
		bestAddr:      addrQuality{epAddr: current},
		sentPing:      map[stun.TxID]sentPing{txid: {to: candidate, at: now.Add(-10 * time.Millisecond), timer: timer, purpose: pingPathQuality, pathQualityGeneration: 3}},
		endpointState: map[netip.AddrPort]*endpointState{candidate.ap: {}},
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 3,
			current:    current,
			candidate:  addrQuality{epAddr: candidate},
			burst:      pathQualityBurst{target: 2},
		},
	}
	if !de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: wrongSource.ap}, &discoInfo{}, wrongSource) {
		t.Fatal("quality Pong TxID was not recognized")
	}
	if de.bestAddr.epAddr != current {
		t.Fatalf("wrong-source quality Pong promoted %v", de.bestAddr)
	}
	if got := de.pathQualityEvaluation.burst.received; got != 0 {
		t.Fatalf("wrong-source Pong recorded %d successes; want 0", got)
	}
	if got := len(de.endpointState[candidate.ap].recentPongs); got != 0 {
		t.Fatalf("quality Pong entered ordinary history; got %d entries", got)
	}
}

func TestPathQualityDoesNotBlockCLIPingCallback(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	wrongSource := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	callback := make(chan *ipnstate.PingResult, 1)
	resCB := &pingResultAndCallback{res: new(ipnstate.PingResult), cb: func(res *ipnstate.PingResult) { callback <- res }}
	de := &endpoint{
		c:                  &Conn{logf: func(string, ...any) {}, peerMap: newPeerMap()},
		bestAddr:           addrQuality{epAddr: current, latency: time.Second},
		trustBestAddrUntil: now.Add(time.Hour),
		sentPing:           map[stun.TxID]sentPing{txid: {to: candidate, at: now.Add(-10 * time.Millisecond), timer: timer, purpose: pingCLI, resCB: resCB}},
		endpointState:      map[netip.AddrPort]*endpointState{candidate.ap: {}},
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 8,
			current:    current,
			candidate:  addrQuality{epAddr: candidate},
			burst:      pathQualityBurst{target: 10},
		},
		debugUpdates: ringlog.New[EndpointChange](4),
	}
	de.c.discoAtomic.Set(key.NewDisco())
	de.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	if !de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: wrongSource.ap}, &discoInfo{}, wrongSource) {
		t.Fatal("CLI Pong TxID was not recognized")
	}
	select {
	case got := <-callback:
		if got.Endpoint != candidate.String() {
			t.Fatalf("CLI callback endpoint = %q; want %q", got.Endpoint, candidate.String())
		}
	case <-time.After(time.Second):
		t.Fatal("CLI Pong callback was blocked by path-quality evaluation")
	}
	if len(de.endpointState[candidate.ap].recentPongs) != 1 {
		t.Fatal("ordinary wrong-source CLI Pong behavior changed")
	}
	if de.bestAddr.epAddr != current {
		t.Fatalf("candidate promoted before quality burst: %v", de.bestAddr)
	}
}

func TestPathQualityTimeoutDoesNotClearCurrentBest(t *testing.T) {
	now := mono.Now()
	current := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	candidate := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de := &endpoint{
		bestAddr:           addrQuality{epAddr: current},
		trustBestAddrUntil: now.Add(-time.Hour),
		sentPing:           map[stun.TxID]sentPing{txid: {to: candidate, timer: timer, purpose: pingPathQuality, pathQualityGeneration: 5}},
		pathQualityEvaluation: &pathQualityEvaluation{
			generation: 5,
			current:    current,
			candidate:  addrQuality{epAddr: candidate},
			burst:      pathQualityBurst{target: 1},
		},
	}
	de.discoPingTimeout(txid)
	if de.bestAddr.epAddr != current {
		t.Fatalf("candidate quality timeout cleared current best: %v", de.bestAddr)
	}
}
