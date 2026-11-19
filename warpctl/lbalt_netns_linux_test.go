package main

// The edge tests of the lb_alt network-namespace harness (lbalt_netns_test.go,
// which runs each in a fresh edge container; the environment is in
// lbalt_netns_edge_linux_test.go). Outside a harness edge container they skip.
//
// Each test checks the kernel's answer flow by flow: every flow names the
// generation that answered it and the DNAT target it reached, and each source
// must reach the block its HMARK bucket is assigned (lbAltNetnsHmarkBucket).

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every source reaches the block its HMARK bucket is assigned, on both
// interfaces and in both families, over tcp and udp on every public port. The
// split chains hold one rule per bucket in bucket order, so the blocks take
// main's weights' shares, and each source's flows, whatever their protocol
// and ports, reach one block. Replies come from the public address and port
// the client dialed, and leave by the interface the flow came in on, through
// its policy table. Dials from the host itself take the same split through
// mangle OUTPUT. The rules list back in the forms the writers compare, so
// another reconcile, and another write of the same block chains, change
// nothing.
func TestLbAltNetnsEdgeSplitsSourcesByWeight(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	blockGenerations := edge.startBlocks(1)
	for _, iface := range edge.interfaces {
		edge.reconcile(iface)
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	// main's weights total 100, so each block's largest-remainder share is its
	// weight, in ServiceBlockWeights order: worked out here, not by the split
	wantBaseBucketBlocks := []string{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		wantBaseBucketBlocks = append(wantBaseBucketBlocks, slices.Repeat([]string{blockWeight.Block}, blockWeight.Weight)...)
	}
	if !slices.Equal(baseBucketBlocks, wantBaseBucketBlocks) {
		t.Fatalf("the buckets go %v, want %v", baseBucketBlocks, wantBaseBucketBlocks)
	}
	for _, iface := range edge.interfaces {
		edge.requireSplitChain(iface, baseBucketBlocks)
	}

	for _, iface := range edge.interfaces {
		for _, ipv6 := range []bool{false, true} {
			replyArgs := []string{"-m", "conntrack", "--ctdir", "REPLY", "--ctorigdst", iface.publicAddress(ipv6).String()}
			edge.addCounter(ipv6, "POSTROUTING", "reply-"+iface.spec.name, append(replyArgs, "-o", iface.spec.name)...)
			edge.addCounter(ipv6, "POSTROUTING", "astray-"+iface.spec.name, append(replyArgs, "!", "-o", iface.spec.name)...)
		}
	}

	probes := edge.probes(edge.interfaces, lbAltNetnsPublicPorts(), nil, false)
	generationAnsweredCounts := edge.requireDialAnswers("every source, interface and public port", probes, lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations))
	// one source per bucket and family: each block answers its buckets' share
	flowsPerBucket := len(edge.interfaces) * len(lbAltNetnsPublicPorts()) * 2
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		bucketCount := 0
		for _, block := range baseBucketBlocks {
			if block == blockWeight.Block {
				bucketCount += 1
			}
		}
		if answered := generationAnsweredCounts[blockWeight.Block+"/1"]; answered != bucketCount*flowsPerBucket {
			t.Fatalf("block %s answered %d flows, want %d for its %d buckets", blockWeight.Block, answered, bucketCount*flowsPerBucket, bucketCount)
		}
		edge.fact("block %s weight %d: %d buckets, %d of %d flows", blockWeight.Block, blockWeight.Weight, bucketCount, generationAnsweredCounts[blockWeight.Block+"/1"], len(probes))
	}

	for _, ipv6 := range []bool{false, true} {
		counterPackets := edge.counterPackets(ipv6)
		for _, iface := range edge.interfaces {
			if counterPackets["reply-"+iface.spec.name] == 0 || counterPackets["astray-"+iface.spec.name] != 0 {
				t.Fatalf("%s replies of %s: %d by it, %d by another interface", lbAltNetnsIptablesCommand(ipv6), iface.spec.name, counterPackets["reply-"+iface.spec.name], counterPackets["astray-"+iface.spec.name])
			}
			edge.fact("%s replies of %s: %d packets by it, none by another interface", lbAltNetnsIptablesCommand(ipv6), iface.spec.name, counterPackets["reply-"+iface.spec.name])
		}
	}

	// local dials, from the host's other addresses to eth0's public ones
	eth0 := edge.interfaces[0]
	eth1 := edge.interfaces[1]
	localSources := []netip.Addr{
		netip.MustParseAddr(edge.servicesNetwork.ipv4.interfaceIp),
		eth1.bridgeAddress(false),
		eth1.publicAddress(false),
		eth1.bridgeAddress(true),
		eth1.publicAddress(true),
	}
	for _, source := range localSources {
		bucket := lbAltNetnsHmarkBucket(source)
		generation := blockGenerations[baseBucketBlocks[bucket]]
		for _, protocol := range []string{"tcp", "udp"} {
			target := netip.AddrPortFrom(eth0.publicAddress(source.Is6()), 443)
			want := generation.answer(protocol, netip.AddrPortFrom(eth0.bridgeAddress(source.Is6()), uint16(generation.ports.tls)))
			keptFlow := lbAltNetnsLocalFlow(t, protocol, source, target, edge.settings.flowTimeout)
			result := keptFlow.exchange("local", edge.settings.flowTimeout)
			keptFlow.close()
			if result.Answer != want || result.ReplyFrom != target.String() {
				t.Fatalf("local %s dial from %s (bucket %d) to %s: got %q from %s (%s), want %q", protocol, source, bucket, target, result.Answer, result.ReplyFrom, result.Error, want)
			}
		}
	}
	edge.fact("local dials: %d sources through mangle OUTPUT reached their buckets' blocks over tcp and udp", len(localSources))

	writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
	for _, iface := range edge.interfaces {
		if err := writer.reconcile(edge.ctx, edge.splitConfig(iface)); err != nil {
			t.Fatal(err)
		}
	}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		generation := blockGenerations[blockWeight.Block]
		if err := writer.writeBlockChains(edge.ctx, lbAltNetnsEnv, generation.name, edge.splitInterfaces(), generation.targets()); err != nil {
			t.Fatal(err)
		}
	}
	if restores := commandLog.restores(); 0 < len(restores) {
		t.Fatalf("a converged host was written again, so its listed rules differ from the written ones:\n%s", lbAltNetnsDescribeRestores(restores))
	}
	for _, ipv6 := range []bool{false, true} {
		for _, rule := range edge.taggedRules(ipv6, "mangle", eth0.chainNames(t).ruleComment) {
			if strings.Contains(rule, "-p udp") && strings.HasPrefix(rule, "-A PREROUTING") {
				edge.fact("%s lists %s", lbAltNetnsIptablesCommand(ipv6), rule)
			}
		}
	}
}

// A flow from the edge itself, as the client agent makes one.
func lbAltNetnsLocalFlow(t *testing.T, protocol string, source netip.Addr, target netip.AddrPort, timeout time.Duration) *lbAltNetnsKeptFlow {
	t.Helper()
	session := &lbAltNetnsAgentSession{
		settings:    defaultLbAltNetnsSettings(),
		sourcePorts: nil,
		idKeptFlows: map[string]*lbAltNetnsKeptFlow{},
	}
	session.settings.flowTimeout = timeout
	result := session.dial(lbAltNetnsFlow{
		Id:       "local-dial",
		Protocol: protocol,
		Source:   source.String(),
		Target:   target.String(),
		Keep:     true,
	})
	keptFlow := session.idKeptFlows["local-dial"]
	if keptFlow == nil {
		t.Fatalf("local %s dial from %s to %s: %s", protocol, source, target, result.Error)
	}
	return keptFlow
}

// A block promotion moves only new flows: flows established on the old
// generation keep reaching it through conntrack, while new flows from the same
// sources reach the new one. An lb reconcile concurrent with the promotion
// takes the host lock in turn, in either order: holding it from its socket
// listing to its last write, it never judges the promoted chain by a listing
// older than the new generation's sockets, so it moves no bucket and writes
// nothing.
func TestLbAltNetnsEdgeKeepsEstablishedFlowsThroughAPromotion(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	blockGenerations := edge.startBlocks(1)
	for _, iface := range edge.interfaces {
		edge.reconcile(iface)
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	eth0 := edge.interfaces[0]
	establishedBlockGenerations := map[string]*lbAltNetnsGeneration{}
	for block, generation := range blockGenerations {
		establishedBlockGenerations[block] = generation
	}
	tlsPorts := []lbAltNetnsPublicPort{
		lbAltNetnsPublicPort{protocol: "tcp", port: 443},
		lbAltNetnsPublicPort{protocol: "udp", port: 443},
	}
	established := edge.probes(edge.interfaces, tlsPorts, nil, true)
	edge.requireDialAnswers("established flows", established, lbAltNetnsSplitAnswerer(baseBucketBlocks, establishedBlockGenerations))

	// the reconcile lists the sockets before g1's second generation listens,
	// and is held there; the promotion then waits for the host lock
	socketsListed := newLbAltNetnsHold(edge.settings)
	reconcileWriter, reconcileLog := edge.newWriter(lbAltNetnsWriterHooks{
		after: func(command lbAltCommand) {
			if command.name == "ss" {
				socketsListed.at()
			}
		},
	})
	promotionWaited := make(chan struct{})
	promotionWaitedOnce := sync.Once{}
	promotionCommitted := newLbAltNetnsHold(edge.settings)
	promotionWriter, promotionLog := edge.newWriter(lbAltNetnsWriterHooks{
		after: func(command lbAltCommand) {
			if strings.HasSuffix(command.name, "-restore") {
				promotionCommitted.at()
			}
		},
		lockBusy: func() {
			promotionWaitedOnce.Do(func() {
				close(promotionWaited)
			})
		},
	})
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- reconcileWriter.reconcile(edge.ctx, edge.splitConfig(eth0))
	}()
	socketsListed.wait(t)
	second := edge.startBlock("g1", 2)
	promotionDone := make(chan error, 1)
	go func() {
		promotionDone <- promotionWriter.writeBlockChains(edge.ctx, lbAltNetnsEnv, second.name, edge.splitInterfaces(), second.targets())
	}()
	select {
	case <-promotionWaited:
	case <-promotionCommitted.held:
		t.Fatal("the promotion wrote while the reconcile held the host lock")
	case err := <-promotionDone:
		t.Fatalf("the promotion did not wait for the reconcile's host lock: %v", err)
	case <-time.After(edge.settings.hookTimeout):
		t.Fatal("the promotion neither waited nor finished")
	}
	socketsListed.resume(t)
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	// after each of the promotion's transactions, one per family, new flows of
	// g1's sources reach the second generation in the families written so far
	// and the first in the others: a block chain is never seen partial
	g1Buckets := func(bucket int) bool {
		return baseBucketBlocks[bucket] == "g1"
	}
	writtenFamilies := map[bool]bool{}
	for done := false; !done; {
		select {
		case <-promotionCommitted.held:
			restores := promotionLog.restores()
			writtenFamilies[restores[len(restores)-1].name == "ip6tables-restore"] = true
			edge.requireDialAnswers(
				fmt.Sprintf("g1's new flows after the promotion's transaction %d", len(restores)),
				edge.probes(edge.interfaces, tlsPorts, g1Buckets, false),
				func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
					if writtenFamilies[probe.source.Is6()] {
						return second
					}
					return blockGenerations["g1"]
				},
			)
			promotionCommitted.resume(t)
		case err := <-promotionDone:
			if err != nil {
				t.Fatal(err)
			}
			done = true
		case <-time.After(edge.settings.hookTimeout):
			t.Fatal("the promotion neither committed nor finished")
		}
	}
	if restores := reconcileLog.restores(); 0 < len(restores) {
		t.Fatalf("the reconcile wrote during the promotion:\n%s", lbAltNetnsDescribeRestores(restores))
	}
	if restores := promotionLog.restores(); len(restores) != 2 {
		t.Fatalf("the promotion wrote %d transactions, want one per family:\n%s", len(restores), lbAltNetnsDescribeRestores(restores))
	}
	blockGenerations["g1"] = second
	edge.requireSendAnswers("established flows after the promotion", established, lbAltNetnsSplitAnswerer(baseBucketBlocks, establishedBlockGenerations))
	edge.requireDialAnswers("new flows after the promotion", edge.probes(edge.interfaces, tlsPorts, nil, false), lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations))
	edge.fact("promotion during a held reconcile: the promotion waited for the host lock, the reconcile wrote nothing, %d established flows stayed on their blockGenerations, and g1's new flows met a whole chain after each of the promotion's transactions", len(established))

	// the promotion to a third generation is held after its first nat
	// listing; the reconcile then waits, and runs on the promoted chain
	third := edge.startBlock("g1", 3)
	natListed := newLbAltNetnsHold(edge.settings)
	natListedOnce := sync.Once{}
	promotionWriter, promotionLog = edge.newWriter(lbAltNetnsWriterHooks{
		after: func(command lbAltCommand) {
			if lbAltNetnsListsNat(command, false) {
				natListedOnce.Do(natListed.at)
			}
		},
	})
	reconcileWaited := make(chan struct{})
	reconcileWaitedOnce := sync.Once{}
	reconcileWriter, reconcileLog = edge.newWriter(lbAltNetnsWriterHooks{
		lockBusy: func() {
			reconcileWaitedOnce.Do(func() {
				close(reconcileWaited)
			})
		},
	})
	promotionDone = make(chan error, 1)
	go func() {
		promotionDone <- promotionWriter.writeBlockChains(edge.ctx, lbAltNetnsEnv, third.name, edge.splitInterfaces(), third.targets())
	}()
	natListed.wait(t)
	reconcileDone = make(chan error, 1)
	go func() {
		reconcileDone <- reconcileWriter.reconcile(edge.ctx, edge.splitConfig(eth0))
	}()
	select {
	case <-reconcileWaited:
	case err := <-reconcileDone:
		t.Fatalf("the reconcile did not wait for the promotion's host lock: %v", err)
	case <-time.After(edge.settings.hookTimeout):
		t.Fatal("the reconcile neither waited nor finished")
	}
	natListed.resume(t)
	if err := <-promotionDone; err != nil {
		t.Fatal(err)
	}
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	if restores := promotionLog.restores(); len(restores) != 2 {
		t.Fatalf("the promotion wrote %d transactions, want one per family:\n%s", len(restores), lbAltNetnsDescribeRestores(restores))
	}
	if restores := reconcileLog.restores(); 0 < len(restores) {
		t.Fatalf("the reconcile after the promotion wrote, so it judged g1 not ready:\n%s", lbAltNetnsDescribeRestores(restores))
	}
	blockGenerations["g1"] = third
	edge.requireSendAnswers("established flows after the second promotion", established, lbAltNetnsSplitAnswerer(baseBucketBlocks, establishedBlockGenerations))
	edge.requireDialAnswers("new flows after the second promotion", edge.probes(edge.interfaces, tlsPorts, nil, false), lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations))
	edge.fact("reconcile during a held promotion: it waited for the host lock and found g1 ready on its third generation")
}
