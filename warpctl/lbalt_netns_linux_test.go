package main

// The edge tests of the lb_alt network-namespace harness (lbalt_netns_test.go,
// which runs each in a fresh edge container; the environment is in
// lbalt_netns_edge_linux_test.go). Outside a harness edge container they skip.
//
// Each test checks the kernel's answer flow by flow: every flow names the
// generation that answered it and the DNAT target it reached, and each source
// must reach the block its HMARK bucket is assigned (lbAltNetnsHmarkBucket).

import (
	"errors"
	"fmt"
	"maps"
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

// A block is orphaned when its chain is missing or its targets have no
// listener, and the reconcile moves only its buckets, to the ready blocks by
// weight (largest remainder), and gives them back when it returns. Between
// the reconcile's transactions every other source keeps its block, so no
// jump ever reaches a partial chain. With every block down the split sends
// nothing, so tcp 80 refuses and Route53 withdraws the interface; one block
// back takes every bucket.
func TestLbAltNetnsEdgeMovesOnlyOrphanedBuckets(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	eth0 := edge.interfaces[0]
	blockGenerations := map[string]*lbAltNetnsGeneration{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		blockGenerations[blockWeight.Block] = edge.startBlock(blockWeight.Block, 1)
		// g4 has not written its chains yet
		if blockWeight.Block != "g4" {
			edge.writeBlockChains(blockGenerations[blockWeight.Block])
		}
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	allPorts := lbAltNetnsPublicPorts()
	reconcileTo := func(what string, bucketBlocks []string) {
		t.Helper()
		edge.reconcile(eth0)
		edge.requireSplitChain(eth0, bucketBlocks)
		edge.requireDialAnswers(what, edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false), lbAltNetnsSplitAnswerer(bucketBlocks, blockGenerations))
	}
	// Requires an assignment that moves only the lost block's buckets, as many
	// to each ready block as wantBlockMoveCounts says, which are worked out here by
	// hand, so the harness does not check the kernel against the reconcile's
	// own arithmetic alone. With main's weights, a lost g block's 25 buckets
	// go by 1, 24, 25 and 25 over the ready total of 75: shares of 0.33, 8,
	// 8.33 and 8.33, so 0, 8, 8 and 8, and the one left to the largest
	// remainder, which ties go to the earlier block: beta.
	requireMoves := func(what string, bucketBlocks []string, lostBlock string, wantBlockMoveCounts map[string]int) {
		t.Helper()
		blockMoveCounts := map[string]int{}
		for bucket, block := range bucketBlocks {
			switch baseBlock := baseBucketBlocks[bucket]; {
			case baseBlock == lostBlock:
				blockMoveCounts[block] += 1
			case block != baseBlock:
				t.Fatalf("%s: bucket %d of %s moved to %q", what, bucket, baseBlock, block)
			}
		}
		if !maps.Equal(blockMoveCounts, wantBlockMoveCounts) {
			t.Fatalf("%s: %s's buckets went %v, want %v", what, lostBlock, blockMoveCounts, wantBlockMoveCounts)
		}
	}

	withoutG4 := edge.bucketBlocksWithReady("beta", "g1", "g2", "g3")
	requireMoves("g4 without its chain", withoutG4, "g4", map[string]int{"beta": 1, "g1": 8, "g2": 8, "g3": 8})
	reconcileTo("g4 without its chain", withoutG4)
	edge.fact("g4 without its chain: its 25 buckets went to the ready blocks by weight")
	edge.writeBlockChains(blockGenerations["g4"])
	reconcileTo("g4 with its chain", baseBucketBlocks)

	// g2 loses its public sockets. Between the reconcile's transactions, every
	// source whose block is ready keeps it.
	blockGenerations["g2"].closePublic("")
	withoutG2 := edge.bucketBlocksWithReady("beta", "g1", "g3", "g4")
	requireMoves("g2 lost", withoutG2, "g2", map[string]int{"beta": 1, "g1": 8, "g3": 8, "g4": 8})
	keptBuckets := func(bucket int) bool {
		return baseBucketBlocks[bucket] != "g2"
	}
	tlsPorts := []lbAltNetnsPublicPort{
		lbAltNetnsPublicPort{protocol: "tcp", port: 443},
		lbAltNetnsPublicPort{protocol: "udp", port: 443},
	}
	committed := newLbAltNetnsHold(edge.settings)
	writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{
		after: func(command lbAltCommand) {
			if strings.HasSuffix(command.name, "-restore") {
				committed.at()
			}
		},
	})
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- writer.reconcile(edge.ctx, edge.splitConfig(eth0))
	}()
	heldCount := 0
	for done := false; !done; {
		select {
		case <-committed.held:
			heldCount += 1
			edge.requireDialAnswers(
				fmt.Sprintf("ready blocks' sources after transaction %d", heldCount),
				edge.probes([]*lbAltNetnsInterface{eth0}, tlsPorts, keptBuckets, false),
				lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations),
			)
			committed.resume(t)
		case err := <-reconcileDone:
			if err != nil {
				t.Fatal(err)
			}
			done = true
		case <-time.After(edge.settings.hookTimeout):
			t.Fatal("the reconcile neither committed nor finished")
		}
	}
	if heldCount != len(commandLog.restores()) || heldCount == 0 {
		t.Fatalf("held after %d of %d transactions", heldCount, len(commandLog.restores()))
	}
	edge.requireSplitChain(eth0, withoutG2)
	edge.requireDialAnswers("g2 lost", edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false), lbAltNetnsSplitAnswerer(withoutG2, blockGenerations))
	edge.fact("g2 lost: its 25 buckets moved by weight in %d transactions, and every other source kept its block between them", heldCount)

	if err := blockGenerations["g2"].openPublic(""); err != nil {
		t.Fatal(err)
	}
	reconcileTo("g2 back", baseBucketBlocks)

	// g3 is lost, and the reconcile that moves its buckets is interrupted after
	// IPv4's entry jumps moved to the replacement chain, and before IPv6's
	// first transaction, as a worker that died at each would leave it
	blockGenerations["g3"].closePublic("")
	withoutG3 := edge.bucketBlocksWithReady("beta", "g1", "g2", "g4")
	requireMoves("g3 lost", withoutG3, "g3", map[string]int{"beta": 1, "g1": 8, "g2": 8, "g4": 8})
	staleWithoutG3 := slices.Clone(baseBucketBlocks)
	for bucket, block := range staleWithoutG3 {
		if block == "g3" {
			staleWithoutG3[bucket] = ""
		}
	}
	commandNatTransactionCounts := map[string]int{}
	interruptedWriter, _ := edge.newWriter(lbAltNetnsWriterHooks{
		before: func(command lbAltCommand) error {
			if !strings.HasSuffix(command.name, "-restore") || !strings.HasPrefix(command.stdin, "*nat") {
				return nil
			}
			commandNatTransactionCounts[command.name] += 1
			if (command.name == "iptables-restore" && commandNatTransactionCounts[command.name] == 3) ||
				(command.name == "ip6tables-restore" && commandNatTransactionCounts[command.name] == 1) {
				return errors.New("interrupted")
			}
			return nil
		},
	})
	if err := interruptedWriter.reconcile(edge.ctx, edge.splitConfig(eth0)); err == nil {
		t.Fatal("the interrupted reconcile succeeded")
	}
	names := eth0.chainNames(t)
	for _, rule := range edge.taggedRules(false, "nat", names.ruleComment) {
		if !strings.HasSuffix(rule, "-j "+names.temporarySplitChain) {
			t.Fatalf("an IPv4 entry jump after the interruption: %s", rule)
		}
	}
	edge.requireBucketRules(eth0, false, names.temporarySplitChain, withoutG3)
	edge.requireBucketRules(eth0, true, names.splitChain, baseBucketBlocks)
	edge.requireDialAnswers(
		"after the interrupted reconcile",
		edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false),
		lbAltNetnsFamiliesAnswerer(lbAltNetnsSplitAnswerer(withoutG3, blockGenerations), lbAltNetnsSplitAnswerer(staleWithoutG3, blockGenerations)),
	)
	// the next reconcile rebuilds IPv4's split chain from the replacement and
	// replaces IPv6's, and then has nothing to write
	reconcileTo("after the reconcile that followed the interruption", withoutG3)
	writer, commandLog = edge.newWriter(lbAltNetnsWriterHooks{})
	if err := writer.reconcile(edge.ctx, edge.splitConfig(eth0)); err != nil {
		t.Fatal(err)
	}
	if restores := commandLog.restores(); 0 < len(restores) {
		t.Fatalf("the converged split was written again:\n%s", lbAltNetnsDescribeRestores(restores))
	}
	edge.fact("interrupted reconcile: IPv4 served from the replacement chain and IPv6 from the old split until the next reconcile converged both")
	if err := blockGenerations["g3"].openPublic(""); err != nil {
		t.Fatal(err)
	}
	reconcileTo("g3 back", baseBucketBlocks)

	for _, generation := range blockGenerations {
		generation.closePublic("")
	}
	err := reconcileLbAltSplit(edge.ctx, edge.splitConfig(eth0))
	if !errors.Is(err, errLbAltSplitNoReadyBlock) {
		t.Fatalf("every block down: %v, want %v", err, errLbAltSplitNoReadyBlock)
	}
	nowhere := make([]string, len(baseBucketBlocks))
	edge.requireSplitChain(eth0, nowhere)
	edge.requireDialAnswers("every block down", edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false), lbAltNetnsSplitAnswerer(nowhere, blockGenerations))
	edge.fact("every block down: the split chains are empty and no flow is answered, tcp 80 included")

	if err := blockGenerations["g3"].openPublic(""); err != nil {
		t.Fatal(err)
	}
	onlyG3 := edge.bucketBlocksWithReady("g3")
	if wantOnlyG3 := slices.Repeat([]string{"g3"}, lbAltHmarkMod); !slices.Equal(onlyG3, wantOnlyG3) {
		t.Fatalf("with only g3 up the buckets go %v", onlyG3)
	}
	reconcileTo("only g3 up", onlyG3)
}

// One interface hands over between nginx and the split, both ways, on a host
// whose other interface stays on nginx. Turning lb_alt on sends new flows to
// the blocks ahead of nginx's DNAT, while flows established on nginx stay
// there; a reconcile puts the entry jumps back ahead of a stray nginx
// redirect. Rolling back, nginx's redirect (warpctl's own) puts its DNAT ahead
// of the split, which keeps only udp 4053, private on nginx, until
// removeLbAltSplit takes the split away; flows established on the blocks stay
// there throughout. A removal interrupted twice, leaving IPv4's HMARK rules
// and all of IPv6's split, still sends new flows to nginx, and the next
// removal leaves no HMARK rule, entry jump or split chain in either family.
func TestLbAltNetnsEdgeRollsBackToNginx(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	eth0 := edge.interfaces[0]
	eth1 := edge.interfaces[1]
	startNginx := func(iface *lbAltNetnsInterface, generation int) *lbAltNetnsGeneration {
		t.Helper()
		nginx := edge.startGeneration(
			"nginx-"+iface.spec.name,
			generation,
			iface.nginxPorts(generation),
			[]netip.Addr{iface.bridgeAddress(false), iface.bridgeAddress(true)},
			netip.Addr{},
		)
		externalInternalPorts := map[int]int{}
		serviceInternalPorts := nginx.ports.serviceInternalPorts()
		for externalPort, servicePort := range iface.lbWorker.portBlocks.externalsToService {
			externalInternalPorts[externalPort] = serviceInternalPorts[servicePort]
		}
		if err := iface.lbWorker.redirect(externalInternalPorts, serviceInternalPorts, ""); err != nil {
			t.Fatal(err)
		}
		return nginx
	}
	allPorts := lbAltNetnsPublicPorts()
	everyFourthBucket := func(bucket int) bool {
		return bucket%4 == 0
	}

	nginxEth0 := startNginx(eth0, 1)
	nginxEth1 := startNginx(eth1, 1)
	eth1OnNginx := lbAltNetnsNginxAnswerer(nginxEth1, nil)
	bothOnNginx := lbAltNetnsInterfaceAnswerer(lbAltNetnsNginxAnswerer(nginxEth0, nil), eth1OnNginx)
	nginxEstablished := edge.probes(edge.interfaces, allPorts, everyFourthBucket, true)
	edge.requireDialAnswers("both interfaces on nginx", nginxEstablished, bothOnNginx)

	blockGenerations := edge.startBlocks(1)
	baseBucketBlocks := edge.baseBucketBlocks()
	onSplit := lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations)
	edge.reconcile(eth0)
	edge.requireDialAnswers("eth0 on the split, eth1 on nginx", edge.probes(edge.interfaces, allPorts, nil, false), lbAltNetnsInterfaceAnswerer(onSplit, eth1OnNginx))
	edge.requireSendAnswers("flows established on nginx, after the switch", nginxEstablished, bothOnNginx)
	splitEstablished := edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, everyFourthBucket, true)
	edge.requireDialAnswers("flows established on the split", splitEstablished, onSplit)
	edge.fact("handover to the split: new flows of eth0 went to the blocks, flows established on nginx stayed there, eth1 stayed on nginx")

	// an nginx generation redirected while eth0 is still lb_alt puts its DNAT
	// ahead of the entry jumps, which keep only udp 4053; the lb unit's next
	// reconcile puts the entry jumps back ahead of it
	nginxEth0Stray := startNginx(eth0, 2)
	edge.requireDialAnswers(
		"a stray nginx redirect ahead of the split",
		edge.probes(edge.interfaces, allPorts, nil, false),
		lbAltNetnsInterfaceAnswerer(lbAltNetnsNginxAnswerer(nginxEth0Stray, onSplit), eth1OnNginx),
	)
	edge.reconcile(eth0)
	edge.requireDialAnswers("the entry jumps back ahead of nginx", edge.probes(edge.interfaces, allPorts, nil, false), lbAltNetnsInterfaceAnswerer(onSplit, eth1OnNginx))
	edge.fact("a stray nginx redirect went ahead of the entry jumps, and the next reconcile put them back ahead of it")

	// rollback: nginx's next generation takes new flows as soon as its
	// redirect puts its DNAT ahead of the entry jumps
	nginxEth0Second := startNginx(eth0, 3)
	edge.requireDialAnswers(
		"nginx's redirect ahead of the split",
		edge.probes(edge.interfaces, allPorts, nil, false),
		lbAltNetnsInterfaceAnswerer(lbAltNetnsNginxAnswerer(nginxEth0Second, onSplit), eth1OnNginx),
	)
	edge.requireSendAnswers("flows established on the split, after nginx's redirect", splitEstablished, onSplit)
	edge.requireSendAnswers("flows established on nginx, after nginx's redirect", nginxEstablished, bothOnNginx)

	// the removal is interrupted before IPv4's mangle transaction and before
	// IPv6's nat transaction, as a worker that died there would leave it
	interruptedWriter, _ := edge.newWriter(lbAltNetnsWriterHooks{
		before: func(command lbAltCommand) error {
			if (command.name == "iptables-restore" && strings.HasPrefix(command.stdin, "*mangle")) ||
				(command.name == "ip6tables-restore" && strings.HasPrefix(command.stdin, "*nat")) {
				return errors.New("interrupted")
			}
			return nil
		},
	})
	if err := interruptedWriter.remove(edge.ctx, lbAltNetnsEnv, eth0.spec.name); err == nil {
		t.Fatal("the interrupted removal succeeded")
	}
	names := eth0.chainNames(t)
	splitLeft := func(ipv6 bool) map[string][]string {
		left := map[string][]string{}
		for _, table := range []string{"mangle", "nat"} {
			left[table] = edge.taggedRules(ipv6, table, names.ruleComment)
		}
		for _, chain := range []string{names.splitChain, names.temporarySplitChain} {
			if edge.hasChain(ipv6, "nat", chain) {
				left["chains"] = append(left["chains"], chain)
			}
		}
		return left
	}
	ipv4Left := splitLeft(false)
	ipv6Left := splitLeft(true)
	if len(ipv4Left["mangle"]) == 0 || 0 < len(ipv4Left["nat"]) || 0 < len(ipv4Left["chains"]) ||
		len(ipv6Left["mangle"]) == 0 || len(ipv6Left["nat"]) == 0 || len(ipv6Left["chains"]) == 0 {
		t.Fatalf("after the interrupted removal, IPv4 keeps %v and IPv6 %v; want IPv4's HMARK rules alone, and all of IPv6's split", ipv4Left, ipv6Left)
	}
	edge.requireDialAnswers(
		"after the interrupted removal",
		edge.probes(edge.interfaces, allPorts, nil, false),
		lbAltNetnsInterfaceAnswerer(lbAltNetnsNginxAnswerer(nginxEth0Second, lbAltNetnsFamiliesAnswerer(nil, onSplit)), eth1OnNginx),
	)
	edge.requireSendAnswers("flows established on the split, after the interrupted removal", splitEstablished, onSplit)
	edge.requireSendAnswers("flows established on nginx, after the interrupted removal", nginxEstablished, bothOnNginx)
	edge.fact("interrupted removal: IPv4 kept %d HMARK rules, IPv6 %d HMARK rules, %d entry jumps and its split chain; new flows went to nginx, udp 4053 to the split only in IPv6", len(ipv4Left["mangle"]), len(ipv6Left["mangle"]), len(ipv6Left["nat"]))

	if err := removeLbAltSplit(edge.ctx, lbAltNetnsEnv, eth0.spec.name); err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		left := splitLeft(ipv6)
		if 0 < len(left["mangle"])+len(left["nat"])+len(left["chains"]) {
			t.Fatalf("%s keeps after the removal: %v", lbAltNetnsIptablesCommand(ipv6), left)
		}
		blockChainCount := 0
		for _, line := range edge.iptables(ipv6, "-t", "nat", "-S") {
			if strings.HasPrefix(line, "-N "+names.blockChainPrefix) {
				blockChainCount += 1
			}
		}
		edge.fact("%s after the rollback: no HMARK rule, entry jump or split chain of eth0; %d of its block chains left", lbAltNetnsIptablesCommand(ipv6), blockChainCount)
	}
	backOnNginx := lbAltNetnsInterfaceAnswerer(lbAltNetnsNginxAnswerer(nginxEth0Second, nil), eth1OnNginx)
	edge.requireDialAnswers("rolled back", edge.probes(edge.interfaces, allPorts, nil, false), backOnNginx)
	edge.requireSendAnswers("flows established on the split, after the rollback", splitEstablished, onSplit)
	edge.requireSendAnswers("flows established on nginx, after the rollback", nginxEstablished, bothOnNginx)

	writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
	if err := writer.remove(edge.ctx, lbAltNetnsEnv, eth0.spec.name); err != nil {
		t.Fatal(err)
	}
	if restores := commandLog.restores(); 0 < len(restores) {
		t.Fatalf("a removal with nothing left wrote:\n%s", lbAltNetnsDescribeRestores(restores))
	}
}
