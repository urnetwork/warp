package main

// The edge tests of the lb_alt network-namespace harness (lbalt_netns_test.go,
// which runs each in a fresh edge container; the environment is in
// lbalt_netns_edge_linux_test.go). Outside a harness edge container they skip.
//
// Each test checks the kernel's answer flow by flow: every flow names the
// generation that answered it and the DNAT target it reached, and each source
// must reach the block its HMARK bucket is assigned (lbAltNetnsHmarkBucket).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/urnetwork/warp"
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
	// a flow from the edge itself, as the client agent makes one
	localFlow := func(protocol string, source netip.Addr, target netip.AddrPort) *lbAltNetnsKeptFlow {
		t.Helper()
		session := &lbAltNetnsAgentSession{
			settings:    edge.settings,
			sourcePorts: nil,
			idKeptFlows: map[string]*lbAltNetnsKeptFlow{},
		}
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
	for _, source := range localSources {
		bucket := lbAltNetnsHmarkBucket(source)
		generation := blockGenerations[baseBucketBlocks[bucket]]
		for _, protocol := range []string{"tcp", "udp"} {
			target := netip.AddrPortFrom(eth0.publicAddress(source.Is6()), 443)
			want := generation.answer(protocol, netip.AddrPortFrom(eth0.bridgeAddress(source.Is6()), uint16(generation.ports.tls)))
			keptFlow := localFlow(protocol, source, target)
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

// An interface with no public IPv6, as two of the inventory's lb interfaces
// are (§9's family matrix: ten public IPv4 addresses and eight IPv6), splits
// only IPv4. Its blocks still write their IPv6 chains, for its bridge, and the
// reconcile leaves its IPv6 no HMARK rule, entry jump or split chain, so the
// IPv6 flows its address takes get no answer. An interface whose public IPv6
// goes loses its IPv6 split at the next reconcile, each rule deleted by the
// form ip6tables lists it in, and keeps its IPv6 block chains, so the address
// coming back finds every block ready, with no chain written meanwhile.
func TestLbAltNetnsEdgeSplitsAnIpv4OnlyInterface(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	eth0 := edge.interfaces[0]
	eth1 := edge.interfaces[1]
	// the blocks' workers take eth1 as an IPv4-only interface whose bridge has
	// both families
	blockGenerations := map[string]*lbAltNetnsGeneration{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		generation := edge.startBlock(blockWeight.Block, 1)
		blockGenerations[blockWeight.Block] = generation
		splitInterfaces := edge.splitInterfaces()
		splitInterfaces[eth1.index].publicIpv6 = ""
		if err := writeLbAltBlockChains(edge.ctx, lbAltNetnsEnv, generation.name, splitInterfaces, generation.targets()); err != nil {
			t.Fatal(err)
		}
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	onSplit := lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations)
	ipv4Only := lbAltNetnsFamiliesAnswerer(onSplit, nil)
	allPorts := lbAltNetnsPublicPorts()
	// the interface's split config with no public IPv6 address
	ipv4OnlyConfig := func(iface *lbAltNetnsInterface) *lbAltSplitConfig {
		config := edge.splitConfig(iface)
		config.splitInterface.publicIpv6 = ""
		return config
	}
	// requires the interface's IPv6 to hold no split and every block's chain
	requireIpv6Unsplit := func(what string, iface *lbAltNetnsInterface) {
		t.Helper()
		if state := edge.splitState(iface, true); 0 < len(state["mangle"])+len(state["nat"])+len(state["chains"]) {
			t.Fatalf("%s: ip6tables keeps %s's split: %v", what, iface.spec.name, state)
		}
		names := iface.chainNames(t)
		wantBlockChains := []string{}
		for _, blockWeight := range lbAltNetnsBlockWeights() {
			blockChain, err := names.blockChain(blockWeight.Block)
			if err != nil {
				t.Fatal(err)
			}
			wantBlockChains = append(wantBlockChains, blockChain)
		}
		slices.Sort(wantBlockChains)
		if blockChains := edge.blockChains(iface, true); !slices.Equal(blockChains, wantBlockChains) {
			t.Fatalf("%s: %s's IPv6 block chains are %v, want %v", what, iface.spec.name, blockChains, wantBlockChains)
		}
	}
	// requires a reconcile of the config to write nothing
	requireConverged := func(what string, config *lbAltSplitConfig) {
		t.Helper()
		writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
		if err := writer.reconcile(edge.ctx, config); err != nil {
			t.Fatal(err)
		}
		if restores := commandLog.restores(); 0 < len(restores) {
			t.Fatalf("%s: a converged split was written again:\n%s", what, lbAltNetnsDescribeRestores(restores))
		}
	}

	edge.reconcile(eth0)
	if err := reconcileLbAltSplit(edge.ctx, ipv4OnlyConfig(eth1)); err != nil {
		t.Fatal(err)
	}
	edge.requireSplitChain(eth0, baseBucketBlocks)
	edge.requireBucketRules(eth1, false, eth1.chainNames(t).splitChain, baseBucketBlocks)
	requireIpv6Unsplit("eth1 IPv4 only", eth1)
	edge.requireDialAnswers("eth1 IPv4 only", edge.probes(edge.interfaces, allPorts, nil, false), lbAltNetnsInterfaceAnswerer(onSplit, ipv4Only))
	requireConverged("eth1 IPv4 only", ipv4OnlyConfig(eth1))
	edge.fact("IPv4-only eth1: its IPv4 split by weight, no IPv6 HMARK rule, entry jump or split chain and no answer to IPv6, and the %d blocks' IPv6 chains written for its bridge", len(edge.blockChains(eth1, true)))

	// eth0's public IPv6 goes: the reconcile removes its IPv6 split, and only
	// that
	writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
	if err := writer.reconcile(edge.ctx, ipv4OnlyConfig(eth0)); err != nil {
		t.Fatal(err)
	}
	restores := commandLog.restores()
	if len(restores) == 0 {
		t.Fatal("the reconcile left eth0's IPv6 split in place")
	}
	for _, restore := range restores {
		if restore.name != lbAltNetnsIptablesCommand(true)+"-restore" {
			t.Fatalf("the reconcile that removed eth0's IPv6 split also wrote:\n%s", lbAltNetnsDescribeRestores(restores))
		}
	}
	requireIpv6Unsplit("eth0's public IPv6 gone", eth0)
	edge.requireBucketRules(eth0, false, eth0.chainNames(t).splitChain, baseBucketBlocks)
	edge.requireDialAnswers("eth0's public IPv6 gone", edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false), ipv4Only)
	requireConverged("eth0's public IPv6 gone", ipv4OnlyConfig(eth0))

	// it comes back, and the reconcile finds every block's IPv6 chain ready
	edge.reconcile(eth0)
	edge.requireSplitChain(eth0, baseBucketBlocks)
	edge.requireDialAnswers("eth0's public IPv6 back", edge.probes([]*lbAltNetnsInterface{eth0}, allPorts, nil, false), onSplit)
	edge.fact("eth0's public IPv6 gone: %d ip6tables transactions removed its IPv6 split by its listed rules and left its block chains, which its IPv6 split used again when the address came back", len(restores))
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
			// its listing of IPv4's nat table, before it writes there
			if command.name == lbAltNetnsIptablesCommand(false) && slices.Equal(command.args, []string{"-w", "-t", "nat", "-S"}) {
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
// whose other interface stays on nginx. While beta alone is ready, the
// interface's first switch waits for every block and writes nothing, so new
// flows keep reaching nginx rather than all going to beta. Turning lb_alt on
// with every block ready sends new flows to the blocks ahead of nginx's
// DNAT, while flows established on nginx stay there; a reconcile puts the
// entry jumps back ahead of a stray nginx redirect. Rolling back, nginx's redirect (warpctl's own) puts its DNAT ahead
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

	blockGenerations := map[string]*lbAltNetnsGeneration{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		blockGenerations[blockWeight.Block] = edge.startBlock(blockWeight.Block, 1)
		edge.writeBlockChains(blockGenerations[blockWeight.Block])
		if blockWeight.Block != "beta" {
			continue
		}
		// beta alone is ready
		if err := reconcileLbAltSplit(edge.ctx, edge.splitConfig(eth0)); !errors.Is(err, errLbAltSplitAwaitsEveryBlock) {
			t.Fatalf("reconcile with beta alone ready: %v, want it to wait for every block", err)
		}
		for _, ipv6 := range []bool{false, true} {
			if left := edge.splitState(eth0, ipv6); 0 < len(left["mangle"])+len(left["nat"])+len(left["chains"]) {
				t.Fatalf("%s holds eth0's split with beta alone ready: %v", lbAltNetnsIptablesCommand(ipv6), left)
			}
		}
		edge.requireDialAnswers("beta alone ready", edge.probes(edge.interfaces, allPorts, nil, false), bothOnNginx)
		edge.fact("beta alone ready: eth0's first switch waited for every block, wrote no rule in either family, and every new flow stayed on nginx")
	}
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
	// the removal keeps every block's chain, the block workers' (LBALT-IMPL
	// §2.5, §7), so an interface turned lb_alt again finds every block ready
	names := eth0.chainNames(t)
	wantBlockChains := []string{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		blockChain, err := names.blockChain(blockWeight.Block)
		if err != nil {
			t.Fatal(err)
		}
		wantBlockChains = append(wantBlockChains, blockChain)
	}
	slices.Sort(wantBlockChains)
	requireBlockChains := func(what string) {
		t.Helper()
		for _, ipv6 := range []bool{false, true} {
			if blockChains := edge.blockChains(eth0, ipv6); !slices.Equal(blockChains, wantBlockChains) {
				t.Fatalf("%s: %s keeps eth0's block chains %v, want every block's, %v", what, lbAltNetnsIptablesCommand(ipv6), blockChains, wantBlockChains)
			}
		}
	}
	requireBlockChains("after the interrupted removal")
	ipv4Left := edge.splitState(eth0, false)
	ipv6Left := edge.splitState(eth0, true)
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
		left := edge.splitState(eth0, ipv6)
		if 0 < len(left["mangle"])+len(left["nat"])+len(left["chains"]) {
			t.Fatalf("%s keeps after the removal: %v", lbAltNetnsIptablesCommand(ipv6), left)
		}
	}
	requireBlockChains("after the rollback")
	edge.fact("after the rollback: no HMARK rule, entry jump or split chain of eth0 in either family, and its %d block chains in each", len(wantBlockChains))
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

	// eth0 turned lb_alt again: the reconcile finds every block's kept chain
	// ready, with none written since, and puts the base split ahead of
	// nginx's DNAT
	edge.reconcile(eth0)
	edge.requireSplitChain(eth0, baseBucketBlocks)
	edge.requireDialAnswers("lb_alt again", edge.probes(edge.interfaces, allPorts, nil, false), lbAltNetnsInterfaceAnswerer(onSplit, eth1OnNginx))
	edge.fact("lb_alt again: the reconcile split eth0 by weight onto the kept block chains, with no block chain written")
}

// Conntrack keeps a udp flow on the generation it first reached, so the flows
// of a retired generation, whose clients keep sending, stay pinned to its dead
// ports. cleanupStaleConntrack deletes those tuples on every bridge the block
// binds, in both families, and only those: nothing of a generation whose udp
// sockets are being re-created (D22), which its trusted sockets keep holding
// its ports for, nothing of a draining generation, and nothing of another
// block. The pinned flows then reach the current generation through the
// split. The socket listing it reads (ss) holds a device-bound, a link-local
// and a dual-stack wildcard socket, in ss's own forms.
func TestLbAltNetnsEdgeCleansARetiredGenerationsUdpTuples(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	blockGenerations := edge.startBlocks(1)
	for _, iface := range edge.interfaces {
		edge.reconcile(iface)
	}
	baseBucketBlocks := edge.baseBucketBlocks()

	// sockets ss prints in its device-bound and wildcard forms, as a DHCP
	// client's and a wildcard service's are: on a dummy device of their own,
	// udp on 0.0.0.0 bound to the device and udp on the device's link-local
	// IPv6 address, which has no duplicate detection to wait for; and a
	// dual-stack tcp wildcard
	listenOddSockets := func() []io.Closer {
		t.Helper()
		const deviceName = "oddlink0"
		linkLocal := netip.MustParseAddr("fe80::1")
		lbAltNetnsIpBatch(t, []string{
			fmt.Sprintf("link add %s type dummy", deviceName),
			fmt.Sprintf("link set %s up", deviceName),
			fmt.Sprintf("addr add %s/64 dev %s nodad", linkLocal, deviceName),
		})
		closers := []io.Closer{}
		deviceBound := &net.ListenConfig{
			Control: func(network string, address string, rawConn syscall.RawConn) error {
				var socketErr error
				if err := rawConn.Control(func(fd uintptr) {
					socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, deviceName)
				}); err != nil {
					return err
				}
				return socketErr
			},
		}
		for _, network := range []struct {
			name    string
			address netip.AddrPort
		}{
			{name: "udp4", address: netip.AddrPortFrom(netip.IPv4Unspecified(), 6868)},
			{name: "udp6", address: netip.AddrPortFrom(linkLocal.WithZone(deviceName), 5466)},
		} {
			packetConn, err := deviceBound.ListenPacket(context.Background(), network.name, network.address.String())
			if err != nil {
				t.Fatal(err)
			}
			closers = append(closers, packetConn)
		}
		listener, err := net.Listen("tcp", ":9100")
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, listener)
		return closers
	}
	for _, closer := range listenOddSockets() {
		defer closer.Close()
	}
	sockets, err := readListenSockets(func(name string, args []string) (commandOutput, error) {
		return runQuiet(exec.Command(name, args...))
	})
	if err != nil {
		t.Fatalf("ss's listing: %s", err)
	}
	for _, iface := range edge.interfaces {
		for _, ipv6 := range []bool{false, true} {
			for _, protocol := range []string{"tcp", "udp"} {
				if !sockets.holds(protocol, iface.bridgeAddress(ipv6), blockGenerations["g1"].ports.tls) {
					t.Fatalf("ss's listing misses g1's %s socket on %s", protocol, iface.bridgeAddress(ipv6))
				}
			}
		}
	}
	edge.fact("ss: %d socket rows read, a device-bound, a link-local and a wildcard one among them", sockets.rowCount)

	newConnectWorker := func(block string) *RunWorker {
		portLists := [3][]string{}
		for generation := 1; generation <= 3; generation += 1 {
			ports := lbAltNetnsBlockPorts(block, generation)
			for i, port := range []int{ports.http, ports.tls, ports.whodis} {
				portLists[i] = append(portLists[i], strconv.Itoa(port))
			}
		}
		return &RunWorker{
			env:                   lbAltNetnsEnv,
			service:               lbAltBlockService,
			block:                 block,
			servicesDockerNetwork: edge.servicesNetwork,
			portBlocks: parsePortBlocks(fmt.Sprintf(
				"80:7123:%s;443:7124:%s;4053:7125:%s",
				strings.Join(portLists[0], ","),
				strings.Join(portLists[1], ","),
				strings.Join(portLists[2], ","),
			)),
			hostNetworking: true,
			quitEvent:      warp.NewEvent(),
		}
	}
	g1Worker := newConnectWorker("g1")
	g2Worker := newConnectWorker("g2")
	udpPorts := []lbAltNetnsPublicPort{}
	for _, publicPort := range lbAltNetnsPublicPorts() {
		if publicPort.protocol == "udp" {
			udpPorts = append(udpPorts, publicPort)
		}
	}
	bucketsOf := func(block string) func(bucket int) bool {
		return func(bucket int) bool {
			return baseBucketBlocks[bucket] == block
		}
	}
	establishedBlockGenerations := map[string]*lbAltNetnsGeneration{}
	for block, generation := range blockGenerations {
		establishedBlockGenerations[block] = generation
	}
	onEstablished := lbAltNetnsSplitAnswerer(baseBucketBlocks, establishedBlockGenerations)
	g1Flows := edge.probes(edge.interfaces, udpPorts, bucketsOf("g1"), true)
	g2Flows := edge.probes(edge.interfaces, udpPorts, bucketsOf("g2"), true)
	edge.requireDialAnswers("g1's udp flows", g1Flows, onEstablished)
	edge.requireDialAnswers("g2's udp flows", g2Flows, onEstablished)

	bridgeAddresses := []netip.Addr{netip.MustParseAddr(edge.servicesNetwork.ipv4.interfaceIp)}
	for _, iface := range edge.interfaces {
		bridgeAddresses = append(bridgeAddresses, iface.bridgeAddress(false), iface.bridgeAddress(true))
	}
	// the tuples, on every bridge, whose replies come from the generation's
	// tls or whodis port. Each count follows an exchange on the flows, which
	// renews their tuples, so none expires before the count after it.
	tuplesOf := func(generation *lbAltNetnsGeneration) int {
		count := 0
		for _, bridgeAddress := range bridgeAddresses {
			replyPortCounts := edge.conntrackReplyPortCounts(bridgeAddress)
			count += replyPortCounts[generation.ports.tls] + replyPortCounts[generation.ports.whodis]
		}
		return count
	}
	g1First := blockGenerations["g1"]
	g2First := blockGenerations["g2"]

	// g2's udp sockets are being re-created: its tcp sockets keep the bridges
	// in the listing, and its trusted sockets keep holding its udp ports
	edge.requireSendAnswers("g2's flows", g2Flows, onEstablished)
	g2Tuples := tuplesOf(g2First)
	if g2Tuples != len(g2Flows) {
		t.Fatalf("conntrack holds %d tuples of g2's %d flows", g2Tuples, len(g2Flows))
	}
	g2First.closePublic("udp")
	g2Worker.cleanupStaleConntrack()
	if tuples := tuplesOf(g2First); tuples != g2Tuples {
		t.Fatalf("re-creating g2's udp sockets cost %d of its %d tuples", g2Tuples-tuples, g2Tuples)
	}
	if err := g2First.openPublic("udp"); err != nil {
		t.Fatal(err)
	}
	edge.requireSendAnswers("g2's flows after its udp sockets came back", g2Flows, onEstablished)

	// g1's promotion: its first generation drains, and keeps its tuples
	g1Second := edge.startBlock("g1", 2)
	edge.writeBlockChains(g1Second)
	blockGenerations["g1"] = g1Second

	// the worker reads its block chains' targets from `iptables -L` in both
	// families, as a restart's container protection does, and its own chains
	// never claim its ports
	configuredPorts, err := g1Worker.configuredInternalPorts()
	if err != nil {
		t.Fatal(err)
	}
	targetPorts, err := g1Worker.lbAltChainTargetPorts(configuredPorts)
	if err != nil {
		t.Fatal(err)
	}
	if wantPorts := []int{g1Second.ports.http, g1Second.ports.tls, g1Second.ports.whodis}; !slices.Equal(slices.Sorted(maps.Keys(targetPorts)), wantPorts) {
		t.Fatalf("g1's block chains target %v, want %v", slices.Sorted(maps.Keys(targetPorts)), wantPorts)
	}
	externalInternalPorts := map[int]int{}
	for externalPort, servicePort := range g1Worker.portBlocks.externalsToService {
		externalInternalPorts[externalPort] = g1Second.ports.serviceInternalPorts()[servicePort]
	}
	if err := g1Worker.validateRedirectPortOwnership(externalInternalPorts); err != nil {
		t.Fatal(err)
	}
	edge.requireSendAnswers("g1's flows on the draining generation", g1Flows, onEstablished)
	g1Tuples := tuplesOf(g1First)
	if g1Tuples != len(g1Flows) {
		t.Fatalf("conntrack holds %d tuples of g1's %d flows", g1Tuples, len(g1Flows))
	}
	g1Worker.cleanupStaleConntrack()
	if tuples := tuplesOf(g1First); tuples != g1Tuples {
		t.Fatalf("the cleanup took %d of the draining generation's %d tuples", g1Tuples-tuples, g1Tuples)
	}

	// retired, its flows stay pinned to its dead ports
	g1First.retire()
	edge.requireSendAnswers("g1's flows pinned to the retired generation", g1Flows, func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
		return nil
	})
	if tuples := tuplesOf(g1First); tuples != len(g1Flows) {
		t.Fatalf("%d tuples pin g1's %d flows to the retired generation", tuples, len(g1Flows))
	}
	edge.requireSendAnswers("g2's flows before the cleanup", g2Flows, onEstablished)
	g2Tuples = tuplesOf(g2First)

	logOutput := captureErrOutput(t)
	g1Worker.cleanupStaleConntrack()
	cleanupLines := []string{}
	deletedFlowCount := 0
	cleanupCounts := regexp.MustCompile(`deleted_flows=(\d+) errors=(\d+)`)
	for _, line := range strings.Split(logOutput.String(), "\n") {
		if !strings.Contains(line, "Conntrack cleanup") {
			continue
		}
		cleanupLines = append(cleanupLines, line)
		groups := cleanupCounts.FindStringSubmatch(line)
		if groups == nil || groups[2] != "0" {
			t.Fatalf("conntrack cleanup failed: %s", line)
		}
		count, err := strconv.Atoi(groups[1])
		if err != nil {
			t.Fatal(err)
		}
		deletedFlowCount += count
	}
	// the services bridge, and both families of each lb bridge
	if len(cleanupLines) != 1+2*len(edge.interfaces) {
		t.Fatalf("conntrack cleanup ran on %d bridges:\n%s", len(cleanupLines), strings.Join(cleanupLines, "\n"))
	}
	if tuples := tuplesOf(g1First); tuples != 0 {
		t.Fatalf("%d tuples of the retired generation are left", tuples)
	}
	if tuples := tuplesOf(g2First); tuples != g2Tuples {
		t.Fatalf("the cleanup took %d of g2's %d tuples", g2Tuples-tuples, g2Tuples)
	}
	if deletedFlowCount != len(g1Flows) {
		t.Fatalf("the cleanup deleted %d tuples, want the %d of the retired generation", deletedFlowCount, len(g1Flows))
	}
	edge.fact("conntrack cleanup: %d tuples of the retired generation deleted on %d bridges; none of the draining one, of re-created sockets or of another block", deletedFlowCount, len(cleanupLines))

	edge.requireSendAnswers("g1's flows after the cleanup", g1Flows, lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations))
	edge.requireSendAnswers("g2's flows after the cleanup", g2Flows, onEstablished)
}

// HMARK marks only a new flow's first packet, to an lb_alt interface's public
// address and ports. Traffic the host sends with a routing mark, 0x65 to 0x6a
// as the edges' fwmark rules route it, keeps its mark to the wire and leaves
// by its table's interface, also to the public ports of another address, as a
// host-networked service's egress to a remote :443 or :53 does. Inbound
// packets of established split flows, and inbound flows to another port of
// the public address, get no bucket mark. Replies to the split's flows carry
// none, with the kernel's default tcp_fwmark_accept and fwmark_reflect, which
// the test reports. No fwmark rule of the host selects a bucket mark.
func TestLbAltNetnsEdgeLeavesRoutingMarksAlone(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	blockGenerations := edge.startBlocks(1)
	for _, iface := range edge.interfaces {
		edge.reconcile(iface)
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	eth0 := edge.interfaces[0]
	bucketMark := fmt.Sprintf("%#x/0xffff0000", lbAltHmarkOffset)

	for _, sysctl := range []string{"net/ipv4/tcp_fwmark_accept", "net/ipv4/fwmark_reflect", "net/ipv6/fwmark_reflect"} {
		value, err := os.ReadFile("/proc/sys/" + sysctl)
		if err != nil {
			t.Fatal(err)
		}
		edge.fact("%s = %s", sysctl, strings.TrimSpace(string(value)))
	}

	const unrelatedPort = 8080
	// the edges' routing marks, 0x65 to 0x6a: the lb units' own two route by
	// their interfaces' tables, and the harness routes the other four by the
	// same tables in turn, as other interfaces' units would by theirs
	markInterfaces := map[int]*lbAltNetnsInterface{}
	for i, mark := 0, 0x65; mark <= 0x6a; i, mark = i+1, mark+1 {
		iface := edge.interfaces[i%len(edge.interfaces)]
		markInterfaces[mark] = iface
		if mark == iface.spec.fwMark {
			continue
		}
		for _, family := range []string{"-4", "-6"} {
			if _, err := lbAltNetnsCommand("", "ip", family, "rule", "add", "fwmark", strconv.Itoa(mark), "table", strconv.Itoa(iface.spec.tableNumber)); err != nil {
				t.Fatal(err)
			}
		}
	}

	// the routed traffic goes to the public ports of a client source, which
	// the main table has no route to, so only the mark's table routes it
	publicPorts := lbAltNetnsSplitPublicPorts()
	familyDestinations := map[bool]netip.Addr{}
	for _, ipv6 := range []bool{false, true} {
		sources, err := lbAltNetnsSources(ipv6)
		if err != nil {
			t.Fatal(err)
		}
		familyDestinations[ipv6] = sources[0]
	}
	for _, ipv6 := range []bool{false, true} {
		publicAddress := eth0.publicAddress(ipv6).String()
		edge.addCounter(ipv6, "INPUT", "unrelated", "-d", publicAddress, "-p", "tcp", "--dport", strconv.Itoa(unrelatedPort))
		edge.addCounter(ipv6, "INPUT", "marked-unrelated", "-d", publicAddress, "-p", "tcp", "--dport", strconv.Itoa(unrelatedPort), "-m", "mark", "--mark", bucketMark)
		// after the HMARK rules, which the reconcile put first
		establishedArgs := []string{"-d", publicAddress, "-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "ORIGINAL"}
		edge.addCounter(ipv6, "PREROUTING", "established", establishedArgs...)
		edge.addCounter(ipv6, "PREROUTING", "marked-established", append(slices.Clone(establishedArgs), "-m", "mark", "--mark", bucketMark)...)
		edge.addCounter(ipv6, "POSTROUTING", "reply", "-m", "conntrack", "--ctdir", "REPLY", "--ctorigdst", publicAddress)
		edge.addCounter(ipv6, "POSTROUTING", "marked-reply", "-m", "conntrack", "--ctdir", "REPLY", "-m", "mark", "--mark", bucketMark)
		// every datagram and syn the host sends to the destination's public
		// ports, and those that leave by each routing mark's interface with
		// the mark
		for _, protocol := range []string{"udp", "tcp"} {
			portTexts := []string{}
			for _, port := range publicPorts[protocol] {
				portTexts = append(portTexts, strconv.Itoa(port))
			}
			sentArgs := []string{"-d", familyDestinations[ipv6].String(), "-p", protocol}
			if protocol == "tcp" {
				sentArgs = append(sentArgs, "--syn")
			}
			sentArgs = append(sentArgs, "-m", "multiport", "--dports", strings.Join(portTexts, ","))
			edge.addCounter(ipv6, "POSTROUTING", "sent-"+protocol, sentArgs...)
			for mark, iface := range markInterfaces {
				edge.addCounter(ipv6, "POSTROUTING", fmt.Sprintf("routing-mark-%s-%#x", protocol, mark), append(slices.Clone(sentArgs), "-o", iface.spec.name, "-m", "mark", "--mark", fmt.Sprintf("%#x", mark))...)
			}
		}
	}

	// an unrelated service on the public address
	unrelated := edge.startGeneration("unrelated", 0, lbAltNetnsPorts{http: unrelatedPort, tls: 0, whodis: 0}, nil, netip.Addr{})
	for _, ipv6 := range []bool{false, true} {
		if err := unrelated.listenPublic("tcp", eth0.publicAddress(ipv6), unrelatedPort, 1); err != nil {
			t.Fatal(err)
		}
	}
	unrelatedProbes := edge.probes([]*lbAltNetnsInterface{eth0}, []lbAltNetnsPublicPort{lbAltNetnsPublicPort{protocol: "tcp", port: unrelatedPort}}, nil, false)
	for i, result := range edge.dial(unrelatedProbes) {
		probe := unrelatedProbes[i]
		if want := unrelated.answer("tcp", probe.target()); result.Answer != want {
			t.Fatalf("unrelated flow from %s: got %q (%s), want %q", probe.source, result.Answer, result.Error, want)
		}
	}

	// split flows, kept for a second exchange, whose inbound packets are
	// those of established flows
	tlsPorts := []lbAltNetnsPublicPort{
		lbAltNetnsPublicPort{protocol: "tcp", port: 443},
		lbAltNetnsPublicPort{protocol: "udp", port: 443},
	}
	splitProbes := edge.probes([]*lbAltNetnsInterface{eth0}, tlsPorts, nil, true)
	onSplit := lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations)
	edge.requireDialAnswers("split flows", splitProbes, onSplit)
	edge.requireSendAnswers("established split flows", splitProbes, onSplit)

	// with each routing mark, one socket sends datagrams to each public udp
	// port of the destination, and a dial to each public tcp port is refused
	// by the client, whose reset shows that the syn reached it
	const markedDatagramCount = 10
	markedControl := func(mark int) func(network string, address string, rawConn syscall.RawConn) error {
		return func(network string, address string, rawConn syscall.RawConn) error {
			var socketErr error
			if err := rawConn.Control(func(fd uintptr) {
				socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}); err != nil {
				return err
			}
			return socketErr
		}
	}
	for _, ipv6 := range []bool{false, true} {
		destination := familyDestinations[ipv6]
		familySuffix := lbAltNetnsFamilySuffix(destination)
		for mark := range markInterfaces {
			sendDatagrams := func() error {
				markedConfig := &net.ListenConfig{
					Control: markedControl(mark),
				}
				packetConn, err := markedConfig.ListenPacket(edge.ctx, "udp"+familySuffix, ":0")
				if err != nil {
					return err
				}
				defer packetConn.Close()
				for _, port := range publicPorts["udp"] {
					for range markedDatagramCount {
						if _, err := packetConn.(*net.UDPConn).WriteToUDPAddrPort([]byte("routing mark"), netip.AddrPortFrom(destination, uint16(port))); err != nil {
							return fmt.Errorf("udp %d: %w", port, err)
						}
					}
				}
				return nil
			}
			if err := sendDatagrams(); err != nil {
				t.Fatalf("datagrams with mark %#x to %s: %s", mark, destination, err)
			}
			markedDialer := &net.Dialer{
				Timeout: edge.settings.flowTimeout,
				Control: markedControl(mark),
			}
			for _, port := range publicPorts["tcp"] {
				target := netip.AddrPortFrom(destination, uint16(port))
				conn, err := markedDialer.DialContext(edge.ctx, "tcp"+familySuffix, target.String())
				if err == nil {
					conn.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("dial with mark %#x to tcp %s: %v, want the client's refusal", mark, target, err)
				}
			}
		}
	}

	for _, ipv6 := range []bool{false, true} {
		counterPackets := edge.counterPackets(ipv6)
		command := lbAltNetnsIptablesCommand(ipv6)
		if counterPackets["unrelated"] == 0 || counterPackets["marked-unrelated"] != 0 {
			t.Fatalf("%s unrelated inbound packets: %d, %d of them bucket-marked", command, counterPackets["unrelated"], counterPackets["marked-unrelated"])
		}
		if counterPackets["established"] == 0 || counterPackets["marked-established"] != 0 {
			t.Fatalf("%s inbound packets of established flows: %d, %d of them bucket-marked", command, counterPackets["established"], counterPackets["marked-established"])
		}
		if counterPackets["reply"] == 0 || counterPackets["marked-reply"] != 0 {
			t.Fatalf("%s reply packets: %d of the split's flows, %d bucket-marked", command, counterPackets["reply"], counterPackets["marked-reply"])
		}
		markedCounts := map[string]int{}
		for mark, iface := range markInterfaces {
			udpCount := counterPackets[fmt.Sprintf("routing-mark-udp-%#x", mark)]
			if want := len(publicPorts["udp"]) * markedDatagramCount; udpCount != want {
				t.Fatalf("%s: %d of %d datagrams with mark %#x left by %s with the mark", command, udpCount, want, mark, iface.spec.name)
			}
			// a syn whose reset comes late is sent again
			tcpCount := counterPackets[fmt.Sprintf("routing-mark-tcp-%#x", mark)]
			if tcpCount < len(publicPorts["tcp"]) {
				t.Fatalf("%s: %d syns of %d dials with mark %#x left by %s with the mark", command, tcpCount, len(publicPorts["tcp"]), mark, iface.spec.name)
			}
			markedCounts["udp"] += udpCount
			markedCounts["tcp"] += tcpCount
		}
		// and none left without its mark, or by another interface
		for _, protocol := range []string{"udp", "tcp"} {
			if sentCount := counterPackets["sent-"+protocol]; sentCount != markedCounts[protocol] {
				t.Fatalf("%s: the host sent %d %s packets to public ports, %d of them by their mark's interface with the mark", command, sentCount, protocol, markedCounts[protocol])
			}
		}
		edge.fact("%s: %d unrelated inbound packets, %d inbound packets of established split flows and %d reply packets carried no bucket mark; %d datagrams and %d syns with routing marks 0x65-0x6a to a client's public ports left by their tables' interfaces with their marks", command, counterPackets["unrelated"], counterPackets["established"], counterPackets["reply"], markedCounts["udp"], markedCounts["tcp"])
	}

	fwMarkRule := regexp.MustCompile(`\bfwmark (0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?`)
	for _, family := range []string{"-4", "-6"} {
		out, err := lbAltNetnsCommand("", "ip", family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		ruleCount := 0
		for _, groups := range fwMarkRule.FindAllStringSubmatch(out, -1) {
			value, err := strconv.ParseUint(groups[1], 0, 32)
			if err != nil {
				t.Fatal(err)
			}
			mask := uint64(0xffffffff)
			if groups[2] != "" {
				if mask, err = strconv.ParseUint(groups[2], 0, 32); err != nil {
					t.Fatal(err)
				}
			}
			ruleCount += 1
			for bucket := range lbAltHmarkMod {
				if uint64(lbAltHmarkOffset+bucket)&mask == value {
					t.Fatalf("ip %s rule fwmark %s selects bucket %d's mark", family, groups[0], bucket)
				}
			}
		}
		if ruleCount != len(markInterfaces) {
			t.Fatalf("ip %s rule has %d fwmark rules, want the %d routing marks':\n%s", family, ruleCount, len(markInterfaces), out)
		}
		edge.fact("ip %s rule: %d fwmark rules, none selects a bucket mark", family, ruleCount)
	}
}

// With tcp_fwmark_accept and fwmark_reflect on, which copy a packet's mark to
// the socket that accepts it and to the kernel's own resets, the split's tcp
// replies carry their bucket marks. No fwmark rule selects a bucket mark, so
// they still leave by the interface their flow came in on, through its policy
// table: connections are answered from the public address, and the reset of a
// block whose tcp sockets are gone reaches the client as a refusal.
// TestLbAltNetns starts this test's container with both settings on
// (lbAltNetnsMarkedReplySysctls).
func TestLbAltNetnsEdgeRoutesRepliesThatCarryBucketMarks(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	for _, sysctl := range lbAltNetnsMarkedReplySysctls() {
		name, value, _ := strings.Cut(sysctl, "=")
		current, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(current)) != value {
			t.Fatalf("%s is %s: the container must start with %s (TestLbAltNetns)", name, strings.TrimSpace(string(current)), sysctl)
		}
	}
	blockGenerations := edge.startBlocks(1)
	for _, iface := range edge.interfaces {
		edge.reconcile(iface)
	}
	baseBucketBlocks := edge.baseBucketBlocks()
	bucketMark := fmt.Sprintf("%#x/0xffff0000", lbAltHmarkOffset)
	for _, iface := range edge.interfaces {
		for _, ipv6 := range []bool{false, true} {
			replyArgs := []string{"-m", "conntrack", "--ctdir", "REPLY", "--ctorigdst", iface.publicAddress(ipv6).String()}
			edge.addCounter(ipv6, "POSTROUTING", "marked-reply-"+iface.spec.name, append(replyArgs, "-o", iface.spec.name, "-m", "mark", "--mark", bucketMark)...)
			edge.addCounter(ipv6, "POSTROUTING", "astray-"+iface.spec.name, append(replyArgs, "!", "-o", iface.spec.name)...)
		}
	}

	tcpPorts := []lbAltNetnsPublicPort{}
	for _, publicPort := range lbAltNetnsPublicPorts() {
		if publicPort.protocol == "tcp" {
			tcpPorts = append(tcpPorts, publicPort)
		}
	}
	edge.requireDialAnswers("tcp flows", edge.probes(edge.interfaces, tcpPorts, nil, false), lbAltNetnsSplitAnswerer(baseBucketBlocks, blockGenerations))

	// g2's tcp sockets are gone, and the split still sends its buckets there
	blockGenerations["g2"].closePublic("tcp")
	g2Probes := edge.probes(edge.interfaces, tcpPorts, func(bucket int) bool {
		return baseBucketBlocks[bucket] == "g2"
	}, false)
	for i, result := range edge.dial(g2Probes) {
		if result.Answer != "" || !strings.Contains(result.Error, "connection refused") {
			probe := g2Probes[i]
			t.Fatalf("%s %s from %s to g2's closed socket: got %q (%s), want a refusal", probe.iface.spec.name, probe.target(), probe.source, result.Answer, result.Error)
		}
	}

	for _, ipv6 := range []bool{false, true} {
		counterPackets := edge.counterPackets(ipv6)
		for _, iface := range edge.interfaces {
			if counterPackets["marked-reply-"+iface.spec.name] == 0 || counterPackets["astray-"+iface.spec.name] != 0 {
				t.Fatalf("%s replies of %s: %d bucket-marked by it, %d by another interface", lbAltNetnsIptablesCommand(ipv6), iface.spec.name, counterPackets["marked-reply-"+iface.spec.name], counterPackets["astray-"+iface.spec.name])
			}
			edge.fact("%s with marks copied onto replies: %d bucket-marked reply packets of %s left by it, none by another interface", lbAltNetnsIptablesCommand(ipv6), counterPackets["marked-reply-"+iface.spec.name], iface.spec.name)
		}
	}
	edge.fact("with marks copied onto replies: %d tcp dials to a block with no tcp socket were refused by resets that reached the client", len(g2Probes))
}

// The sources of a port-hash prefix (server LBALTOPT2 R16) spread their new
// tcp flows by source port: on both interfaces and in both families, each tcp
// flow from such a source reaches the block the port model
// (lbAltNetnsHmarkPortBucket) puts its source address and port in, while its
// udp flows, and every flow of every other source, keep the source address's
// bucket (lbAltPortHashProtocols). The kernel lists the port-hash rules, tcp
// alone, after the address-only rules of each chain, in the form the
// reconcile compares, so another reconcile writes nothing. A prefix taken out
// of the config takes its rules with it, and its sources' new flows go back
// to their addresses' buckets; the rollback takes every rule of the
// interface.
func TestLbAltNetnsEdgeHashesPortHashSourcesByPort(t *testing.T) {
	edge := newLbAltNetnsEdge(t)
	blockGenerations := edge.startBlocks(1)
	baseBucketBlocks := edge.baseBucketBlocks()
	// the lower half of the client's first IPv4 range, and the start of its
	// IPv6 range: some sources of each family in a prefix, the rest outside
	ipv4Source := netip.MustParsePrefix("203.0.113.0/25")
	ipv6Source := netip.MustParsePrefix("2001:db8:c::/121")
	portHashConfig := func(iface *lbAltNetnsInterface, sources ...netip.Prefix) *lbAltSplitConfig {
		config := edge.splitConfig(iface)
		config.portHashSources = sources
		return config
	}
	// requires a reconcile of the configs to write nothing
	requireConverged := func(what string, sources ...netip.Prefix) {
		t.Helper()
		writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
		for _, iface := range edge.interfaces {
			if err := writer.reconcile(edge.ctx, portHashConfig(iface, sources...)); err != nil {
				t.Fatal(err)
			}
		}
		if restores := commandLog.restores(); 0 < len(restores) {
			t.Fatalf("%s: a converged split was written again:\n%s", what, lbAltNetnsDescribeRestores(restores))
		}
	}
	// requires each chain's HMARK rules of the interface to list the
	// address-only rules first and then each source's tcp rule, in order, and
	// returns the listed port-hash rules
	requireHmarkOrder := func(what string, iface *lbAltNetnsInterface, ipv6 bool, sources ...netip.Prefix) []string {
		t.Helper()
		portHashRules := []string{}
		for _, chain := range []string{"PREROUTING", "OUTPUT"} {
			sourceArgs := []string{}
			for _, rule := range edge.taggedRules(ipv6, "mangle", iface.chainNames(t).ruleComment) {
				if !strings.HasPrefix(rule, "-A "+chain+" ") {
					continue
				}
				sourceArg := ""
				if rest, ok := strings.CutPrefix(rule, "-A "+chain+" -s "); ok {
					sourceArg, _, _ = strings.Cut(rest, " ")
					portHashRules = append(portHashRules, rule)
					if !strings.Contains(rule, " --hmark-sport-mask 0xffff ") || !strings.Contains(rule, " -p tcp ") {
						t.Fatalf("%s: %s lists a port-hash rule that is not tcp with the port mask: %s", what, lbAltNetnsIptablesCommand(ipv6), rule)
					}
				}
				sourceArgs = append(sourceArgs, sourceArg)
			}
			// tcp and udp for no source, then tcp alone for each
			wantSourceArgs := []string{"", ""}
			for _, source := range sources {
				if source.Addr().Is6() == ipv6 {
					wantSourceArgs = append(wantSourceArgs, source.String())
				}
			}
			if !slices.Equal(sourceArgs, wantSourceArgs) {
				t.Fatalf("%s: %s %s %s lists the HMARK rules of the sources %q, want %q", what, iface.spec.name, lbAltNetnsIptablesCommand(ipv6), chain, sourceArgs, wantSourceArgs)
			}
		}
		return portHashRules
	}
	// dials every source on every interface and public port, and requires
	// each flow to reach the block of its bucket: by its source port for a
	// tcp flow whose source a source prefix holds, else by its source address.
	// Returns how many tcp flows of the prefixes' sources the port took to
	// another block than their address's, how many of those sources reached
	// more than one block, how many udp flows of the prefixes' sources kept
	// their address's block, and how many of those the port would have taken
	// to another block, which shows the probes tell the two hashes apart.
	requirePortBuckets := func(what string, sources ...netip.Prefix) (int, int, int, int) {
		t.Helper()
		probes := edge.probes(edge.interfaces, lbAltNetnsPublicPorts(), nil, false)
		results := edge.dial(probes)
		flowPorts := map[string]uint16{}
		for _, result := range results {
			if local, err := netip.ParseAddrPort(result.Local); err == nil {
				flowPorts[result.Id] = local.Port()
			}
		}
		portHashed := func(source netip.Addr) bool {
			return slices.ContainsFunc(sources, func(prefix netip.Prefix) bool {
				return prefix.Contains(source)
			})
		}
		movedFlowCount := 0
		sourceBlocks := map[netip.Addr]map[string]bool{}
		keptUdpFlowCount := 0
		portWouldMoveUdpFlowCount := 0
		edge.requireAnswers(what, probes, results, func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
			block := baseBucketBlocks[probe.bucket()]
			if !portHashed(probe.source) {
				return blockGenerations[block]
			}
			portBlock := baseBucketBlocks[lbAltNetnsHmarkPortBucket(probe.source, flowPorts[probe.flow.Id])]
			if probe.protocol != "tcp" {
				// udp keeps the address hash
				keptUdpFlowCount += 1
				if portBlock != block {
					portWouldMoveUdpFlowCount += 1
				}
				return blockGenerations[block]
			}
			if portBlock != block {
				movedFlowCount += 1
			}
			if sourceBlocks[probe.source] == nil {
				sourceBlocks[probe.source] = map[string]bool{}
			}
			sourceBlocks[probe.source][portBlock] = true
			return blockGenerations[portBlock]
		})
		spreadSourceCount := 0
		for _, blocks := range sourceBlocks {
			if 1 < len(blocks) {
				spreadSourceCount += 1
			}
		}
		return movedFlowCount, spreadSourceCount, keptUdpFlowCount, portWouldMoveUdpFlowCount
	}

	for _, iface := range edge.interfaces {
		if err := reconcileLbAltSplit(edge.ctx, portHashConfig(iface, ipv4Source, ipv6Source)); err != nil {
			t.Fatal(err)
		}
		edge.requireSplitChain(iface, baseBucketBlocks)
		for _, ipv6 := range []bool{false, true} {
			portHashRules := requireHmarkOrder("both prefixes", iface, ipv6, ipv4Source, ipv6Source)
			if iface.index == 0 {
				edge.fact("%s lists %s", lbAltNetnsIptablesCommand(ipv6), portHashRules[0])
			}
		}
	}
	requireConverged("both prefixes", ipv4Source, ipv6Source)
	movedFlowCount, spreadSourceCount, keptUdpFlowCount, portWouldMoveUdpFlowCount := requirePortBuckets("both prefixes", ipv4Source, ipv6Source)
	if movedFlowCount == 0 || spreadSourceCount == 0 || portWouldMoveUdpFlowCount == 0 {
		t.Fatalf("both prefixes: the port took %d tcp flows to another block and spread %d sources, and would have moved %d udp flows, so the probes cannot tell the port hash from the address hash", movedFlowCount, spreadSourceCount, portWouldMoveUdpFlowCount)
	}
	edge.fact("port-hash prefixes %s and %s: every tcp flow of their sources reached its port bucket's block, %d of them another block than their address's, %d sources more than one block; all %d of their udp flows kept their address's block, though the port would have moved %d; every other source kept its address's block", ipv4Source, ipv6Source, movedFlowCount, spreadSourceCount, keptUdpFlowCount, portWouldMoveUdpFlowCount)

	// the IPv6 prefix leaves the config: only its rules go
	for _, iface := range edge.interfaces {
		writer, commandLog := edge.newWriter(lbAltNetnsWriterHooks{})
		if err := writer.reconcile(edge.ctx, portHashConfig(iface, ipv4Source)); err != nil {
			t.Fatal(err)
		}
		restores := commandLog.restores()
		if len(restores) != 1 || restores[0].name != lbAltNetnsIptablesCommand(true)+"-restore" || !strings.HasPrefix(restores[0].stdin, "*mangle\n") {
			t.Fatalf("taking the IPv6 prefix out of %s's config wrote:\n%s", iface.spec.name, lbAltNetnsDescribeRestores(restores))
		}
		requireHmarkOrder("the IPv4 prefix alone", iface, false, ipv4Source)
		requireHmarkOrder("the IPv4 prefix alone", iface, true)
	}
	requireConverged("the IPv4 prefix alone", ipv4Source)
	movedFlowCount, _, _, _ = requirePortBuckets("the IPv4 prefix alone", ipv4Source)
	if movedFlowCount == 0 {
		t.Fatal("the IPv4 prefix alone: the port took no tcp flow to another block")
	}
	edge.fact("the IPv6 prefix taken out of the config: one ip6tables mangle transaction per interface removed its rules, and its sources' new flows went back to their addresses' blocks")

	// the rollback takes every rule of the interface, the port-hash rules too
	for _, iface := range edge.interfaces {
		if err := removeLbAltSplit(edge.ctx, lbAltNetnsEnv, iface.spec.name); err != nil {
			t.Fatal(err)
		}
		for _, ipv6 := range []bool{false, true} {
			if state := edge.splitState(iface, ipv6); 0 < len(state["mangle"])+len(state["nat"])+len(state["chains"]) {
				t.Fatalf("the rollback left %s's %s split: %v", iface.spec.name, lbAltNetnsIptablesCommand(ipv6), state)
			}
		}
	}
	edge.fact("the rollback removed every HMARK rule, port-hash rules among them, by its listed form")
}
