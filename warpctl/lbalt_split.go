package main

// The lb_alt split (server/LBALT-IMPL.md §2.4, §2.5; LBALT.md D10, D13, review
// §4.7): HMARK on new flows to an lb_alt interface's public address, a split
// chain per interface sending bucket ranges to per-block chains by weight, and
// per-block chains that hold only the DNAT to that block's interface sockets.
// The lb unit of an lb_alt interface reconciles the HMARK rules, the entry jumps
// and the split chain every 30 s; each connect block worker writes its own block
// chain once its candidate generation is ready.
//
// Owner: unit w-split. These declarations are the contract other units call;
// the bodies are stubs until w-split lands.

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/warp/services"
)

// One lb_alt interface as the split sees it. An empty address means the family
// is absent.
type lbAltSplitInterface struct {
	name       string
	publicIpv4 string
	publicIpv6 string
	bridgeIpv4 string
	bridgeIpv6 string
	// services.LbAltPublicPorts: protocol -> public ports
	publicPorts map[string][]int
}

// The lb unit's view of its interface's split.
type lbAltSplitConfig struct {
	env            string
	splitInterface lbAltSplitInterface
	// the lb_alt service's blocks in services.ServiceBlockWeights order
	blockWeights []services.BlockWeight
}

// Reconciles the HMARK rules, the lb chain's entry jumps and the split chain of
// one lb_alt interface, in both families. Run by the lb unit at start and every
// 30 s. Orphaned bucket ranges move to ready blocks by weight; when every block
// is down the split sends nothing.
func reconcileLbAltSplit(ctx context.Context, config *lbAltSplitConfig) error {
	return errors.New("lbalt: split reconcile not implemented")
}

// Removes the HMARK rules, entry jumps, split chain and block chains of an
// interface that is no longer lb_alt, after nginx's DNAT is back (rollback, D18).
func removeLbAltSplit(ctx context.Context, env string, interfaceName string) error {
	return errors.New("lbalt: split removal not implemented")
}

// One DNAT a block chain holds: public (protocol, port) to the block's internal
// port on the interface's bridge address.
type lbAltBlockTarget struct {
	protocol     string
	publicPort   int
	internalPort int
}

// Writes the block's chain on every lb_alt interface, built complete before it
// replaces the previous generation's targets. Called by the block worker after
// pollLbAltReadiness accepts the candidate.
func writeLbAltBlockChains(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
	return errors.New("lbalt: block chains not implemented")
}

// One socket a candidate generation must report in X-UR-Front-Sockets.
type lbAltExpectedSocket struct {
	protocol string
	address  string
	port     int
}

// Polls the candidate's private status until it is accepted under §2.4 or the
// timeout passes: 200 with status exactly "ok", X-UR-Front-Ready 1, the
// expected generation and revision, and every expected socket at up == expected.
func pollLbAltReadiness(ctx context.Context, statusUrl string, generation string, revision string, expected []lbAltExpectedSocket, timeout time.Duration) error {
	return errors.New("lbalt: readiness poll not implemented")
}
