package main

// Tests of the lb_alt public port contract (lbalt_edge.go): the host dnat
// targets of an lb_alt interface beside an nginx interface's, the block chain
// targets, and the refusal of every port without a front socket.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
)

// main's lb_alt public ports (services.LbAltPublicPorts on main's shape)
func lbAltMainPublicPorts() map[string][]int {
	return map[string][]int{
		"tcp": {80, 443},
		"udp": {53, 443, 4053},
	}
}

// The same lb service ports and forward (udp 53 to 4053) through both maps.
// nginx keeps today's contract: the forward target 4053 is private on both
// protocols, and every direct lb port is published on both, udp 80 included.
// lb_alt publishes the §2.3 map: tcp 80 and 443, udp 443, 4053 and 53, with
// 53 and 4053 both reaching whodis, and nothing on udp 80.
func TestLbAltPublicPortServiceTargetsBesideNginx(t *testing.T) {
	servicePorts := map[int]int{80: 7301, 443: 7302, 4053: 7303}
	forwardPorts := parseForwardPorts("udp:53:4053")

	nginxTcp, err := publicPortServiceTargets("tcp", servicePorts, forwardPorts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(nginxTcp), "map[80:80 443:443]"; got != want {
		t.Fatalf("nginx tcp targets=%s want=%s", got, want)
	}
	nginxUdp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(nginxUdp), "map[53:4053 80:80 443:443]"; got != want {
		t.Fatalf("nginx udp targets=%s want=%s", got, want)
	}

	lbAltTcp, err := lbAltPublicPortServiceTargets("tcp", lbAltMainPublicPorts(), servicePorts)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(lbAltTcp), "map[80:80 443:443]"; got != want {
		t.Fatalf("lb_alt tcp targets=%s want=%s", got, want)
	}
	lbAltUdp, err := lbAltPublicPortServiceTargets("udp", lbAltMainPublicPorts(), servicePorts)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(lbAltUdp), "map[53:4053 443:443 4053:4053]"; got != want {
		t.Fatalf("lb_alt udp targets=%s want=%s", got, want)
	}
	if _, ok := lbAltUdp[80]; ok {
		t.Fatal("lb_alt publishes udp 80")
	}
	if _, ok := nginxUdp[4053]; ok {
		t.Fatal("nginx publishes its forward target 4053")
	}
}

// Every port outside the §2.3 map is refused, whatever the list says, as is a
// port whose connect service port the generation does not allocate.
func TestLbAltPublicPortServiceTargetsRefuseWhatNoSocketServes(t *testing.T) {
	servicePorts := map[int]int{80: 7301, 443: 7302, 4053: 7303}
	cases := []struct {
		protocol     string
		publicPorts  map[string][]int
		servicePorts map[int]int
		want         string
	}{
		{protocol: "udp", publicPorts: map[string][]int{"udp": {80}}, servicePorts: servicePorts, want: "udp port 80 has no front socket"},
		{protocol: "tcp", publicPorts: map[string][]int{"tcp": {4053}}, servicePorts: servicePorts, want: "tcp port 4053 has no front socket"},
		{protocol: "tcp", publicPorts: map[string][]int{"tcp": {53}}, servicePorts: servicePorts, want: "tcp port 53 has no front socket"},
		{protocol: "tcp", publicPorts: map[string][]int{"tcp": {80, 443, 8443}}, servicePorts: servicePorts, want: "tcp port 8443 has no front socket"},
		{protocol: "udp", publicPorts: map[string][]int{"udp": {53, 8053}}, servicePorts: servicePorts, want: "udp port 8053 has no front socket"},
		// a bad port on the other protocol still refuses the list
		{protocol: "tcp", publicPorts: map[string][]int{"tcp": {80}, "udp": {80}}, servicePorts: servicePorts, want: "udp port 80 has no front socket"},
		{protocol: "tcp", publicPorts: map[string][]int{"sctp": {443}}, servicePorts: servicePorts, want: `protocol "sctp"`},
		{protocol: "icmp", publicPorts: lbAltMainPublicPorts(), servicePorts: servicePorts, want: `invalid lb_alt protocol "icmp"`},
		// whodis is not allocated: neither 53 nor 4053 may be published
		{protocol: "udp", publicPorts: map[string][]int{"udp": {53}}, servicePorts: map[int]int{80: 7301, 443: 7302}, want: "udp port 53 reaches service port 4053, which the generation does not allocate"},
		{protocol: "tcp", publicPorts: map[string][]int{"tcp": {443}}, servicePorts: map[int]int{80: 7301}, want: "tcp port 443 reaches service port 443"},
	}
	for _, c := range cases {
		targets, err := lbAltPublicPortServiceTargets(c.protocol, c.publicPorts, c.servicePorts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: targets=%v err=%v, want %q", c.protocol, c.publicPorts, targets, err, c.want)
		}
	}
}

// The block chain targets: by protocol then port, each public port to the
// internal port of the connect service port behind it, so udp 53 and 4053
// share whodis's internal port and tcp and udp 443 share the 443 port.
func TestLbAltBlockTargetsMapEachPublicPortToItsSocket(t *testing.T) {
	// a connect generation's WARP_PORTS: 80 the front's port-80 handler, 443
	// tls and quic, 4053 whodis, 5080 and up the service's own ports
	servicePorts := map[int]int{80: 7080, 443: 7443, 4053: 7453, 5080: 7500}
	targets, err := lbAltBlockTargets(lbAltMainPublicPorts(), servicePorts)
	if err != nil {
		t.Fatal(err)
	}
	want := []lbAltBlockTarget{
		{protocol: "tcp", publicPort: 80, internalPort: 7080},
		{protocol: "tcp", publicPort: 443, internalPort: 7443},
		{protocol: "udp", publicPort: 53, internalPort: 7453},
		{protocol: "udp", publicPort: 443, internalPort: 7443},
		{protocol: "udp", publicPort: 4053, internalPort: 7453},
	}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets=%+v want=%+v", targets, want)
	}

	// an interface lb_alt is not in effect on has no public ports
	empty, err := lbAltBlockTargets(map[string][]int{}, servicePorts)
	if err != nil || len(empty) != 0 {
		t.Fatalf("targets=%v err=%v, want none", empty, err)
	}
	if _, err := lbAltBlockTargets(map[string][]int{"udp": {80}}, servicePorts); err == nil || !strings.Contains(err.Error(), "udp port 80 has no front socket") {
		t.Fatalf("err=%v, want udp 80 refused", err)
	}
}

// The composed path: services.LbAltPublicPorts of a loaded config in main's
// shape feeds the block targets, and an nginx interface of the same host
// gives none.
func TestLbAltBlockTargetsFromTheServicesConfig(t *testing.T) {
	generator := newVyosTestGeneratorWith(t, func(servicesYaml string) string {
		return lbAltVyosServicesYaml(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true})
	})
	latest := generator.servicesConfig.Latest()
	publicPorts := services.LbAltPublicPorts(latest, "edge-3.example.com", "eno1np0")
	if !reflect.DeepEqual(publicPorts, lbAltMainPublicPorts()) {
		t.Fatalf("lb_alt public ports=%v want=%v", publicPorts, lbAltMainPublicPorts())
	}
	targets, err := lbAltBlockTargets(publicPorts, map[int]int{80: 7080, 443: 7443, 4053: 7453})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(targets), "[{tcp 80 7080} {tcp 443 7443} {udp 53 7453} {udp 443 7443} {udp 4053 7453}]"; got != want {
		t.Fatalf("targets=%s want=%s", got, want)
	}
	nginxPublicPorts := services.LbAltPublicPorts(latest, "edge-3.example.com", "eno2np1")
	nginxTargets, err := lbAltBlockTargets(nginxPublicPorts, map[int]int{80: 7080, 443: 7443, 4053: 7453})
	if err != nil || len(nginxTargets) != 0 {
		t.Fatalf("nginx interface targets=%v err=%v, want none", nginxTargets, err)
	}
}
