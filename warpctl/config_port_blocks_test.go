package main

// Tests of the port block allocation of a given services config
// (portBlocksOf), which the lb_alt route render runs on every connect
// generation start, and of the nginx generator's read-only use of the config
// it is given.

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
)

// portBlocksOf allocates exactly what getPortBlocks allocates from the vault,
// logs nothing, and leaves the config as it was: the lb's udp stream port
// services, which every interface of the fixture inherits, are merged into a
// copy, not into the interfaces. getPortBlocks still logs each assignment.
func TestPortBlocksOfAllocatesAsGetPortBlocksQuietly(t *testing.T) {
	env := setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	servicesConfig := getServicesConfig(env)
	if lbBlock := servicesConfig.Latest().Lb.Interfaces["edge-a.example"]["eth1"]; 0 < len(lbBlock.UdpStreamPortServices) {
		t.Fatal("the fixture's interface has stream port services of its own, so the merge is not checked")
	}

	errOutput := captureErrOutput(t)
	quietPortBlocks := portBlocksOf(servicesConfig, nil)
	if errOutput.Len() != 0 {
		t.Fatalf("portBlocksOf logged:\n%s", errOutput.String())
	}
	if !reflect.DeepEqual(servicesConfig, getServicesConfig(env)) {
		t.Fatal("portBlocksOf changed the services config it was given")
	}

	loggedPortBlocks := getPortBlocks(env)
	if !strings.Contains(errOutput.String(), "Assign port block connect g1 443\n") {
		t.Fatalf("getPortBlocks did not log its assignments:\n%s", errOutput.String())
	}
	if !reflect.DeepEqual(quietPortBlocks, loggedPortBlocks) {
		t.Fatalf("portBlocksOf allocated\n%v\nwhere getPortBlocks allocated\n%v", collectPortAssignments(quietPortBlocks), collectPortAssignments(loggedPortBlocks))
	}
	// the interfaces' inherited stream ports are allocated
	if portBlock := quietPortBlocks["edge-a.example"]["lb"]["edge-a.example-eth1"][4053]; portBlock == nil || portBlock.lbTypes["udp"] != "stream" {
		t.Fatalf("edge-a eth1 udp 4053 port block %+v, want a stream port block", portBlock)
	}
}

// The nginx generator's list of the services an lb host fronts is sorted in a
// copy: the host_services list of the config it was given stays as written.
func TestNginxConfigServicesSortsACopyOfTheHostList(t *testing.T) {
	hostServices := []string{"mcp", "connect", "api"}
	nginxConfig := &NginxConfig{
		servicesConfig: &services.ServicesConfig{
			Versions: []*services.ServicesConfigVersion{
				{
					HostServices: map[string][]string{"edge-a.example": hostServices},
					Services: map[string]*services.ServiceConfig{
						"api":     {},
						"connect": {},
						"mcp":     {},
					},
				},
			},
		},
		lbBlockInfo: &BlockInfo{
			service: "lb",
			host:    "edge-a.example",
		},
	}
	if got := nginxConfig.services(); !slices.Equal(got, []string{"api", "connect", "mcp"}) {
		t.Fatalf("services = %v, want them sorted", got)
	}
	if !slices.Equal(hostServices, []string{"mcp", "connect", "api"}) {
		t.Fatalf("the config's host_services list is now %v", hostServices)
	}
}
