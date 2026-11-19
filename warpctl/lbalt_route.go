package main

// Rendering and writing the lb_alt route file (server/LBALT-IMPL.md §2.1, §2.2;
// LBALT.md D5). A connect worker on an lb_alt host renders the file when it
// starts a generation, from the same services.yml inputs and functions the nginx
// generator uses, writes it once under WARP_HOME with mode 0444, and bind-mounts
// it read-only into the container. The file is removed with its container.
//
// Owner: unit w-route. These declarations are the contract other units call;
// the bodies are stubs until w-route lands.

import (
	"errors"

	"github.com/urnetwork/warp/services"
)

// One lb interface of the host as the worker sees it when it starts a connect
// generation: its name, whether lb_alt is effective on it (informational for
// connect), and its docker network's bridge addresses. An empty address means
// the family is absent.
type lbAltRouteInterfaceInput struct {
	name  string
	lbAlt bool
	ipv4  string
	ipv6  string
}

// What a worker knows when it starts a connect generation on an lb_alt host.
type lbAltRouteInputs struct {
	// versions[0] of this is what is rendered
	servicesConfig *services.ServicesConfig
	env            string
	host           string
	// the container name of the generation, also its generation id
	generation string
	// every non-transparent lb interface on the host, as --lbaltnets lists them
	interfaces []lbAltRouteInterfaceInput
	// this generation's WARP_PORTS: service port -> internal port
	servicePorts map[int]int
	// the warpservices bridge address the upstream blocks listen on
	upstreamIpv4 string
}

// Renders the generation's route table. It fails, and the generation does not
// start, if any input is missing or the table would not validate on the server.
func renderLbAltRouteTable(inputs *lbAltRouteInputs) (*LbAltRouteTable, error) {
	return nil, errors.New("lbalt: route rendering not implemented")
}

// Writes the encoded table to <warpHome>/lbalt/<containerName>/route.json with
// mode 0444, never over an existing file, and returns the host path and the
// revision (lowercase hex sha256 of the bytes written).
func writeLbAltRouteFile(warpHome string, containerName string, table *LbAltRouteTable) (hostPath string, revision string, err error) {
	return "", "", errors.New("lbalt: route file writing not implemented")
}

// Removes <warpHome>/lbalt/<containerName>/, once the container is gone.
func removeLbAltRouteFile(warpHome string, containerName string) error {
	return errors.New("lbalt: route file removal not implemented")
}
