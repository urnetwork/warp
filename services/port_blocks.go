package services

// warp's port allocation (README.md's services.yml RULES), as a function of a services config alone,
// so warpctl and the commands outside it that check a services.yml (sidecarctl's services
// apply-fragment) run the one allocator. warpctl's getPortBlocks is this, read from its vault.

import (
	"fmt"
	"slices"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp"
)

// One port of one block: the lb's, per host, or a service's, for every host the service runs on (host
// ""). The external port is what the lb or the host's dnat exposes, and the internal ports are the
// container's, one per parallel block slot.
type PortBlock struct {
	Service           string
	Block             string
	Port              int
	ExternalPort      int
	ExternalPortTypes map[string]bool
	// port type -> lb type
	LbTypes       map[string]string
	InternalPorts []int
	RoutingTable  int
	// the index of the version that last assigned it; 0, the latest, for every block the latest
	// version still names
	Version int
}

// Whether this is the given block's port.
func (self *PortBlock) eq(service string, block string, port int) bool {
	return self.Service == service && self.Block == block && self.Port == port
}

// Assigns every block's ports by replaying the versions oldest first, so a port once assigned to a
// service block keeps it (README.md's RULES): host -> service -> block -> port -> block, where a
// service's blocks are under host "". Each assignment is logged through logf. The lb blocks' stream
// port services take their lb's defaults, which changes servicesConfig's lb blocks as warpctl always
// has. A config the rules cannot place, such as an exhausted range or two blocks on one port, is an
// error.
func AllocatePortBlocks(
	servicesConfig *ServicesConfig,
	logf func(format string, a ...any),
) (hostPortBlocks map[string]map[string]map[string]map[int]*PortBlock, returnErr error) {
	// the rules below panic where a config breaks them, as warpctl always has
	defer func() {
		if r := recover(); r != nil {
			hostPortBlocks = nil
			if err, ok := r.(error); ok {
				returnErr = err
			} else {
				returnErr = fmt.Errorf("%v", r)
			}
		}
	}()
	/*
	   RULES:
	   1. Once an internal port is associated to a service-block, it can never be associated to another service-block.
	   2. Each service-block-<serviceport> has a fixed external port that will never change.
	      If the port is removed from the exteral ports list, that is a config error.
	   3. An lb-block has a fixed routing table that will never change
	   4. An internal port can't use a port ever used by as an external; and vice-versa
	*/

	hostPortBlocks = map[string]map[string]map[string]map[int]*PortBlock{}
	hostAssignedExternalPorts := map[string]map[int]*PortBlock{}
	hostAssignedInternalPorts := map[string]map[int]*PortBlock{}
	hostAssignedLbRoutingTables := map[string]map[int]string{}

	// portBlocks := func(host string) map[string]map[string]map[int]*PortBlock {
	//  b, ok := hostPortBlocks[host]
	//  if !ok {
	//      b = map[string]map[string]map[int]*PortBlock{}
	//      hostPortBlocks[host] = b
	//  }
	//  return b
	// }
	assignedExternalPorts := func(host string) map[int]*PortBlock {
		b := map[int]*PortBlock{}
		for existingHost, existingB := range hostAssignedExternalPorts {
			if host == "" || existingHost == host || existingHost == "" {
				maps.Copy(b, existingB)
			}
		}
		return b
	}
	assignedInternalPorts := func(host string) map[int]*PortBlock {
		b := map[int]*PortBlock{}
		for existingHost, existingB := range hostAssignedInternalPorts {
			if host == "" || existingHost == host || existingHost == "" {
				maps.Copy(b, existingB)
			}
		}
		return b
	}
	assignedLbRoutingTables := func(host string) map[int]string {
		b := map[int]string{}
		if assigned, ok := hostAssignedLbRoutingTables[host]; ok {
			maps.Copy(b, assigned)
		}
		return b
	}

	setExternalPort := func(host string, port int, portBlock *PortBlock) {
		b, ok := hostAssignedExternalPorts[host]
		if !ok {
			b = map[int]*PortBlock{}
			hostAssignedExternalPorts[host] = b
		}
		for existingHost, existingB := range hostAssignedExternalPorts {
			if host == "" || existingHost == host || existingHost == "" {
				if existingPortBlock, ok := existingB[port]; ok && existingPortBlock != portBlock {
					panic("Cannot overwrite external port")
				}
			}
		}
		b[port] = portBlock
	}
	setInternalPort := func(host string, port int, portBlock *PortBlock) {
		b, ok := hostAssignedInternalPorts[host]
		if !ok {
			b = map[int]*PortBlock{}
			hostAssignedInternalPorts[host] = b
		}
		for existingHost, existingB := range hostAssignedInternalPorts {
			if host == "" || existingHost == host || existingHost == "" {
				if existingPortBlock, ok := existingB[port]; ok && existingPortBlock != portBlock {
					panic("Cannot overwrite internal port")
				}
			}
		}
		b[port] = portBlock
	}
	setLbRoutingTable := func(host string, rt int, block string) {
		b, ok := hostAssignedLbRoutingTables[host]
		if !ok {
			b = map[int]string{}
			hostAssignedLbRoutingTables[host] = b
		}
		if existingBlock, ok := b[rt]; ok && existingBlock != block {
			panic("Cannot overwrite rt")
		}
		b[rt] = block
	}

	assignPortBlock := func(host string, service string, block string, port int) *PortBlock {
		logf("Assign port block %s %s %d\n", service, block, port)
		// portBlocks := portBlocks(host)
		portBlocks, ok := hostPortBlocks[host]
		if !ok {
			portBlocks = map[string]map[string]map[int]*PortBlock{}
			hostPortBlocks[host] = portBlocks
		}

		if portBlock, ok := portBlocks[service][block][port]; ok {
			return portBlock
		}
		portBlock := &PortBlock{
			Service:           service,
			Block:             block,
			Port:              port,
			ExternalPortTypes: map[string]bool{},
			LbTypes:           map[string]string{},
		}
		if _, ok := portBlocks[service]; !ok {
			portBlocks[service] = map[string]map[int]*PortBlock{}
		}
		if _, ok := portBlocks[service][block]; !ok {
			portBlocks[service][block] = map[int]*PortBlock{}
		}
		portBlocks[service][block][port] = portBlock
		return portBlock
	}

	assignExternalPort := func(
		host string,
		service string,
		block string,
		port int,
		externalPorts []int,
		force map[int]int,
		externalPortType string,
		lbType string,
		version int,
	) {
		portBlock := assignPortBlock(host, service, block, port)
		assignedExternalPorts := assignedExternalPorts(host)
		assignedInternalPorts := assignedInternalPorts(host)

		p := portBlock.ExternalPort
		if 0 < p {
			// verify consistent state
			assignedPortBlock, ok := assignedExternalPorts[p]
			if !ok {
				panic(fmt.Errorf("Port block must be assigned (%s %s %d)", service, block, port))
			}
			if !assignedPortBlock.eq(service, block, port) {
				panic(fmt.Errorf("Port block does not match (%s %s %d) <> (%s %s %d)", assignedPortBlock.Service, assignedPortBlock.Block, assignedPortBlock.Port, service, block, port))
			}
		} else {
			p = func() int {
				orderedForcePorts := maps.Keys(force)
				slices.Sort(orderedForcePorts)
				for _, p := range orderedForcePorts {
					servicePort := force[p]
					if port == servicePort {
						// fmt.Printf("FORCE\n")
						return p
					}
				}

				// find an already assigned port
				// for _, p := range externalPorts {
				//  if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
				//      if assignedPortBlock.eq(service, block, port) {
				//          fmt.Printf("ASSIGNED\n")
				//          return p
				//      }
				//  }
				// }

				// find a free port
				for _, p := range externalPorts {
					if _, ok := assignedExternalPorts[p]; !ok {
						if _, ok := assignedInternalPorts[p]; !ok {
							// fmt.Printf("FREE\n")
							return p
						}
					}
				}

				panic("No more external ports to assign. Increase the external port range.")
			}()
		}

		// if portBlock.ExternalPort != 0 && portBlock.ExternalPort != p {
		//  panic(fmt.Errorf("The external port of a port block cannot change (%d: %d <> %d %v)", port, portBlock.ExternalPort, p, assignedExternalPorts))
		// }
		//
		// if portBlock.externalPortType != "" && portBlock.externalPortType != externalPortType {
		//  panic("The external port type of a port block cannot change.")
		// }

		if portBlock.LbTypes[externalPortType] != "" && portBlock.LbTypes[externalPortType] != lbType {
			panic("The lb type of a port block cannot change.")
		}

		// if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
		//  if !assignedPortBlock.eq(service, block, port) {
		//      panic("Cannot overwrite the external port of another port block.")
		//  }
		// }
		// if _, ok := assignedInternalPorts[p]; ok {
		//  panic("Cannot use an internal port as an external port.")
		// }

		setExternalPort(host, p, portBlock)
		portBlock.ExternalPort = p
		portBlock.ExternalPortTypes[externalPortType] = true
		portBlock.LbTypes[externalPortType] = lbType
		portBlock.Version = version

		logf("Assigned external port %s %s %d -> %d\n", service, block, port, p)
	}
	assignInternalPorts := func(
		host string,
		service string,
		block string,
		port int,
		internalPorts []int,
		count int,
		version int,
	) {
		portBlock := assignPortBlock(host, service, block, port)
		assignedExternalPorts := assignedExternalPorts(host)
		assignedInternalPorts := assignedInternalPorts(host)

		ps := []int{}

		// verify consistent state
		for _, p := range portBlock.InternalPorts {
			assignedPortBlock, ok := assignedInternalPorts[p]
			if !ok {
				panic(fmt.Errorf("Port block must be assigned (%s %s %d)", service, block, port))
			}
			if !assignedPortBlock.eq(service, block, port) {
				panic(fmt.Errorf("Port block does not match (%s %s %d) <> (%s %s %d)", assignedPortBlock.Service, assignedPortBlock.Block, assignedPortBlock.Port, service, block, port))
			}
		}

		// find already assigned ports
		for _, p := range internalPorts {
			if count <= len(ps) {
				break
			}
			if assignedPortBlock, ok := assignedInternalPorts[p]; ok {
				if assignedPortBlock.eq(service, block, port) {
					ps = append(ps, p)
				}
			}
		}

		// find free ports
		for _, p := range internalPorts {
			if count <= len(ps) {
				break
			}
			if _, ok := assignedExternalPorts[p]; !ok {
				if _, ok := assignedInternalPorts[p]; !ok {
					ps = append(ps, p)
				}
			}
		}

		if len(ps) < count {
			panic("No more internal ports to assign. Increase the internal port range.")
		}

		for _, p := range ps {
			setInternalPort(host, p, portBlock)
			logf("Assigned internal port %s %s %d -> %d\n", service, block, port, p)
		}
		portBlock.InternalPorts = ps
		portBlock.Version = version
	}
	assignLbRoutingTable := func(
		host string,
		block string,
		routingTables []int,
	) {
		assignedLbRoutingTables := assignedLbRoutingTables(host)

		// find an already routing table
		for _, rt := range routingTables {
			if assignedBlock, ok := assignedLbRoutingTables[rt]; ok {
				if assignedBlock == block {
					return
				}
			}
		}

		rt := func() int {
			// find a free routing table
			for _, rt := range routingTables {
				if _, ok := assignedLbRoutingTables[rt]; !ok {
					return rt
				}
			}

			panic("No more routing tables to assign. Increase the routing table range.")
		}()

		// search all the routing tables
		// for assignedRt, assignedBlock := range assignedLbRoutingTables {
		//  if assignedBlock == block {
		//      if assignedRt != rt {
		//          panic("The routing table of a block cannot change.")
		//      }
		//  }
		// }

		setLbRoutingTable(host, rt, block)
	}

	// interate versions from last to first
	for version := len(servicesConfig.Versions) - 1; 0 <= version; version -= 1 {
		serviceConfigVersion := servicesConfig.Versions[version]
		externalPorts, err := warp.ExpandAnyPorts(serviceConfigVersion.ExternalPorts)
		if err != nil {
			panic(err)
		}
		internalPorts, err := warp.ExpandAnyPorts(serviceConfigVersion.InternalPorts)
		if err != nil {
			panic(err)
		}
		routingTables, err := warp.ExpandAnyPorts(serviceConfigVersion.RoutingTables)
		if err != nil {
			panic(err)
		}

		slices.Sort(externalPorts)
		slices.Sort(internalPorts)
		slices.Sort(routingTables)

		// iteration for port assignment must have a stable order
		// when iterating map keys always sort the keys and iterate the sorted keys

		lbConfig := serviceConfigVersion.Lb
		// process forced external ports first
		for _, includeForcedExternalPorts := range []bool{true, false} {
			orderedHosts := maps.Keys(lbConfig.Interfaces)
			sort.Strings(orderedHosts)
			for _, host := range orderedHosts {
				lbBlocks := lbConfig.Interfaces[host]
				orderedInterfaceNames := maps.Keys(lbBlocks)
				sort.Strings(orderedInterfaceNames)
				for _, interfaceName := range orderedInterfaceNames {
					lbBlock := lbBlocks[interfaceName]

					// merge the port services from the lb config to the lb block
					lbBlock.SetDefaultStreamPortServices(&lbConfig.StreamPortServiceConfig)

					hasForcedExternalPorts := 0 < len(lbBlock.ExternalPorts)
					if hasForcedExternalPorts != includeForcedExternalPorts {
						continue
					}

					block := fmt.Sprintf("%s-%s", host, interfaceName)

					assignLbRoutingTable(
						host,
						block,
						routingTables,
					)

					lbTypeAllPorts := map[string]map[string][]int{}
					lbTypeAllPorts["http"] = lbConfig.AllHttpPorts()
					// merge the ports and service ports
					mergedStreamPorts := lbConfig.AllStreamPorts()
					for portType, portServices := range lbBlock.AllPortServices() {
						for port, _ := range portServices {
							if !slices.Contains(mergedStreamPorts[portType], port) {
								mergedStreamPorts[portType] = append(mergedStreamPorts[portType], port)
							}
						}
					}
					lbTypeAllPorts["stream"] = mergedStreamPorts

					orderedLbTypes := maps.Keys(lbTypeAllPorts)
					slices.Sort(orderedLbTypes)

					for _, lbType := range orderedLbTypes {
						allPorts := lbTypeAllPorts[lbType]

						orderedPortTypes := maps.Keys(allPorts)
						slices.Sort(orderedPortTypes)

						for _, portType := range orderedPortTypes {
							orderedPorts := allPorts[portType]
							slices.Sort(orderedPorts)

							logf(
								"Assigning %s ports %s %v (%v)\n",
								lbType,
								portType,
								orderedPorts,
								lbBlock.ExternalPorts,
							)
							for _, port := range orderedPorts {
								assignExternalPort(
									host,
									"lb",
									block,
									port,
									externalPorts,
									lbBlock.ExternalPorts,
									portType,
									lbType,
									version,
								)
								assignInternalPorts(
									host,
									"lb",
									block,
									port,
									internalPorts,
									serviceConfigVersion.ParallelBlockCount,
									version,
								)
							}
						}
					}
				}
			}
		}

		// join back the lb routing tables
		for host, assignedLbRoutingTables := range hostAssignedLbRoutingTables {
			for routingTable, block := range assignedLbRoutingTables {
				for _, portBlock := range hostPortBlocks[host]["lb"][block] {
					portBlock.RoutingTable = routingTable
				}
			}
		}

		orderedServices := maps.Keys(serviceConfigVersion.Services)
		sort.Strings(orderedServices)
		for _, service := range orderedServices {
			serviceConfig := serviceConfigVersion.Services[service]
			for _, blockWeights := range serviceConfig.Blocks {
				orderedBlocks := maps.Keys(blockWeights)
				slices.Sort(orderedBlocks)

				for _, block := range orderedBlocks {
					allHttpPorts := serviceConfig.AllHttpPorts()
					orderedHttpPortTypes := maps.Keys(allHttpPorts)
					slices.Sort(orderedHttpPortTypes)

					for _, portType := range orderedHttpPortTypes {
						orderedPorts := allHttpPorts[portType]
						slices.Sort(orderedPorts)

						for _, port := range orderedPorts {
							assignExternalPort(
								"",
								service,
								block,
								port,
								externalPorts,
								map[int]int{},
								portType,
								"http",
								version,
							)
							assignInternalPorts(
								"",
								service,
								block,
								port,
								internalPorts,
								serviceConfigVersion.ParallelBlockCount,
								version,
							)
						}
					}

					allStreamPorts := serviceConfig.AllStreamPorts()
					orderedStreamPortTypes := maps.Keys(allStreamPorts)
					slices.Sort(orderedStreamPortTypes)

					for _, portType := range orderedStreamPortTypes {
						orderedPorts := allStreamPorts[portType]
						slices.Sort(orderedPorts)

						for _, port := range orderedPorts {
							assignExternalPort(
								"",
								service,
								block,
								port,
								externalPorts,
								map[int]int{},
								portType,
								"stream",
								version,
							)
							assignInternalPorts(
								"",
								service,
								block,
								port,
								internalPorts,
								serviceConfigVersion.ParallelBlockCount,
								version,
							)
						}
					}

					// a public port the service owns on its pinned hosts allocates
					// exactly like an lb-fronted port, so the container finds it in
					// WARP_PORTS and binds only the allocated port. The "external"
					// lb type keeps it out of the http and stream nginx blocks: the
					// block's own interface dnat publishes it, not the lb.
					allExternalPorts := serviceConfig.AllExternalPorts()
					orderedExternalPortTypes := maps.Keys(allExternalPorts)
					slices.Sort(orderedExternalPortTypes)

					for _, portType := range orderedExternalPortTypes {
						orderedPorts := allExternalPorts[portType]
						slices.Sort(orderedPorts)

						for _, port := range orderedPorts {
							assignExternalPort(
								"",
								service,
								block,
								port,
								externalPorts,
								map[int]int{},
								portType,
								"external",
								version,
							)
							assignInternalPorts(
								"",
								service,
								block,
								port,
								internalPorts,
								serviceConfigVersion.ParallelBlockCount,
								version,
							)
						}
					}
				}
			}
		}
	}

	// removed blocks not used in the latest version
	for _, serviceBlockPortBlocks := range hostPortBlocks {
		for _, blockPortBlocks := range serviceBlockPortBlocks {
			for _, portBlocks := range blockPortBlocks {
				for port, portBlock := range portBlocks {
					if portBlock.Version != 0 {
						delete(portBlocks, port)
					}
				}
			}
		}
	}

	// validate no overlapping ports
	for _, serviceBlockPortBlocks := range hostPortBlocks {
		portServiceBlocks := map[int]string{}
		validate := func(serviceBlock string, port int) {
			conflictServiceBlock, ok := portServiceBlocks[port]
			if ok {
				panic(fmt.Errorf("Port %d assigned to both %s and %s", port, conflictServiceBlock, serviceBlock))
			}
			portServiceBlocks[port] = serviceBlock
		}

		for service, blockPortBlocks := range serviceBlockPortBlocks {
			for block, portBlocks := range blockPortBlocks {
				serviceBlock := fmt.Sprintf("%s-%s", service, block)
				for _, portBlock := range portBlocks {
					validate(serviceBlock, portBlock.ExternalPort)
					for _, port := range portBlock.InternalPorts {
						validate(serviceBlock, port)
					}
				}
			}
		}
	}

	return hostPortBlocks, nil
}
