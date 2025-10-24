package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	// "os/signal"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/warpctl/dynamo"
	"golang.org/x/exp/maps"

	"github.com/coreos/go-semver/semver"
)

// run supports two network configurations:
// 1. hostNetworking=false
//    This is the old default, where each container has a unique ipv4, and
//    docker runs a `docker-proxy` process that listens on 0.0.0.0/::
//    and translates "external" ports (on the host) to "internal" ports (on the container).
//    A typical packet flow involves user -> lb -> connect -> connect exchange -> lb -> provider,
//    and each arrow is an instance of `docker-proxy` doing packet translation (5 for a typical flow).
// 2. hostNetworking=true
//    This is the new default. In this mode, all containers share the same IP (the docker network IP for the container),
//    and sockets inside the docker container bind directly to the host network.
//    Because the sockets bind to a specific IP instead of 0.0.0.0/::,
//    DNAT is used to translate packets to the destination port to the specific IP:destination port.
//    This configuration uses the kernel/iptables and hence does not involve user space copying of the packets,
//    which results in lower overall latency.

const WarpPollTimeout = 5 * time.Second
const KillTimeout = 15 * time.Second
const DrainTimeout = 60 * time.Minute
const NewContainerPollTimeout = 120 * time.Second

const (
	MOUNT_MODE_NO   = "no"
	MOUNT_MODE_YES  = "yes"
	MOUNT_MODE_ROOT = "root"
)

const (
	STATUS_MODE_NO       = "no"
	STATUS_MODE_STANDARD = "standard"
)

type RunWorker struct {
	warpState    *WarpState
	dynamoClient *dynamo.Client

	env                   string
	service               string
	block                 string
	portBlocks            *PortBlocks
	servicesDockerNetwork *DockerNetwork
	routingTable          *RoutingTable
	dockerNetwork         *DockerNetwork
	domain                string
	runArgs               []string

	vaultMountMode  string
	configMountMode string
	siteMountMode   string

	statusMode   string
	statusPrefix string

	hostNetworking bool

	envVars map[string]string

	deployedVersion       *semver.Version
	deployedConfigVersion *semver.Version

	quitEvent *warp.Event
}

func (self *RunWorker) Run() {
	// on start, deploy the latest version and start the watcher loop

	self.quitEvent = warp.NewEvent()

	closeFn := self.quitEvent.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer closeFn()

	announceRunEnter()
	defer announceRunExit()

	initNetwork := func() {
		// enable policy routing
		self.initRoutingTable()
		self.initBlockRedirect()
	}

	initNetwork()

	self.deployedVersion = nil
	self.deployedConfigVersion = nil

	// watch for new versions until killed
	for !self.quitEvent.IsSet() {
		latestVersion, latestConfigVersion, err := self.getLatestVersion()

		var deployable bool

		if err != nil {
			Err.Printf("Polled latest version error: %s\n", err)
			deployable = false
		} else {
			Err.Printf("Polled latest versions: %s, %s\n", latestVersion, latestConfigVersion)
			deployable = func() bool {
				switch self.configMountMode {
				case MOUNT_MODE_NO, MOUNT_MODE_ROOT:
					// the config version is not needed
					if latestVersion == nil {
						return false
					}
					if self.deployedVersion == nil || *self.deployedVersion != *latestVersion {
						return true
					}
				default:
					if latestVersion == nil {
						return false
					}
					if latestConfigVersion == nil {
						return false
					}
					if self.deployedVersion == nil || *self.deployedVersion != *latestVersion {
						return true
					}
					if self.deployedConfigVersion == nil || *self.deployedConfigVersion != *latestConfigVersion {
						return true
					}
				}
				if self.hasDaemon() {
					containerIds, err := self.findServiceBlockContainersWithVersion(self.deployedVersion)
					if err != nil {
						Err.Printf("Could not poll running service block container, err = %s\n", err)
						return false
					}
					// deploy if the container is not running
					return len(containerIds) == 0
				}
				return false
			}()
		}

		if deployable {
			// deploy new version
			previousVersion := self.deployedVersion
			previousConfigVersion := self.deployedConfigVersion
			self.deployedVersion = latestVersion
			self.deployedConfigVersion = latestConfigVersion

			Err.Printf("Deploy version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
			success := func() bool {
				announceRunStart()
				// do not recover() errors from `deploy()`
				// the expected behavior on error is to exit the run worker
				// the control launcher should restart the run worker
				err := self.deploy()
				if err != nil {
					Err.Printf("Deploy fail version=%s, configVersion=%s: %s\n", self.deployedVersion, self.deployedConfigVersion, err)
					announceRunFail()
					// at this point, the previous version is still running
					return false
				} else {
					Err.Printf("Deploy success version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
					announceRunSuccess()
					return true
				}
			}()
			if !success {
				self.deployedVersion = previousVersion
				self.deployedConfigVersion = previousConfigVersion
			}
			// else try to deploy again

			// prune stopped containers
			// this may not catch the draining containers from this epoch
			// it runs after each deploy to bound the number of stopped containers
			self.prune()
		} else if latestVersion == nil {
			announceRunWaitForVersion()
		} else if latestConfigVersion == nil {
			announceRunWaitForConfig()
		}

		self.quitEvent.WaitForSet(WarpPollTimeout)
	}

	Err.Printf("Run worker stop.")
}

func (self *RunWorker) hasDaemon() bool {
	switch self.service {
	case "config-updater":
		return false
	default:
		return true
	}
}

// service version, config version
func (self *RunWorker) getLatestVersion() (latestVersion *semver.Version, latestConfigVersion *semver.Version, returnErr error) {

	v, err := self.dynamoClient.GetLatestVersion(context.Background(), self.env, self.service, self.block)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get latest version: %w", err)
	}

	Err.Printf("Latest version (%s, %s, %s) = %s\n", self.env, self.service, self.block, v)

	latestVersion, err = semver.NewVersion(v)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse latest version: %w", err)
	}

	entries, err := os.ReadDir(self.warpState.warpSettings.RequireConfigHome())
	if err != nil {
		returnErr = err
		return
	}

	configVersions := []semver.Version{}
	for _, entry := range entries {
		if entry.IsDir() {
			if version, err := semver.NewVersion(entry.Name()); err == nil {
				configVersions = append(configVersions, *version)
			}
		}
	}
	semverSortWithBuild(configVersions)

	if 0 < len(configVersions) {
		latestConfigVersion = &configVersions[len(configVersions)-1]
	} else {
		latestConfigVersion = nil
	}

	return
}

func (self *RunWorker) findServiceBlockContainersWithVersion(version *semver.Version) ([]string, error) {
	containerNamePattern := fmt.Sprintf(
		"%s-%s-%s-%s-*",
		self.env,
		self.service,
		self.block,
		convertVersionToDocker(version.String()),
	)

	psCmd := docker(
		"ps",
		"-f", fmt.Sprintf("name=%s", containerNamePattern),
		"--format", "{{.ID}}",
	)
	out, err := psCmd.Output()
	if err != nil {
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		return nil, nil
	}

	containerIds := []string{}
	for _, containerIdStr := range strings.Split(outStr, "\n") {
		containerId := strings.TrimSpace(containerIdStr)
		containerIds = append(containerIds, containerId)
	}

	return containerIds, nil
}

func (self *RunWorker) findServiceBlockContainers() ([]string, error) {
	containerNamePattern := fmt.Sprintf(
		"%s-%s-%s-*",
		self.env,
		self.service,
		self.block,
	)

	psCmd := docker(
		"ps",
		"-f", fmt.Sprintf("name=%s", containerNamePattern),
		"--format", "{{.ID}}",
	)
	out, err := psCmd.Output()
	if err != nil {
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		return nil, nil
	}

	containerIds := []string{}
	for _, containerIdStr := range strings.Split(outStr, "\n") {
		containerId := strings.TrimSpace(containerIdStr)
		containerIds = append(containerIds, containerId)
	}

	return containerIds, nil
}

func (self *RunWorker) getNetworkConfigs() []*NetworkConfig {
	var dockerNetwork *DockerNetwork
	if self.dockerNetwork != nil {
		dockerNetwork = self.dockerNetwork
	} else {
		dockerNetwork = self.servicesDockerNetwork
	}
	return getNetworkConfigs(self.routingTable, dockerNetwork)
}

func (self *RunWorker) initRoutingTable() {
	// ** important: restarting warpctl should not interrupt running services **
	// this does not remove routes/tables or rules to avoid interrupting running services
	// instead missing rules are added

	if self.routingTable == nil {
		return
	}

	tableNumberStr := strconv.Itoa(self.routingTable.tableNumber)

	// services is always via ipv4
	// lb listens to incoming on both ipv4 and ipv6

	runAndLog(sudo(
		"ip", "route", "replace", self.servicesDockerNetwork.ipv4.interfaceSubnet,
		"dev", self.servicesDockerNetwork.ipv4.interfaceName,
		"src", self.servicesDockerNetwork.ipv4.interfaceIp,
		"table", tableNumberStr,
	))

	for _, networkConfig := range self.getNetworkConfigs() {
		if networkConfig.routingTable == nil || networkConfig.dockerNetwork == nil {
			continue
		}

		// ip route list table <table>
		runAndLog(sudo2(
			networkConfig.ipCommand, "route", "replace", networkConfig.routingTable.interfaceSubnet,
			"dev", networkConfig.routingTable.interfaceName,
			"src", networkConfig.routingTable.interfaceIp,
			"table", tableNumberStr,
		))
		runAndLog(sudo2(
			networkConfig.ipCommand, "route", "replace", networkConfig.dockerNetwork.interfaceSubnet,
			"dev", networkConfig.dockerNetwork.interfaceName,
			"src", networkConfig.dockerNetwork.interfaceIp,
			"table", tableNumberStr,
		))
		runAndLog(sudo2(
			networkConfig.ipCommand, "route", "add", "default",
			"via", networkConfig.routingTable.interfaceGateway,
			"dev", networkConfig.routingTable.interfaceName,
			"table", tableNumberStr,
		))

		// add a masq for the interface
		// this is not needed for ipv4 if there is a gateway router applying a masq, but do it anyway
		masqCmd := func(op string) *exec.Cmd {
			cmd := sudo2(
				networkConfig.iptablesCommand, "-t", "nat", op, "POSTROUTING",
				"-o", networkConfig.routingTable.interfaceName,
				"-j", "MASQUERADE",
			)
			return cmd
		}
		if err := runAndLog(masqCmd("-C")); err != nil {
			if err := runAndLog(masqCmd("-A")); err != nil {
				panic(err)
			}
		}

		// ip rule list table <table>
		/*
		   32737:  from 172.19.0.0/16 lookup warp1
		   32738:  from 192.168.208.1 lookup warp1
		   32739:  from 172.19.0.0/16 lookup warp1
		   32740:  from 192.168.208.1 lookup warp1
		*/
		ipRuleFromLookups := map[string]string{}
		if out, err := sudo2(
			networkConfig.ipCommand, "rule", "list", "table", tableNumberStr,
		).Output(); err == nil {
			ruleRegex := regexp.MustCompile("^\\s*.*\\s+from\\s+(\\S+)\\s+lookup\\s+(\\S+)\\s*$")
			for _, line := range strings.Split(string(out), "\n") {
				if groups := ruleRegex.FindStringSubmatch(line); groups != nil {
					from := groups[1]
					// `ip rule list table X` shows lookup table names not numbers
					tableName := groups[2]
					ipRuleFromLookups[from] = tableName
				}
			}
		}

		// lookup to the table for packets from these sources:
		// - interface ip (sockets bound to the interface)
		// - docker interface subnet (sockets in docker containers in the network)
		for _, from := range []string{
			networkConfig.routingTable.interfaceIp,
			networkConfig.dockerNetwork.interfaceSubnet,
		} {
			if tableName, ok := ipRuleFromLookups[from]; !ok || tableName != self.routingTable.tableName {
				runAndLog(sudo2(
					networkConfig.ipCommand, "rule", "add",
					"from", from,
					"table", tableNumberStr,
				))
			}
		}
	}
}

func (self *RunWorker) iptablesChainName() string {
	// iptables target names are 28 chars max
	maxLen := 28

	maxServiceLen := 10
	var shortService string
	if len(self.service) <= maxServiceLen {
		shortService = self.service
	} else if parts := strings.Split(self.service, "-"); 1 < len(parts) && len(parts) <= maxServiceLen/2 {
		firstLetters := []string{}
		for _, part := range parts {
			if 0 < len(part) {
				firstLetters = append(firstLetters, part[:1])
			} else {
				firstLetters = append(firstLetters, "")
			}
		}
		shortService = strings.Join(firstLetters, "-")
	} else {
		shortService = self.service[:maxServiceLen]
	}

	var shortBlock string
	if self.service == "lb" {
		// use the interface name which is locally unique
		parts := strings.Split(self.block, "-")
		shortBlock = parts[len(parts)-1]
	} else {
		shortBlock = self.block
	}

	chainName := fmt.Sprintf(
		"WARP-%s-%s-%s",
		strings.ToUpper(self.env),
		strings.ToUpper(shortService),
		strings.ToUpper(shortBlock),
	)
	if maxLen < len(chainName) {
		panic(fmt.Sprintf("iptables chain name cannot exceed %d chars", maxLen))
	}
	return chainName
}

func (self *RunWorker) initBlockRedirect() {
	// ** important: restarting warpctl should not interrupt running services **
	// add rules if they do not already exists

	chainName := self.iptablesChainName()

	for _, networkConfig := range self.getNetworkConfigs() {
		// ignore errors
		runAndLog(sudo2(
			networkConfig.iptablesCommand, "-t", "nat", "-N", chainName,
		))

		chainCmd := func(op string, entryChainName string) *exec.Cmd {
			cmd := sudo2(
				networkConfig.iptablesCommand, "-t", "nat", op, entryChainName,
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", chainName,
			)
			return cmd
		}

		// apply chain to external traffic to local
		// do not add if already exists
		if err := runAndLog(chainCmd("-C", "PREROUTING")); err != nil {
			if err := runAndLog(chainCmd("-I", "PREROUTING")); err != nil {
				panic(err)
			}
		}

		// apply chain to local traffic to local
		// do not add if already exists
		if err := runAndLog(chainCmd("-C", "OUTPUT")); err != nil {
			if err := runAndLog(chainCmd("-I", "OUTPUT")); err != nil {
				panic(err)
			}
		}
	}
}

func (self *RunWorker) deploy() error {
	externalPortsToInternalPort, servicePortsToInternalPort := self.assignDeployPorts()
	Err.Printf(
		"Ports %s, %s\n",
		mapStr(externalPortsToInternalPort),
		mapStr(servicePortsToInternalPort),
	)

	deployedContainerId, err := self.startContainer(servicePortsToInternalPort)
	success := false
	defer func() {
		if !success && deployedContainerId != "" {
			go NewKillWorker(deployedContainerId).Run()
		}
	}()
	if err != nil {
		Err.Printf("Start container failed: %s\n", err)
		return err
	}

	if err := self.pollContainerStatus(servicePortsToInternalPort, NewContainerPollTimeout); err != nil {
		return err
	}

	self.redirect(externalPortsToInternalPort, servicePortsToInternalPort, deployedContainerId)

	if self.hostNetworking {
		runningContainers, err := self.findServiceBlockContainers()
		if err != nil {
			return err
		}

		Err.Printf("Found overlapping containers (%s) %s\n", deployedContainerId, strings.Join(runningContainers, ", "))
		for _, containerId := range runningContainers {
			if !containerIdsEqual(containerId, deployedContainerId) {
				go NewDrainWorker(containerId).Run()
			}
		}
	} else {
		runningContainers, err := self.findRunningContainers()
		if err != nil {
			return err
		}

		// verify the internal ports
		for _, internalPort := range servicePortsToInternalPort {
			if containerId, ok := runningContainers[internalPort]; !ok || !containerIdsEqual(deployedContainerId, containerId) {
				return errors.New(fmt.Sprintf("Container is not listening on internal port %d", internalPort))
			}
		}

		// container_ids that overlap the owned ports
		containerIds := map[string]bool{}
		for _, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if containerId, ok := runningContainers[internalPort]; ok {
					containerIds[containerId] = true
				}
			}
		}
		Err.Printf("Found overlapping containers (%s) %s\n", deployedContainerId, strings.Join(maps.Keys(containerIds), ", "))
		for containerId, _ := range containerIds {
			if !containerIdsEqual(containerId, deployedContainerId) {
				go NewDrainWorker(containerId).Run()
			}
		}
	}

	success = true
	return nil
}

func (self *RunWorker) assignDeployPorts() (map[int]int, map[int]int) {
	for !self.quitEvent.IsSet() {
		externalPortsToInternalPort := map[int]int{}

		occupiedPorts, err := self.findOccupiedPorts()
		if err != nil {
			panic(err)
		}
		for internalPort, _ := range occupiedPorts {
			Err.Printf("Found occupied port: %d\n", internalPort)
		}
		for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if !occupiedPorts[internalPort] {
					externalPortsToInternalPort[externalPort] = internalPort
					break
				}
			}
		}

		if len(externalPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
			self.quitEvent.WaitForSet(WarpPollTimeout)
		} else {
			servicePortsToInternalPort := map[int]int{}
			for externalPort, servicePort := range self.portBlocks.externalsToService {
				internalPort := externalPortsToInternalPort[externalPort]
				servicePortsToInternalPort[servicePort] = internalPort
			}

			return externalPortsToInternalPort, servicePortsToInternalPort
		}
	}
	panic("Could not allocate ports.")
}

func (self *RunWorker) findOccupiedPorts() (map[int]bool, error) {
	occupiedPorts := map[int]bool{}
	if self.hostNetworking {
		// note `-p` will show the pid
		out, err := outAndLog(sudo("netstat", "-tuln"))
		if err != nil {
			return nil, err
		}
		/*
					Active Internet connections (only servers)
			Proto Recv-Q Send-Q Local Address           Foreign Address         State
			tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
			tcp        0      0 172.19.0.1:8948         0.0.0.0:*               LISTEN
			tcp        0      0 172.19.0.1:8918         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:8438         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:8408         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7808         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7838         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7718         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7688         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7778         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7748         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7598         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7568         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7658         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7628         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7478         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7441         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7538         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7508         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7351         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7321         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7411         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7381         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7201         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7231         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7291         0.0.0.0:*               LISTEN
			tcp        0      0 172.18.0.1:7261         0.0.0.0:*               LISTEN
			tcp        0      0 172.20.0.1:8828         0.0.0.0:*               LISTEN
			tcp        0      0 172.20.0.1:8858         0.0.0.0:*               LISTEN
			tcp6       0      0 :::22                   :::*                    LISTEN
			tcp6       0      0 fd00:e53d:b0b7:11f:8828 :::*                    LISTEN
			tcp6       0      0 fd00:e53d:b0b7:11f:8858 :::*                    LISTEN
			tcp6       0      0 fd00:844b:dfc:16c7:8948 :::*                    LISTEN
			tcp6       0      0 fd00:844b:dfc:16c7:8918 :::*                    LISTEN
			udp        0      0 172.18.0.1:8558         0.0.0.0:*
			udp        0      0 172.18.0.1:8618         0.0.0.0:*
			udp        0      0 172.20.0.1:8858         0.0.0.0:*
			udp        0      0 172.19.0.1:8948         0.0.0.0:*
			udp        0      0 0.0.0.0:34296           0.0.0.0:*
			udp        0      0 192.168.51.190:68       0.0.0.0:*
			udp6       0      0 fd00:e53d:b0b7:11f:8858 :::*
			udp6       0      0 fd00:844b:dfc:16c7:8948 :::*
		*/
		var ipv4 string
		var ipv6 string

		if self.dockerNetwork != nil {
			if self.dockerNetwork.ipv4 != nil {
				ipv4 = self.dockerNetwork.ipv4.interfaceIp
			}
			if self.dockerNetwork.ipv6 != nil {
				ipv6 = self.dockerNetwork.ipv6.interfaceIp
			}
		} else {
			if self.servicesDockerNetwork.ipv4 != nil {
				ipv4 = self.servicesDockerNetwork.ipv4.interfaceIp
			}
			if self.servicesDockerNetwork.ipv6 != nil {
				ipv6 = self.servicesDockerNetwork.ipv6.interfaceIp
			}
		}

		listenPorts := map[int]bool{}

		if ipv4 != "" {
			r := regexp.MustCompile("(?m)^\\s*(?:tcp|udp)\\s+.*\\s+" + regexp.QuoteMeta(ipv4) + ":(\\d+)\\s+.*$")
			allGroups := r.FindAllSubmatch(out, -1)
			for _, groups := range allGroups {
				internalPort, err := strconv.Atoi(string(groups[1]))
				if err == nil {
					listenPorts[internalPort] = true
				}
			}
		}
		if ipv6 != "" {
			r := regexp.MustCompile("(?m)^\\s*(?:tcp6|udp6)\\s+.*\\s+" + regexp.QuoteMeta(ipv6) + ":(\\d+)\\s+.*$")
			allGroups := r.FindAllSubmatch(out, -1)
			for _, groups := range allGroups {
				internalPort, err := strconv.Atoi(string(groups[1]))
				if err == nil {
					listenPorts[internalPort] = true
				}
			}
		}

		for _, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if listenPorts[internalPort] {
					occupiedPorts[internalPort] = true
				}
			}
		}
	} else {
		runningContainers, err := self.findRunningContainers()
		if err != nil {
			return nil, err
		}
		for internalPort, _ := range runningContainers {
			occupiedPorts[internalPort] = true
		}
	}
	return occupiedPorts, nil
}

func (self *RunWorker) startContainer(servicePortsToInternalPort map[int]int) (string, error) {
	vaultMount := "/srv/warp/vault"
	configMount := "/srv/warp/config"
	siteMount := "/srv/warp/site"

	containerName := fmt.Sprintf(
		"%s-%s-%s-%s-%d",
		self.env,
		self.service,
		self.block,
		convertVersionToDocker(self.deployedVersion.String()),
		time.Now().UnixMilli(),
	)
	imageName := fmt.Sprintf(
		"%s/%s-%s:%s",
		self.warpState.warpSettings.RequireDockerNamespace(),
		self.env,
		self.service,
		convertVersionToDocker(self.deployedVersion.String()),
	)

	pullCmd := docker("pull", imageName)
	err := runAndLog(pullCmd)
	if err != nil {
		return "", err
	}

	args := []string{
		"--label", fmt.Sprintf("%s-%s-%s", self.env, self.service, self.block),
		"--label", fmt.Sprintf("version=%s", convertVersionToDocker(self.deployedVersion.String())),
		"--name", containerName,
		"-d",
		// see https://docs.docker.com/engine/containers/start-containers-automatically/
		// "--restart=unless-stopped",
	}
	if self.hostNetworking {
		args = append(args, []string{"--network", "host"}...)
	} else {
		// publish the ports in order so that changed can be easily diffed
		orderedServicePorts := maps.Keys(servicePortsToInternalPort)
		slices.Sort(orderedServicePorts)
		for _, servicePort := range orderedServicePorts {
			internalPort := servicePortsToInternalPort[servicePort]
			// docker by default accepts connections on both IPv4 and IPv6
			// publish both tcp and udp
			args = append(args, []string{"-p", fmt.Sprintf("%d:%d/tcp", internalPort, servicePort)}...)
			args = append(args, []string{"-p", fmt.Sprintf("%d:%d/udp", internalPort, servicePort)}...)
		}
		if self.dockerNetwork != nil {
			args = append(args, []string{"--network", self.dockerNetwork.networkName}...)
		} else {
			args = append(args, []string{"--network", self.servicesDockerNetwork.networkName}...)
		}
	}
	// docker services run on ipv4 only
	if self.dockerNetwork != nil {
		args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.dockerNetwork.networkName, self.dockerNetwork.ipv4.interfaceIp)}...)
	}
	args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.servicesDockerNetwork.networkName, self.servicesDockerNetwork.ipv4.interfaceIp)}...)

	switch self.vaultMountMode {
	case MOUNT_MODE_YES:
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				self.warpState.warpSettings.RequireVaultHome(),
				vaultMount,
			),
		}...)
	}

	switch self.configMountMode {
	case MOUNT_MODE_YES:
		configVersionHome := filepath.Join(
			self.warpState.warpSettings.RequireConfigHome(),
			self.deployedConfigVersion.String(),
		)
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				configVersionHome,
				configMount,
			),
		}...)
	case MOUNT_MODE_ROOT:
		// mount as read-write (default)
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s",
				self.warpState.warpSettings.RequireConfigHome(),
				configMount,
			),
		}...)
	}

	switch self.siteMountMode {
	case MOUNT_MODE_YES:
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				self.warpState.warpSettings.RequireSiteHome(),
				siteMount,
			),
		}...)
	}

	env := map[string]string{
		"WARP_VERSION": self.deployedVersion.String(),
		"WARP_ENV":     self.env,
		"WARP_SERVICE": self.service,
		"WARP_BLOCK":   self.block,
	}
	if host, err := os.Hostname(); err == nil {
		env["WARP_HOST"] = host
	}

	// service_port:internal_port
	portParts := []string{}
	for servicePort, internalPort := range servicePortsToInternalPort {
		portParts = append(portParts, fmt.Sprintf("%d:%d", servicePort, internalPort))
	}
	env["WARP_PORTS"] = strings.Join(portParts, ",")
	if self.hostNetworking {
		var ipv4 string
		var ipv6 string

		if self.dockerNetwork != nil {
			if self.dockerNetwork.ipv4 != nil {
				ipv4 = self.dockerNetwork.ipv4.interfaceIp
			}
			if self.dockerNetwork.ipv6 != nil {
				ipv6 = self.dockerNetwork.ipv6.interfaceIp
			}
		} else {
			if self.servicesDockerNetwork.ipv4 != nil {
				ipv4 = self.servicesDockerNetwork.ipv4.interfaceIp
			}
			if self.servicesDockerNetwork.ipv6 != nil {
				ipv6 = self.servicesDockerNetwork.ipv6.interfaceIp
			}
		}

		env["WARP_HOST_IPV4"] = ipv4
		env["WARP_HOST_IPV6"] = ipv6
	}

	if self.deployedConfigVersion != nil {
		env["WARP_CONFIG_VERSION"] = self.deployedConfigVersion.String()
	}
	if self.vaultMountMode != MOUNT_MODE_NO {
		env["WARP_VAULT"] = vaultMount
	}
	if self.configMountMode != MOUNT_MODE_NO {
		env["WARP_CONFIG"] = configMount
	}
	if self.siteMountMode != MOUNT_MODE_NO {
		env["WARP_SITE"] = siteMount
	}
	// add the user env vars
	for key, value := range self.envVars {
		env[key] = value
	}
	for name, value := range env {
		args = append(args, []string{"-e", fmt.Sprintf("%s=%s", name, value)}...)
	}

	// aws log driver
	// make sure to configure the docker service with the correct env vars, e.g.
	//     sudo systemctl edit docker
	//     [Service]
	//     Environment="AWS_ACCESS_KEY_ID=<aws_access_key_id>"
	//     Environment="AWS_SECRET_ACCESS_KEY=<aws_secret_access_key>"

	awsRegion := "us-west-1"
	logGroup := fmt.Sprintf("%s-%s", self.env, self.service)
	logStream := fmt.Sprintf("%s", self.block)
	var logTag string
	if host, err := os.Hostname(); err == nil {
		logTag = fmt.Sprintf(
			"%s_%s_{{.ID}}",
			host,
			convertVersionToDocker(self.deployedVersion.String()),
		)
	} else {
		logTag = fmt.Sprintf(
			"%s_{{.ID}}",
			convertVersionToDocker(self.deployedVersion.String()),
		)
	}
	args = append(args, []string{
		"--log-driver=awslogs",
		"--log-opt", fmt.Sprintf("awslogs-region=%s", awsRegion),
		"--log-opt", fmt.Sprintf("awslogs-group=%s", logGroup),
		"--log-opt", fmt.Sprintf("awslogs-stream=%s", logStream),
		"--log-opt", fmt.Sprintf("tag=%s", logTag),
		"--log-opt", "awslogs-create-group=true",
	}...)

	// constraint args
	// https://docs.docker.com/engine/containers/resource_constraints/
	// args = append(args, []string{"--oom-kill-disable"}...)

	args = append(args, imageName)

	args = append(args, self.runArgs...)

	runCmd := docker("run", args...)

	out, err := outAndLog(runCmd)
	// `docker run` prints the container_id as the only output
	containerId := strings.TrimSpace(string(out))

	if err != nil {
		return containerId, err
	}

	if self.dockerNetwork != nil {
		// allow connect to the services network
		docker("network", "connect", self.servicesDockerNetwork.networkName, containerId)
	}

	return containerId, nil
}

func (self *RunWorker) pollContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	switch self.statusMode {
	case STATUS_MODE_STANDARD:
		return self.pollBasicContainerStatus(servicePortsToInternalPort, timeout)
	default:
		// wait 30s
		if !self.quitEvent.WaitForSet(30 * time.Second) {
			return nil
		}
		panic("Could not poll status.")
	}
}

func (self *RunWorker) pollBasicContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	httpPort, ok := servicePortsToInternalPort[80]
	if !ok {
		// no http port - assume ok
		return nil
	}

	client := &http.Client{}

	poll := func() error {
		var routePrefix string
		if self.statusPrefix == "" {
			routePrefix = ""
		} else {
			routePrefix = fmt.Sprintf("/%s", self.statusPrefix)
		}
		var httpIp string
		if self.hostNetworking {
			if self.dockerNetwork != nil {
				httpIp = self.dockerNetwork.ipv4.interfaceIp
			} else {
				httpIp = self.servicesDockerNetwork.ipv4.interfaceIp
			}
		} else {
			httpIp = "127.0.0.1"
		}
		statusUrl := fmt.Sprintf("http://%s:%d%s/status", httpIp, httpPort, routePrefix)
		Err.Printf("Poll %s\n", statusUrl)

		statusRequest, err := http.NewRequest("GET", statusUrl, nil)
		if err != nil {
			return err
		}
		statusRequest.Host = fmt.Sprintf("%s-%s.%s", self.env, self.service, self.domain)
		statusResponse, err := client.Do(statusRequest)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(statusResponse.Body)
		Err.Printf("Poll result %s (%s)\n", body, err)
		if err != nil {
			return err
		}
		var warpStatusResponse WarpStatusResponse
		err = json.Unmarshal(body, &warpStatusResponse)
		if err != nil {
			return err
		}
		if warpStatusResponse.IsError() {
			return errors.New(warpStatusResponse.Status)
		}
		return nil
	}

	endTime := time.Now().Add(timeout)
	for !self.quitEvent.IsSet() {
		err := poll()
		if err == nil {
			return nil
		}
		if time.Now().After(endTime) {
			return err
		}
		self.quitEvent.WaitForSet(WarpPollTimeout)
	}
	panic("Could not poll container status.")
}

// note "internal port" is also called "host port" in other parts of warp
func (self *RunWorker) redirect(
	externalPortsToInternalPort map[int]int,
	servicePortsToInternalPort map[int]int,
	deployedContainerId string,
) {
	chainName := self.iptablesChainName()

	var containerIpv4 string
	var containerIpv6 string
	if self.hostNetworking {
		if self.dockerNetwork != nil {
			if self.dockerNetwork.ipv4 != nil {
				containerIpv4 = self.dockerNetwork.ipv4.interfaceIp
			}
			if self.dockerNetwork.ipv6 != nil {
				containerIpv6 = self.dockerNetwork.ipv6.interfaceIp
			}
		} else {
			if self.servicesDockerNetwork.ipv4 != nil {
				containerIpv4 = self.servicesDockerNetwork.ipv4.interfaceIp
			}
			if self.servicesDockerNetwork.ipv6 != nil {
				containerIpv6 = self.servicesDockerNetwork.ipv6.interfaceIp
			}
		}
	} else {
		if out, err := sudo2(
			[]string{"docker"},
			"inspect",
			"-f",
			"{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
			deployedContainerId,
		).Output(); err == nil {
			containerIpv4 = strings.TrimSpace(string(out))
		}

		if out, err := sudo2(
			[]string{"docker"},
			"inspect",
			"-f",
			"{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}",
			deployedContainerId,
		).Output(); err == nil {
			containerIpv6 = strings.TrimSpace(string(out))
		}
	}

	Err.Printf("Container ipv4='%s', ipv6='%s'\n", containerIpv4, containerIpv6)

	for _, protocol := range []string{"tcp", "udp"} {
		for _, networkConfig := range self.getNetworkConfigs() {

			if self.hostNetworking {
				// use DNAT
				// - forward to the external port
				// - forward to the internal port

				existingPortsToInternalPorts := map[int]map[int]bool{}
				dnatRegex := regexp.MustCompile("^\\s*DNAT\\s+.*\\s+" + protocol + "\\s+dpt:(\\d+)\\s+to:\\s*(\\S+)\\s*$")
				if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
					/*
					   Chain WARP-MAIN-LB-ENO2 (2 references)
					   target     prot opt source               destination
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::3]:443
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:80 to:[fd00:f1a4:349b:bc6e::3]:80
					*/
					for _, line := range strings.Split(string(out), "\n") {
						if groups := dnatRegex.FindStringSubmatch(line); groups != nil {
							destination := groups[2]

							destinationAddrPort, err := netip.ParseAddrPort(destination)
							if err != nil {
								Err.Printf("Invalid DNAT redirect destination, skipping: %s", destination)
							} else {
								var destinationIp string
								if networkConfig.ipv6 {
									destinationIp = containerIpv6
								} else {
									destinationIp = containerIpv4
								}

								switch destinationAddrPort.Addr().String() {
								case destinationIp:
									port, _ := strconv.Atoi(groups[1])
									internalPort := int(destinationAddrPort.Port())
									internalPorts, ok := existingPortsToInternalPorts[port]
									if !ok {
										internalPorts = map[int]bool{}
										existingPortsToInternalPorts[port] = internalPorts
									}
									internalPorts[internalPort] = true
								}
							}
						}
					}
				}

				for port, internalPorts := range existingPortsToInternalPorts {
					for internalPort, _ := range internalPorts {
						Err.Printf("Found existing redirect: %d->%d\n", port, internalPort)
					}
				}

				redirectCmd := func(op string, externalPort int, internalPort int) *exec.Cmd {
					// var destinationIp string
					var destination string
					if networkConfig.ipv6 {
						if containerIpv6 == "" {
							panic("Container must have ipv6")
						}
						// destinationIp = containerIpv6
						destination = fmt.Sprintf("[%s]:%d", containerIpv6, internalPort)
					} else {
						if containerIpv4 == "" {
							panic("Container must have ipv4")
						}
						// destinationIp = containerIpv4
						destination = fmt.Sprintf("%s:%d", containerIpv4, internalPort)
					}

					return sudo2(
						networkConfig.iptablesCommand, "-t", "nat", op, chainName,
						"-p", protocol, "-m", protocol /*"-d", destinationIp,*/, "--dport", strconv.Itoa(externalPort),
						"-j", "DNAT", "--to-destination", destination,
					)
				}
				for externalPort, internalPort := range externalPortsToInternalPort {
					// do not add if already exists
					if err := runAndLog(redirectCmd("-C", internalPort, internalPort)); err != nil {
						if err := runAndLog(redirectCmd("-I", internalPort, internalPort)); err != nil {
							panic(err)
						}
					}
					if err := runAndLog(redirectCmd("-C", externalPort, internalPort)); err != nil {
						if err := runAndLog(redirectCmd("-I", externalPort, internalPort)); err != nil {
							panic(err)
						}
					}
				}
				// remove existing
				for externalPort, internalPort := range externalPortsToInternalPort {
					if existingInternalPorts, ok := existingPortsToInternalPorts[externalPort]; ok {
						for existingInternalPort, _ := range existingInternalPorts {
							if internalPort != existingInternalPort {
								for {
									cmd := redirectCmd("-D", existingInternalPort, existingInternalPort)
									if err := runAndLog(cmd); err != nil {
										break
									}
								}
								for {
									cmd := redirectCmd("-D", externalPort, existingInternalPort)
									if err := runAndLog(cmd); err != nil {
										break
									}
								}
							}
						}
					}
				}
			} else {
				// use REDIR
				// find existing redirects and remove those for the owned external ports
				existingPortsToInternalPorts := map[int]map[int]bool{}
				redirectRegex := regexp.MustCompile("^\\s*REDIRECT\\s+.*\\s+" + protocol + "\\s+dpt:(\\d+)\\s+redir\\s+ports\\s+(\\d+)\\s*$")
				if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
					/*
					   Chain WARP-LOCAL-LB-ENS160 (2 references)
					   target     prot opt source               destination
					   REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443 redir ports 7231
					   REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 redir ports 7201
					*/
					for _, line := range strings.Split(string(out), "\n") {
						if groups := redirectRegex.FindStringSubmatch(line); groups != nil {
							port, _ := strconv.Atoi(groups[1])
							internalPort, _ := strconv.Atoi(groups[2])
							internalPorts, ok := existingPortsToInternalPorts[port]
							if !ok {
								internalPorts = map[int]bool{}
								existingPortsToInternalPorts[port] = internalPorts
							}
							internalPorts[internalPort] = true
						}
					}
				}

				Err.Printf("Existing redirects %s\n", existingPortsToInternalPorts)

				redirectCmd := func(op string, externalPort int, internalPort int) *exec.Cmd {
					return sudo2(
						networkConfig.iptablesCommand, "-t", "nat", op, chainName,
						"-p", protocol, "-m", protocol, "--dport", strconv.Itoa(externalPort),
						"-j", "REDIRECT", "--to-ports", strconv.Itoa(internalPort),
					)
				}
				for externalPort, internalPort := range externalPortsToInternalPort {
					// do not add if already exists
					if err := runAndLog(redirectCmd("-C", externalPort, internalPort)); err != nil {
						if err := runAndLog(redirectCmd("-I", externalPort, internalPort)); err != nil {
							panic(err)
						}
					}
				}
				// remove existing
				for externalPort, internalPort := range externalPortsToInternalPort {
					if existingInternalPorts, ok := existingPortsToInternalPorts[externalPort]; ok {
						for existingInternalPort, _ := range existingInternalPorts {
							if internalPort != existingInternalPort {
								for {
									cmd := redirectCmd("-D", externalPort, existingInternalPort)
									if err := runAndLog(cmd); err != nil {
										break
									}
								}
							}
						}
					}
				}
			}

			if networkConfig.routingTable != nil {
				existingPortsToDestinations := map[int]map[string]bool{}
				dnatRegex := regexp.MustCompile("^\\s*DNAT\\s+.*\\s+" + protocol + "\\s+dpt:(\\d+)\\s+to:\\s*(\\S+)\\s*$")
				if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
					/*
					   Chain WARP-MAIN-LB-ENO2 (2 references)
					   target     prot opt source               destination
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::3]:443
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:80 to:[fd00:f1a4:349b:bc6e::3]:80
					*/
					for _, line := range strings.Split(string(out), "\n") {
						if groups := dnatRegex.FindStringSubmatch(line); groups != nil {
							destination := groups[2]

							destinationAddrPort, err := netip.ParseAddrPort(destination)
							if err != nil {
								Err.Printf("Invalid DNAT destination, skipping: %s", destination)
							} else {
								var destinationIp string
								if networkConfig.ipv6 {
									destinationIp = containerIpv6
								} else {
									destinationIp = containerIpv4
								}

								switch destinationAddrPort.Addr().String() {
								case destinationIp:
									port, _ := strconv.Atoi(groups[1])
									destinations, ok := existingPortsToDestinations[port]
									if !ok {
										destinations = map[string]bool{}
										existingPortsToDestinations[port] = destinations
									}
									destinations[destination] = true
								}
							}
						}
					}
				}

				Err.Printf("Existing destinations %s\n", existingPortsToDestinations)

				containerDestination := func(servicePort int) string {
					var destinationPort int
					if self.hostNetworking {
						var ok bool
						destinationPort, ok = servicePortsToInternalPort[servicePort]
						if !ok {
							panic(fmt.Errorf("Host port not found for service port %d", servicePort))
						}
					} else {
						destinationPort = servicePort
					}
					if networkConfig.ipv6 {
						if containerIpv6 == "" {
							panic("Container must have ipv6")
						}
						return fmt.Sprintf("[%s]:%d", containerIpv6, destinationPort)
					} else {
						if containerIpv4 == "" {
							panic("Container must have ipv4")
						}
						return fmt.Sprintf("%s:%d", containerIpv4, destinationPort)
					}
				}

				// redirect for traffic to the interface ip on the service port
				publicRedirectCmd := func(op string, servicePort int, destination string) *exec.Cmd {
					// use dnat to the container ip and service port to work around the docker issue of masking the remote ip
					// https://github.com/docker/docs/issues/17312

					return sudo2(
						networkConfig.iptablesCommand, "-t", "nat", op, chainName,
						"-p", protocol, "-m", protocol, "-d", networkConfig.routingTable.interfaceIp, "--dport", strconv.Itoa(servicePort),
						"-j", "DNAT", "--to-destination", destination,
					)
				}
				for servicePort, _ := range servicePortsToInternalPort {
					// do not add if already exists
					destination := containerDestination(servicePort)
					if err := runAndLog(publicRedirectCmd("-C", servicePort, destination)); err != nil {
						if err := runAndLog(publicRedirectCmd("-I", servicePort, destination)); err != nil {
							panic(err)
						}
					}
				}

				// remove existing
				for servicePort, _ := range servicePortsToInternalPort {
					destination := containerDestination(servicePort)
					if existingDestinationsMap, ok := existingPortsToDestinations[servicePort]; ok {
						for existingDestination, _ := range existingDestinationsMap {
							if destination != existingDestination {
								for {
									cmd := publicRedirectCmd("-D", servicePort, existingDestination)
									if err := runAndLog(cmd); err != nil {
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func (self *RunWorker) prune() {
	// ignore errors
	cmd := docker(
		"container",
		"prune",
		"-f",
		// restict to containers labeled with <env>-<service>-<block>
		"--filter", fmt.Sprintf("label=%s-%s-%s", self.env, self.service, self.block),
	)
	runAndLog(cmd)
}

type ContainerList = []*Container

type Container struct {
	ContainerId string      `json:"Id"`
	HostConfig  *HostConfig `json:"HostConfig"`
}

type HostConfig struct {
	PortBindings map[string][]*PortBinding `json:"PortBindings"`
}

type PortBinding struct {
	HostIp   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// internal port -> running container_id for all running containers
func (self *RunWorker) findRunningContainers() (map[int]string, error) {
	psCmd := docker("ps", "--format", "{{.ID}}")
	out, err := psCmd.Output()
	if err != nil {
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		// no containers running
		return map[int]string{}, nil
	}

	containerIds := strings.Split(outStr, "\n")
	inspectCmd := docker("inspect", containerIds...)
	out, err = inspectCmd.Output()
	if err != nil {
		return nil, err
	}

	var containerList ContainerList
	err = json.Unmarshal(out, &containerList)
	if err != nil {
		return nil, err
	}

	runningContainers := map[int]string{}

	for _, container := range containerList {
		for _, portBindings := range container.HostConfig.PortBindings {
			for _, portBinding := range portBindings {
				internalPort, err := strconv.Atoi(portBinding.HostPort)
				if err != nil {
					return nil, err
				}
				runningContainers[internalPort] = container.ContainerId
			}
		}
	}

	return runningContainers, nil
}

type PortBlocks struct {
	externalsToInternals map[int][]int
	externalsToService   map[int]int
}

// service:external::p-P,p;service:external:...
func parsePortBlocks(portBlocksStr string) *PortBlocks {
	externalsToInternals := map[int][]int{}
	externalsToService := map[int]int{}

	externalStrs := strings.Split(portBlocksStr, ";")
	for _, externalStr := range externalStrs {
		externalStrSplit := strings.SplitN(externalStr, ":", 3)
		servicePort, err := strconv.Atoi(externalStrSplit[0])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int serviceport:externalport:portlist (%s)", externalStrSplit[0]))
		}
		externalPort, err := strconv.Atoi(externalStrSplit[1])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int serviceport:externalport:portlist (%s)", externalStrSplit[0]))
		}

		internalPorts, err := expandPorts(externalStrSplit[2])
		if err != nil {
			panic(err)
		}
		externalsToInternals[externalPort] = internalPorts
		externalsToService[externalPort] = servicePort
	}
	return &PortBlocks{
		externalsToInternals: externalsToInternals,
		externalsToService:   externalsToService,
	}
}

type NetworkInterface struct {
	interfaceName    string
	interfaceIp      string
	interfaceSubnet  string
	interfaceGateway string
}

type NetworkConfig struct {
	ipv6            bool
	routingTable    *NetworkInterface
	dockerNetwork   *NetworkInterface
	ipCommand       []string
	iptablesCommand []string
}

func getNetworkConfigs(routingTable *RoutingTable, dockerNetwork *DockerNetwork) []*NetworkConfig {
	networkConfigs := []*NetworkConfig{}

	var routingTableIpv4 *NetworkInterface
	var routingTableIpv6 *NetworkInterface
	var dockerNetworkIpv4 *NetworkInterface
	var dockerNetworkIpv6 *NetworkInterface
	if routingTable != nil {
		if routingTable.ipv4 != nil {
			routingTableIpv4 = routingTable.ipv4
		}
		if routingTable.ipv6 != nil {
			routingTableIpv6 = routingTable.ipv6
		}
	}
	if dockerNetwork != nil {
		if dockerNetwork.ipv4 != nil {
			dockerNetworkIpv4 = dockerNetwork.ipv4
		}
		if dockerNetwork.ipv6 != nil {
			dockerNetworkIpv6 = dockerNetwork.ipv6
		}
	}

	if dockerNetworkIpv4 != nil {
		// ipv4
		networkConfigs = append(networkConfigs, &NetworkConfig{
			ipv6:            false,
			routingTable:    routingTableIpv4,
			dockerNetwork:   dockerNetworkIpv4,
			ipCommand:       []string{"ip"},
			iptablesCommand: []string{"iptables"},
		})
	}
	if dockerNetworkIpv6 != nil {
		// ipv6
		networkConfigs = append(networkConfigs, &NetworkConfig{
			ipv6:            true,
			routingTable:    routingTableIpv6,
			dockerNetwork:   dockerNetworkIpv6,
			ipCommand:       []string{"ip", "-6"},
			iptablesCommand: []string{"ip6tables"},
		})
	}
	return networkConfigs
}

// local docker is always ipv4
type DockerNetwork struct {
	networkName string
	ipv4        *NetworkInterface
	ipv6        *NetworkInterface
}

func parseDockerNetwork(dockerNetworkStr string) *DockerNetwork {
	// for docker the interface name is the network name
	networkName := dockerNetworkStr

	v4NetworkInterface, v6NetworkInterface := requireNetworkInterfaceIpv4OptionalIpv6(networkName)

	return &DockerNetwork{
		networkName: networkName,
		ipv4:        v4NetworkInterface,
		ipv6:        v6NetworkInterface,
	}
}

type RoutingTable struct {
	tableNumber int
	tableName   string
	ipv4        *NetworkInterface
	ipv6        *NetworkInterface
}

// interface:rt_table_name
// inspect the local interface for the ip address
func parseRoutingTable(routingTableStr string) *RoutingTable {
	routingTableStrSplit := strings.SplitN(routingTableStr, ":", 2)
	interfaceName := routingTableStrSplit[0]
	tableNumber, err := strconv.Atoi(routingTableStrSplit[1])
	if err != nil {
		panic(err)
	}

	tableNames := map[int]string{}
	tableNameRegex := regexp.MustCompile("^\\s*(\\d+)\\s+(\\S+)\\s*$")
	if out, err := os.ReadFile("/etc/iproute2/rt_tables"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if groups := tableNameRegex.FindStringSubmatch(line); groups != nil {
				tableNumber, err := strconv.Atoi(groups[1])
				if err != nil {
					panic("Bad rt_tables entry.")
				}
				tableName := groups[2]
				tableNames[tableNumber] = tableName
			}
		}
	}

	tableName, ok := tableNames[tableNumber]
	if !ok {
		panic(fmt.Sprintf("Routing table %d does not exist.", tableNumber))
	}

	v4NetworkInterface, v6NetworkInterface := requireNetworkInterfaceIpv4OptionalIpv6(interfaceName)

	return &RoutingTable{
		tableNumber: tableNumber,
		tableName:   tableName,
		ipv4:        v4NetworkInterface,
		ipv6:        v6NetworkInterface,
	}
}

// one ipv4
// zero or one ipv6
func requireNetworkInterfaceIpv4OptionalIpv6(interfaceName string) (*NetworkInterface, *NetworkInterface) {
	v4NetworkInterfaces, v6NetworkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}

	// v4 must be present
	var v4NetworkInterface *NetworkInterface
	if len(v4NetworkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not map docker interface %s to interface", interfaceName)))
	} else if 1 < len(v4NetworkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one v4 network attached to interface %s", interfaceName)))
	} else {
		v4NetworkInterface = v4NetworkInterfaces[0]
	}

	var v6NetworkInterface *NetworkInterface
	if 0 == len(v6NetworkInterfaces) {
		v6NetworkInterface = nil
	} else if 1 < len(v6NetworkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one v6 network attached to interface %s", interfaceName)))
	} else {
		v6NetworkInterface = v6NetworkInterfaces[0]
	}

	return v4NetworkInterface, v6NetworkInterface
}

func getNetworkInterfaces(interfaceName string) ([]*NetworkInterface, []*NetworkInterface, error) {
	// see https://github.com/golang/go/issues/12551

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not find interface for %s: %s", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("Could not find interface addresses for %s: %s", interfaceName, err)
	}

	v4NetworkInterfaces := []*NetworkInterface{}
	v6NetworkInterfaces := []*NetworkInterface{}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalMulticast() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}

		zeroedIpNet := net.IPNet{
			IP:   ipNet.IP.Mask(ipNet.Mask),
			Mask: ipNet.Mask,
		}

		gateway := gateway(zeroedIpNet)

		networkInterface := &NetworkInterface{
			interfaceName:    interfaceName,
			interfaceIp:      ipNet.IP.String(),
			interfaceSubnet:  zeroedIpNet.String(),
			interfaceGateway: gateway.String(),
		}

		if ipNet.IP.To4() != nil {
			v4NetworkInterfaces = append(v4NetworkInterfaces, networkInterface)
		} else if ipNet.IP.To16() != nil {
			v6NetworkInterfaces = append(v6NetworkInterfaces, networkInterface)
		}
	}

	for _, v4NetworkInterface := range v4NetworkInterfaces {
		Err.Printf(
			"%s ipv4=%s ipv4_subnet=%s ipv4_gateway=%s\n",
			v4NetworkInterface.interfaceName,
			v4NetworkInterface.interfaceIp,
			v4NetworkInterface.interfaceSubnet,
			v4NetworkInterface.interfaceGateway,
		)
	}
	for _, v6NetworkInterface := range v6NetworkInterfaces {
		Err.Printf(
			"%s ipv6=%s ipv6_subnet=%s ipv6_gateway=%s\n",
			v6NetworkInterface.interfaceName,
			v6NetworkInterface.interfaceIp,
			v6NetworkInterface.interfaceSubnet,
			v6NetworkInterface.interfaceGateway,
		)
	}

	return v4NetworkInterfaces, v6NetworkInterfaces, nil
}

type KillWorker struct {
	containerId string
	killTimeout time.Duration
}

func NewKillWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
		killTimeout: KillTimeout,
	}
}

func NewDrainWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
		killTimeout: DrainTimeout,
	}
}

func (self *KillWorker) Run() {
	// ignore errors
	runAndLog(docker(
		"update", "--restart=no", self.containerId,
	))

	// ignore errors
	runAndLog(docker(
		"container", "stop", "-t", fmt.Sprintf("%d", int(self.killTimeout/time.Second)), self.containerId,
	))
}
