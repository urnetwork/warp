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
const RoutingTableReconcileTimeout = 30 * time.Second
const KillTimeout = 15 * time.Second
const DrainTimeout = 60 * time.Minute
const NewContainerPollTimeout = 120 * time.Second

const connectListenersReadyHeader = "X-UR-Connect-Listeners-Ready"
const connectUdpListenersHeader = "X-UR-Connect-UDP-Listeners"

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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
	forwardPorts          map[string]map[int]int
	privateServicePorts   map[int]bool
	servicesDockerNetwork *DockerNetwork
	routingTable          *RoutingTable
	dockerNetwork         *DockerNetwork
	transparent           bool
	fwMark                int
	domain                string
	runArgs               []string
	memoryLimit           ByteCount
	coreLimit             int
	limitExcludeSubnets   string

	vaultMountMode  string
	configMountMode string
	siteMountMode   string
	dockerMountMode string
	dataMountMode   string
	capNetAdmin     bool
	containerUser   string
	secretFiles     []string

	statusMode   string
	statusPrefix string

	hostNetworking bool

	// serialize the drain of old containers across the host's groups so only
	// one group per host drains at a time (CONNECTDRAIN2.md §3.4). Default on;
	// disabled with WARPCTL_STAGGER_HOST_DRAIN=0
	staggerHostDrain bool

	envVars map[string]string

	deployedVersion       *semver.Version
	deployedConfigVersion *semver.Version

	quitEvent *warp.Event
}

// Resolve the platform image pulled onto this host into the immutable content
// identity Docker will execute. Running the id, rather than the mutable tag,
// closes the pull-to-run race and gives the process trustworthy provenance.
func inspectPulledImageDigest(imageName string) (string, error) {
	out, err := outAndLog(docker("image", "inspect", "--format={{.Id}}", imageName))
	if err != nil {
		return "", fmt.Errorf("inspect pulled image %s: %w", imageName, err)
	}
	imageDigest := strings.TrimSpace(string(out))
	if !imageDigestPattern.MatchString(imageDigest) {
		return "", fmt.Errorf("pulled image %s has invalid content digest", imageName)
	}
	return imageDigest, nil
}

// Converts the narrow deployment contract into Docker arguments and rejects
// privilege requests outside their explicitly supported service boundary.
func containerIsolationArgs(service string, capNetAdmin bool, containerUser string, dockerMountMode string) ([]string, error) {
	if dockerMountMode == MOUNT_MODE_YES {
		return nil, errors.New("Docker API socket mounts are forbidden")
	}
	if capNetAdmin && service != "proxy" {
		return nil, fmt.Errorf("service %q cannot request CAP_NET_ADMIN", service)
	}
	args := []string{}
	if capNetAdmin {
		args = append(args, "--cap-add=CAP_NET_ADMIN")
	}
	if containerUser != "" {
		args = append(args, "--user", containerUser)
	}
	return args, nil
}

// Resolves regular vault files into read-only mounts while independently
// rejecting traversal and duplicate inputs from stale hand-written units.
func scopedSecretMountArgs(vaultHome string, env string, secretFiles []string) ([]string, error) {
	args := []string{}
	seenSecretFiles := map[string]bool{}
	for _, secretFile := range secretFiles {
		if secretFile == "" || filepath.Base(secretFile) != secretFile || !filepath.IsLocal(secretFile) {
			return nil, fmt.Errorf("unsafe scoped secret file %q", secretFile)
		}
		if seenSecretFiles[secretFile] {
			return nil, fmt.Errorf("repeated scoped secret file %q", secretFile)
		}
		seenSecretFiles[secretFile] = true

		secretPath := filepath.Join(vaultHome, env, secretFile)
		secretInfo, err := os.Lstat(secretPath)
		if errors.Is(err, os.ErrNotExist) {
			secretPath = filepath.Join(vaultHome, secretFile)
			secretInfo, err = os.Lstat(secretPath)
		}
		if err != nil {
			return nil, fmt.Errorf("stat scoped secret %q: %w", secretFile, err)
		}
		if !secretInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("scoped secret %q is not a regular file", secretFile)
		}
		args = append(args,
			"--mount",
			fmt.Sprintf("type=bind,source=%s,target=/srv/warp/secrets/%s,readonly", secretPath, secretFile),
		)
	}
	return args, nil
}

// containerLogArgs selects host-managed journal collection and a parseable,
// stable stream identity without exposing Docker's control API.
func containerLogArgs(env string, service string, block string) []string {
	return []string{
		"--log-driver=journald",
		"--log-opt", fmt.Sprintf("tag=warp|%s|%s|%s", env, service, block),
	}
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
		if self.service == "lb" && self.routingTable != nil {
			self.initRoutingTable()
		}
		self.initBlockRedirect()
	}

	initNetwork()
	if self.hasDaemon() && self.hostNetworking {
		if err := self.reconcileOrphanedServiceBlockContainers(); err != nil {
			// Reconciliation is deliberately fail-safe: a discovery/parsing error
			// must never stop the container that might still own live DNAT. The
			// normal deployment loop remains available and reports port pressure.
			Err.Printf("Could not reconcile orphaned running containers: %s\n", err)
		}
	}

	// self.deployedVersion = nil
	// self.deployedConfigVersion = nil

	if self.service == "lb" && self.transparent {
		var reconcileRoutingTable func()
		if self.routingTable != nil {
			reconcileRoutingTable = self.initRoutingTable
		}
		reconcileRoutingTableUntilQuit(self.quitEvent.WaitForSet, reconcileRoutingTable)
	} else {
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
			} else if self.needsConfigVersion() && latestConfigVersion == nil {
				announceRunWaitForConfig()
			}

			self.quitEvent.WaitForSet(WarpPollTimeout)
		}
	}

	Err.Printf("Run worker stop.")
}

func reconcileRoutingTableUntilQuit(waitForQuit func(time.Duration) bool, reconcile func()) {
	for !waitForQuit(RoutingTableReconcileTimeout) {
		if reconcile != nil {
			reconcile()
		}
	}
}

func (self *RunWorker) hasDaemon() bool {
	switch self.service {
	case "config-updater":
		return false
	default:
		return true
	}
}

func (self *RunWorker) needsConfigVersion() bool {
	switch self.configMountMode {
	case MOUNT_MODE_NO, MOUNT_MODE_ROOT:
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

	if !self.needsConfigVersion() {
		return
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

func containerEnvValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, value := range env {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix), true
		}
	}
	return "", false
}

func containerWarpInternalPorts(container *Container) (map[int]bool, error) {
	if container == nil || container.Config == nil {
		return nil, errors.New("container inspect omitted Config")
	}
	warpPorts, ok := containerEnvValue(container.Config.Env, "WARP_PORTS")
	if !ok {
		return nil, errors.New("container inspect omitted WARP_PORTS")
	}
	internalPorts := map[int]bool{}
	if warpPorts == "" {
		return internalPorts, nil
	}
	for _, portPair := range strings.Split(warpPorts, ",") {
		parts := strings.SplitN(portPair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid WARP_PORTS entry %q", portPair)
		}
		servicePort, serviceErr := strconv.Atoi(parts[0])
		internalPort, internalErr := strconv.Atoi(parts[1])
		if serviceErr != nil || internalErr != nil || servicePort < 1 || 65535 < servicePort || internalPort < 1 || 65535 < internalPort {
			return nil, fmt.Errorf("invalid WARP_PORTS entry %q", portPair)
		}
		internalPorts[internalPort] = true
	}
	return internalPorts, nil
}

func (self *RunWorker) inspectServiceBlockContainers(containerIds []string) (ContainerList, error) {
	if len(containerIds) == 0 {
		return nil, nil
	}
	inspectCmd := docker("inspect", containerIds...)
	out, err := outAndLog(inspectCmd)
	if err != nil {
		return nil, err
	}
	var containers ContainerList
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// activeRedirectInternalPorts returns only current-pool internal ports that
// the block's live DNAT chain references. A partially transitioned chain may
// legitimately reference more than one container, so every matching owner is
// protected by restart reconciliation.
func (self *RunWorker) activeRedirectInternalPorts() (map[int]bool, error) {
	if self.portBlocks == nil {
		return nil, errors.New("missing port blocks")
	}
	configuredInternalPorts := map[int]bool{}
	for _, internalPorts := range self.portBlocks.externalsToInternals {
		for _, internalPort := range internalPorts {
			configuredInternalPorts[internalPort] = true
		}
	}

	activeInternalPorts := map[int]bool{}
	dnatDestination := regexp.MustCompile(`^\s*DNAT\s+.*\bto:(\S+)\s*$`)
	chainName := self.iptablesChainName()
	for _, networkConfig := range self.getNetworkConfigs() {
		out, err := sudo2(
			networkConfig.iptablesCommand,
			"-t", "nat", "-L", chainName, "-n",
		).Output()
		if err != nil {
			return nil, fmt.Errorf("inspect %s active DNAT: %w", networkConfig.iptablesCommand[0], err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			groups := dnatDestination.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			destination, err := netip.ParseAddrPort(groups[1])
			if err != nil {
				continue
			}
			internalPort := int(destination.Port())
			if configuredInternalPorts[internalPort] {
				activeInternalPorts[internalPort] = true
			}
		}
	}
	return activeInternalPorts, nil
}

func selectOrphanedServiceBlockContainers(
	containers ContainerList,
	activeInternalPorts map[int]bool,
) ([]string, error) {
	if len(containers) <= 1 {
		return nil, nil
	}
	if len(activeInternalPorts) == 0 {
		return nil, errors.New("live DNAT chain has no active internal target")
	}

	protected := map[string]bool{}
	for _, container := range containers {
		if container == nil || container.ContainerId == "" {
			return nil, errors.New("container inspect omitted Id")
		}
		internalPorts, err := containerWarpInternalPorts(container)
		if err != nil {
			return nil, fmt.Errorf("container %s: %w", container.ContainerId, err)
		}
		for internalPort := range internalPorts {
			if activeInternalPorts[internalPort] {
				protected[container.ContainerId] = true
				break
			}
		}
	}
	if len(protected) == 0 {
		activePorts := maps.Keys(activeInternalPorts)
		slices.Sort(activePorts)
		return nil, fmt.Errorf("no running container owns active DNAT target(s) %v", activePorts)
	}

	orphaned := []string{}
	for _, container := range containers {
		if !protected[container.ContainerId] {
			orphaned = append(orphaned, container.ContainerId)
		}
	}
	slices.Sort(orphaned)
	return orphaned, nil
}

// A worker can exit while an asynchronous old-generation drain is in flight.
// Older code also launched failed-candidate cleanup in a goroutine immediately
// before the control launcher restarted the process. Reconcile that inherited
// state before allocating: preserve every container referenced by live DNAT
// and resume a graceful drain for the unreferenced same-block containers.
func (self *RunWorker) reconcileOrphanedServiceBlockContainers() error {
	containerIds, err := self.findServiceBlockContainers()
	if err != nil || len(containerIds) <= 1 {
		return err
	}
	containers, err := self.inspectServiceBlockContainers(containerIds)
	if err != nil {
		return err
	}
	activeInternalPorts, err := self.activeRedirectInternalPorts()
	if err != nil {
		return err
	}
	orphanedContainerIds, err := selectOrphanedServiceBlockContainers(containers, activeInternalPorts)
	if err != nil {
		return err
	}
	if len(orphanedContainerIds) == 0 {
		return nil
	}
	Err.Printf(
		"Reconciling %d orphaned running container(s); preserving %d live-DNAT owner(s)\n",
		len(orphanedContainerIds),
		len(containers)-len(orphanedContainerIds),
	)
	go self.drainContainers(orphanedContainerIds)
	return nil
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
		defaultRouteArgs := []string{
			"via", networkConfig.routingTable.interfaceGateway,
			"dev", networkConfig.routingTable.interfaceName,
		}
		if out, err := sudo2(
			networkConfig.ipCommand, "route", "show", "table", "main", "default",
		).Output(); err == nil {
			if gateway, ok := defaultGatewayForInterface(string(out), networkConfig.routingTable.interfaceName); ok {
				defaultRouteArgs = []string{"dev", networkConfig.routingTable.interfaceName}
				if gateway != "" {
					defaultRouteArgs = append([]string{"via", gateway}, defaultRouteArgs...)
				}
			}
		}
		defaultRouteArgs = append(defaultRouteArgs, "table", tableNumberStr)
		runAndLog(sudo2(
			networkConfig.ipCommand,
			append([]string{"route", "replace", "default"}, defaultRouteArgs...)...,
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

		if 0 < self.fwMark {
			/*
				0:	from all lookup local
				32765:	from all fwmark 0x64 lookup warp100
				32766:	from all lookup main
				32767:	from all lookup default
			*/
			ipFwMarkFromLookups := map[int]string{}
			if out, err := sudo2(
				networkConfig.ipCommand, "rule", "list",
			).Output(); err == nil {
				ruleRegex := regexp.MustCompile("^\\s*.*\\s+from\\s+all\\s+fwmark\\s+(\\S+)\\s+lookup\\s+(\\S+)\\s*$")
				for _, line := range strings.Split(string(out), "\n") {
					if groups := ruleRegex.FindStringSubmatch(line); groups != nil {
						fwMarkStr := groups[1]
						// note base 0 detects the 0x prefix
						fwMark, err := strconv.ParseUint(fwMarkStr, 0, 32)
						if err == nil {
							// `ip rule list` shows lookup table names not numbers
							tableName := groups[2]
							ipFwMarkFromLookups[int(fwMark)] = tableName
						}
					}
				}
			}

			if tableName, ok := ipFwMarkFromLookups[self.fwMark]; !ok || tableName != self.routingTable.tableName {
				runAndLog(sudo2(
					networkConfig.ipCommand, "rule", "add",
					"fwmark", strconv.Itoa(self.fwMark),
					"table", tableNumberStr,
				))
			}
		}
	}
}

func defaultGatewayForInterface(routes string, interfaceName string) (string, bool) {
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		gateway := ""
		device := ""
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				gateway = fields[i+1]
			case "dev":
				device = fields[i+1]
			}
		}
		if device == interfaceName {
			return gateway, true
		}
	}
	return "", false
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

		// A host-networked service reaches its own children over loopback, and
		// the OUTPUT entry below matches every LOCAL destination -- loopback
		// included. Without this exclusion the service's own
		// 127.0.0.1:<internal port> dials are DNATed to the docker network ip,
		// where a host-networked service has no listener: the dial fails
		// "connection refused" while `ss` still shows the child LISTENing on
		// loopback. That is the mechanism behind the "bind paradox" (SIGNALS
		// 11.3) -- binding a child to 0.0.0.0 only ever appeared to fix it
		// because a wildcard listener also accepts on the DNAT destination ip.
		//
		// Excluding the destination on the ENTRY rule, rather than returning
		// inside the block chain, keeps this independent of rule order:
		// `redirect` inserts its DNAT rules at the head of the chain on every
		// deploy, so anything placed inside the chain sinks below them.
		//
		// Only host-networked services are excluded. A service in a docker
		// network is legitimately reached through this DNAT, and for it the
		// docker network ip is where the container actually listens.
		loopbackSubnet := "127.0.0.0/8"
		if networkConfig.ipv6 {
			loopbackSubnet = "::1/128"
		}
		chainCmd := func(op string, entryChainName string) *exec.Cmd {
			args := []string{"-t", "nat", op, entryChainName, "-m", "addrtype", "--dst-type", "LOCAL"}
			if self.hostNetworking && entryChainName == "OUTPUT" {
				args = append(args, "!", "-d", loopbackSubnet)
			}
			args = append(args, "-j", chainName)
			return sudo2(networkConfig.iptablesCommand, args...)
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

		if self.hostNetworking {
			// drop the pre-exclusion OUTPUT entry a previous warpctl installed.
			// It matches loopback destinations too, so leaving it in place
			// would keep DNATing the dials the rule above is meant to spare,
			// whichever of the two the packet reaches first. Guarded by -C so a
			// converged host does nothing.
			legacyOutputCmd := func(op string) *exec.Cmd {
				return sudo2(
					networkConfig.iptablesCommand, "-t", "nat", op, "OUTPUT",
					"-m", "addrtype", "--dst-type", "LOCAL",
					"-j", chainName,
				)
			}
			for runAndLog(legacyOutputCmd("-C")) == nil {
				if err := runAndLog(legacyOutputCmd("-D")); err != nil {
					break
				}
			}
		}
	}
}

func (self *RunWorker) deploy() error {
	externalPortsToInternalPort, servicePortsToInternalPort := self.assignDeployPorts()
	if externalPortsToInternalPort == nil {
		if self.quitEvent.IsSet() {
			return errors.New("could not allocate ports (quit)")
		}
		// Do not wait here while holding the version/config target captured by
		// Run. Returning to the watcher makes every retry poll the desired
		// versions again; otherwise a deployment blocked by a full pool can wake
		// hours later and activate an obsolete image.
		return errors.New("could not allocate ports (pool occupied)")
	}
	Err.Printf(
		"Ports %s, %s\n",
		mapStr(externalPortsToInternalPort),
		mapStr(servicePortsToInternalPort),
	)

	deployedContainerId, err := self.startContainer(servicePortsToInternalPort)
	success := false
	defer func() {
		if !success && deployedContainerId != "" {
			// deploy() failures cause the control launcher to restart this worker.
			// Cleanup must finish before that process exit; a detached goroutine can
			// be killed first and leak one still-listening candidate per retry until
			// every port in the block is occupied.
			NewKillWorker(deployedContainerId).Run()
		}
	}()
	if err != nil {
		Err.Printf("Start container failed: %s\n", err)
		return err
	}

	if err := self.pollContainerStatus(servicePortsToInternalPort, NewContainerPollTimeout); err != nil {
		return err
	}
	if err := self.pollConnectTransportReadiness(NewContainerPollTimeout); err != nil {
		return err
	}

	if err := self.redirect(externalPortsToInternalPort, servicePortsToInternalPort, deployedContainerId); err != nil {
		return err
	}

	// unpin client flows whose conntrack entry still steers them to a pool port
	// with no listener (e.g. a container that crashed and is replaced by this
	// deploy). The draining containers below still hold their sockets, so their
	// in-flight flows are preserved.
	self.cleanupStaleConntrack()

	if self.hostNetworking {
		runningContainers, err := self.findServiceBlockContainers()
		if err != nil {
			return err
		}

		Err.Printf("Found overlapping containers (%s) %s\n", deployedContainerId, strings.Join(runningContainers, ", "))
		overlappingContainerIds := []string{}
		for _, containerId := range runningContainers {
			if !containerIdsEqual(containerId, deployedContainerId) {
				overlappingContainerIds = append(overlappingContainerIds, containerId)
			}
		}
		go self.drainContainers(overlappingContainerIds)
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
		overlappingContainerIds := []string{}
		for containerId, _ := range containerIds {
			if !containerIdsEqual(containerId, deployedContainerId) {
				overlappingContainerIds = append(overlappingContainerIds, containerId)
			}
		}
		go self.drainContainers(overlappingContainerIds)
	}

	success = true
	return nil
}

// drainContainers drains the given old containers, serialized across the
// host's groups by the host drain lock so only one group per host drains at a
// time (CONNECTDRAIN2.md §3.4). The new container is already deployed and
// taking traffic before this runs, so holding the lock never blocks new
// capacity — it only staggers the old-container drains. Runs in its own
// goroutine (the deploy has already succeeded); a lock-acquire timeout falls
// back to draining without the stagger so a wedged drain cannot stall a
// rollout.
func (self *RunWorker) drainContainers(containerIds []string) {
	if len(containerIds) == 0 {
		return
	}

	staggered := false
	if self.staggerHostDrain {
		lock := newHostDrainLock(self.warpState.warpSettings.RequireWarpHome(), self.env, self.service)
		if lock.lock(hostDrainLockTimeout) {
			staggered = true
			defer func() {
				// hold the lock a moment after the drain so the lb and
				// conntrack settle onto the surviving capacity before the next
				// group begins its drain
				select {
				case <-self.quitEvent.Ctx.Done():
				case <-time.After(hostDrainSettleTimeout):
				}
				lock.unlock()
			}()
		} else {
			Err.Printf("Host drain lock not acquired within %s; draining without stagger\n", hostDrainLockTimeout)
		}
	}

	Err.Printf("Draining %d overlapping container(s) (staggered=%t)\n", len(containerIds), staggered)
	for _, containerId := range containerIds {
		NewDrainWorker(containerId).Run()
		// the drained container's sockets are now closed; unpin any flows
		// still steered to its ports so their next packet re-resolves against
		// the current DNAT rules
		self.cleanupStaleConntrack()
	}
}

func (self *RunWorker) assignDeployPorts() (map[int]int, map[int]int) {
	if self.quitEvent.IsSet() {
		return nil, nil
	}

	externalPortsToInternalPort := map[int]int{}
	occupiedPorts, err := self.findOccupiedPorts()
	if err != nil {
		panic(err)
	}
	for internalPort := range occupiedPorts {
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

	// A retry belongs to the outer watcher, not this allocation routine. The
	// watcher repolls the deployment target before trying again.
	if len(externalPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
		return nil, nil
	}

	servicePortsToInternalPort := map[int]int{}
	for externalPort, servicePort := range self.portBlocks.externalsToService {
		internalPort := externalPortsToInternalPort[externalPort]
		servicePortsToInternalPort[servicePort] = internalPort
	}

	return externalPortsToInternalPort, servicePortsToInternalPort
}

func (self *RunWorker) findOccupiedPorts() (map[int]bool, error) {
	occupiedPorts := map[int]bool{}
	if self.hostNetworking {
		started := time.Now()
		// netstat does not need elevated privileges without -p. Its output can
		// contain tens of thousands of UDP sockets on a busy edge, so capture it
		// for parsing without copying every row into journald.
		commandResult, err := runQuiet(exec.Command("netstat", "-tuln"))
		if err != nil {
			return nil, fmt.Errorf(
				"netstat socket discovery: %s",
				quietCommandError(err),
			)
		}
		out := commandResult.stdout
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

		addv4 := func(ipv4 string) {
			r := regexp.MustCompile("(?m)^\\s*(?:tcp|udp)\\s+.*\\s+" + regexp.QuoteMeta(ipv4) + ":(\\d+)\\s+.*$")
			allGroups := r.FindAllSubmatch(out, -1)
			for _, groups := range allGroups {
				internalPort, err := strconv.Atoi(string(groups[1]))
				if err == nil {
					listenPorts[internalPort] = true
				}
			}
		}
		if ipv4 != "" {
			addv4(ipv4)
		}
		addv4("0.0.0.0")
		// A service may bind its internal listeners on loopback instead of the
		// docker network ip: the grafana bundle keeps loki/mimir/grafana on
		// 127.0.0.1 behind its authenticated front. A scan anchored only on the
		// docker network ip cannot see those, so the allocator considers the
		// port free and hands it to the next deploy, whose children then die
		// "listen tcp 127.0.0.1:<port>: bind: address already in use" on a loop
		// while the previous container keeps serving. The port block belongs to
		// this service block, so any listener inside it is this block's however
		// it is bound.
		addv4("127.0.0.1")

		addv6 := func(ipv6 string) {
			r := regexp.MustCompile("(?m)^\\s*(?:tcp6|udp6)\\s+.*\\s+" + regexp.QuoteMeta(ipv6) + ":(\\d+)\\s+.*$")
			allGroups := r.FindAllSubmatch(out, -1)
			for _, groups := range allGroups {
				internalPort, err := strconv.Atoi(string(groups[1]))
				if err == nil {
					listenPorts[internalPort] = true
				}
			}
		}
		if ipv6 != "" {
			addv6(ipv6)
		}
		addv6("::")
		// see the loopback note above
		addv6("::1")

		for _, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if listenPorts[internalPort] {
					occupiedPorts[internalPort] = true
				}
			}
		}
		Err.Printf(
			"Socket discovery service=%s block=%s scanned=%d occupied_pool_ports=%d duration=%s\n",
			self.service,
			self.block,
			countNetstatSocketRows(out),
			len(occupiedPorts),
			time.Since(started).Round(time.Millisecond),
		)
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

func countNetstatSocketRows(out []byte) int {
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "tcp", "tcp6", "udp", "udp6":
			count++
		}
	}
	return count
}

// cleanupStaleConntrack deletes udp conntrack entries that pin client flows to
// internal ports in this block's pool that no longer have a listener.
//
// The DNAT decision for a flow is made once, when its conntrack entry is
// created; later packets are translated via the entry, not the current rules.
// That is what lets in-flight flows keep reaching the draining container after
// a deploy repoints the DNAT rules at the new internal port. But a udp client
// that never stops transmitting - e.g. a wireguard client with 25s persistent
// keepalives and 5s handshake retries - refreshes its entry faster than the
// conntrack udp timeout, so the entry outlives the drained container. From then
// on every packet is translated to a port nothing listens on and is dropped,
// while the client's own retries keep the dead entry alive: the tunnel can
// never recover until the client changes source port (i.e. the user restarts
// it). Deleting the stale entries breaks that cycle - the flow's next packet
// re-evaluates the DNAT rules, reaches the live container, and the client's
// normal re-handshake restores the tunnel.
//
// Deleting an entry whose target port has no listener is safe at any moment:
// such a flow is blackholed anyway.
func (self *RunWorker) cleanupStaleConntrack() {
	if !self.hostNetworking || self.portBlocks == nil {
		return
	}
	occupiedPorts, err := self.findOccupiedPorts()
	if err != nil {
		Err.Printf("Conntrack cleanup skipped (could not find occupied ports): %s\n", err)
		return
	}
	self.cleanupStaleConntrackForOccupiedPorts(occupiedPorts)
}

type conntrackCleanupStats struct {
	family         string
	scanned        int
	candidatePorts int
	stalePorts     int
	deletedFlows   int
	errors         []string
	duration       time.Duration
}

func conntrackCommandForEuid(euid int, args ...string) *exec.Cmd {
	if euid == 0 {
		return exec.Command("conntrack", args...)
	}
	return sudo("conntrack", args...)
}

func conntrackCommand(args ...string) *exec.Cmd {
	return conntrackCommandForEuid(os.Geteuid(), args...)
}

func quietCommandError(err error) string {
	// Do not return captured stdout/stderr: netstat and conntrack output can be
	// enormous and may contain unrelated host socket/flow details. The command's
	// exit error is sufficient for the aggregate failure signal.
	return err.Error()
}

func conntrackZeroResult(output commandOutput, operation string) bool {
	detail := string(output.stderr)
	return strings.Contains(detail, "0 flow entries have been "+operation)
}

// parseConntrackSaveReplyPorts parses conntrack's round-trippable `-o save`
// format. Each output line is one flow and contains the reply source port as a
// separate flag/value pair.
func parseConntrackSaveReplyPorts(out []byte) (map[int]int, int, error) {
	entryCountsByPort := map[int]int{}
	scanned := 0
	for lineNumber, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		scanned++
		replyPort := 0
		for i, field := range fields {
			if field != "--reply-port-src" || len(fields) <= i+1 {
				continue
			}
			port, err := strconv.Atoi(fields[i+1])
			if err != nil || port < 1 || 65535 < port {
				return nil, 0, fmt.Errorf(
					"invalid reply source port on conntrack output line %d",
					lineNumber+1,
				)
			}
			replyPort = port
			break
		}
		if replyPort == 0 {
			return nil, 0, fmt.Errorf(
				"missing reply source port on conntrack output line %d",
				lineNumber+1,
			)
		}
		entryCountsByPort[replyPort]++
	}
	return entryCountsByPort, scanned, nil
}

func (self *RunWorker) cleanupStaleConntrackForOccupiedPorts(occupiedPorts map[int]bool) []conntrackCleanupStats {
	candidatePorts := map[int]bool{}
	for _, internalPorts := range self.portBlocks.externalsToInternals {
		for _, internalPort := range internalPorts {
			if !occupiedPorts[internalPort] {
				candidatePorts[internalPort] = true
			}
		}
	}

	allStats := []conntrackCleanupStats{}
	for _, networkConfig := range self.getNetworkConfigs() {
		started := time.Now()
		family := "ipv4"
		if networkConfig.ipv6 {
			family = "ipv6"
		}
		stats := conntrackCleanupStats{
			family:         family,
			candidatePorts: len(candidatePorts),
		}
		// The docker network ip is the DNAT destination (see redirect), so a
		// filtered dump returns only flows translated through this interface.
		containerIp := networkConfig.dockerNetwork.interfaceIp
		listResult, listErr := runQuiet(conntrackCommand(
			"-L",
			"-f", family,
			"-p", "udp",
			"--reply-src", containerIp,
			"-o", "save",
		))
		if listErr != nil && !conntrackZeroResult(listResult, "shown") {
			stats.errors = append(stats.errors, "list: "+quietCommandError(listErr))
		} else {
			entryCountsByPort, scanned, parseErr := parseConntrackSaveReplyPorts(listResult.stdout)
			stats.scanned = scanned
			if parseErr != nil {
				stats.errors = append(stats.errors, "list parse: "+parseErr.Error())
			} else {
				stalePorts := []int{}
				for replyPort := range entryCountsByPort {
					if candidatePorts[replyPort] {
						stalePorts = append(stalePorts, replyPort)
					}
				}
				slices.Sort(stalePorts)
				stats.stalePorts = len(stalePorts)

				for _, stalePort := range stalePorts {
					deleteResult, deleteErr := runQuiet(conntrackCommand(
						"-D",
						"-f", family,
						"-p", "udp",
						"--reply-src", containerIp,
						"--reply-port-src", strconv.Itoa(stalePort),
						"-o", "save",
					))
					if deleteErr != nil {
						// A flow can expire between the list and delete operations.
						// conntrack reports that benign race as a nonzero exit.
						if !conntrackZeroResult(deleteResult, "deleted") {
							stats.errors = append(
								stats.errors,
								fmt.Sprintf(
									"delete port %d: %s",
									stalePort,
									quietCommandError(deleteErr),
								),
							)
						}
						continue
					}
					_, deletedFlows, parseErr := parseConntrackSaveReplyPorts(deleteResult.stdout)
					if parseErr != nil {
						stats.errors = append(
							stats.errors,
							fmt.Sprintf("delete port %d parse: %s", stalePort, parseErr),
						)
						continue
					}
					stats.deletedFlows += deletedFlows
				}
			}
		}

		stats.duration = time.Since(started)
		errorDetails := summarizeConntrackErrors(stats.errors)
		Err.Printf(
			"Conntrack cleanup service=%s block=%s family=%s scanned=%d candidate_ports=%d stale_ports=%d deleted_flows=%d errors=%d duration=%s%s\n",
			self.service,
			self.block,
			stats.family,
			stats.scanned,
			stats.candidatePorts,
			stats.stalePorts,
			stats.deletedFlows,
			len(stats.errors),
			stats.duration.Round(time.Millisecond),
			errorDetails,
		)
		allStats = append(allStats, stats)
	}
	return allStats
}

func summarizeConntrackErrors(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	detail := strings.Join(errors, "; ")
	const maxDetailBytes = 1024
	if maxDetailBytes < len(detail) {
		detail = detail[:maxDetailBytes] + "..."
	}
	return fmt.Sprintf(" error_details=%q", detail)
}

func (self *RunWorker) startContainer(servicePortsToInternalPort map[int]int) (string, error) {
	vaultMount := "/srv/warp/vault"
	configMount := "/srv/warp/config"
	siteMount := "/srv/warp/site"
	dataMount := "/srv/warp/data"

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
	imageDigest, err := inspectPulledImageDigest(imageName)
	if err != nil {
		return "", err
	}

	args := []string{
		"--label", fmt.Sprintf("%s-%s-%s", self.env, self.service, self.block),
		"--label", fmt.Sprintf("version=%s", convertVersionToDocker(self.deployedVersion.String())),
		// retain labels for container inventory; journald stream identity is set below
		"--label", fmt.Sprintf("warp.env=%s", self.env),
		"--label", fmt.Sprintf("warp.service=%s", self.service),
		"--label", fmt.Sprintf("warp.block=%s", self.block),
		"--label", fmt.Sprintf("warp.image_digest=%s", imageDigest),
		"--name", containerName,
		"-d",
		// see https://docs.docker.com/engine/containers/start-containers-automatically/
		// "--restart=unless-stopped",
		// see https://oneuptime.com/blog/post/2026-02-08-how-to-optimize-docker-for-high-throughput-applications
		"--cpu-period=0",
	}
	isolationArgs, err := containerIsolationArgs(self.service, self.capNetAdmin, self.containerUser, self.dockerMountMode)
	if err != nil {
		return "", err
	}
	args = append(args, isolationArgs...)

	args = append(args, []string{"--ulimit", fmt.Sprintf("nofile=%d:%d", 1024*1024, 1024*1024)}...)

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

	secretMountArgs, err := scopedSecretMountArgs(self.warpState.warpSettings.RequireVaultHome(), self.env, self.secretFiles)
	if err != nil {
		return "", err
	}
	args = append(args, secretMountArgs...)

	switch self.dataMountMode {
	case MOUNT_MODE_YES:
		// a persistent docker volume that survives redeploys,
		// shared by all blocks of the service on this host
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=volume,source=warp-%s-%s-data,target=%s",
				self.env,
				self.service,
				dataMount,
			),
		}...)
	}

	env := map[string]string{
		"WARP_VERSION":      self.deployedVersion.String(),
		"WARP_ENV":          self.env,
		"WARP_SERVICE":      self.service,
		"WARP_DOMAIN":       self.domain,
		"WARP_BLOCK":        self.block,
		"WARP_IMAGE_DIGEST": imageDigest,
	}
	if host, err := os.Hostname(); err == nil {
		env["WARP_HOST"] = host
	}
	if 0 < self.memoryLimit {
		// use 90% as a soft limit
		softMemoryLimit := (self.memoryLimit * 9) / 10
		env["GOMEMLIMIT"] = fmt.Sprintf("%dB", softMemoryLimit)
	}
	if 0 < self.coreLimit {
		env["GOMAXPROCS"] = fmt.Sprintf("%d", self.coreLimit)
	}
	if self.limitExcludeSubnets != "" {
		env["WARP_LIMIT_EXCLUDE_SUBNETS"] = self.limitExcludeSubnets
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

		if 0 < self.fwMark {
			env["WARP_FWMARK"] = strconv.Itoa(self.fwMark)
		}
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
	if self.dataMountMode != MOUNT_MODE_NO {
		env["WARP_DATA"] = dataMount
	}
	// add the user env vars
	for key, value := range self.envVars {
		env[key] = value
	}
	for name, value := range env {
		args = append(args, []string{"-e", fmt.Sprintf("%s=%s", name, value)}...)
	}

	// Host-managed Fluent Bit reads the journal without exposing the Docker API
	// to a workload container. The stable tag preserves stream labels.
	args = append(args, containerLogArgs(self.env, self.service, self.block)...)

	// constraint args
	// https://docs.docker.com/engine/containers/resource_constraints/
	if 0 < self.memoryLimit {
		args = append(args, []string{
			"-m", fmt.Sprintf("%db", self.memoryLimit),
			"--oom-kill-disable",
		}...)
	}

	// Execute the inspected id. A concurrent pull may move imageName, but it
	// cannot change the content selected for this container.
	args = append(args, imageDigest)

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
		return errors.New("Could not poll status (quit)")
	}
}

func (self *RunWorker) pollBasicContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	httpPort, ok := servicePortsToInternalPort[80]
	if !ok {
		// no http port - assume ok
		return nil
	}

	// services may need to warm up before exposing a status
	statusTimeout := 60 * time.Second
	dialer := &net.Dialer{
		Timeout: statusTimeout,
	}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: statusTimeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   statusTimeout,
	}

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
		defer statusResponse.Body.Close()
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
	return errors.New("Could not poll container status (quit)")
}

func pollConnectListenerStatus(
	client *http.Client,
	statusUrl string,
	host string,
	requiredUdpPorts []int,
) error {
	statusRequest, err := http.NewRequest("GET", statusUrl, nil)
	if err != nil {
		return err
	}
	statusRequest.Host = host
	statusResponse, err := client.Do(statusRequest)
	if err != nil {
		return err
	}
	defer statusResponse.Body.Close()
	body, err := io.ReadAll(io.LimitReader(statusResponse.Body, 1<<20))
	if err != nil {
		return err
	}
	if statusResponse.StatusCode < 200 || 300 <= statusResponse.StatusCode {
		return fmt.Errorf("status %d: %s", statusResponse.StatusCode, strings.TrimSpace(string(body)))
	}
	if statusResponse.Header.Get(connectListenersReadyHeader) != "1" {
		return fmt.Errorf("missing %s=1", connectListenersReadyHeader)
	}
	readyUdpPorts := map[int]bool{}
	readyUdpPortsHeader := statusResponse.Header.Get(connectUdpListenersHeader)
	for _, portString := range strings.Split(readyUdpPortsHeader, ",") {
		if portString == "" {
			continue
		}
		port, err := strconv.Atoi(portString)
		if err != nil || port < 1 || 65535 < port {
			return fmt.Errorf("invalid %s=%q", connectUdpListenersHeader, readyUdpPortsHeader)
		}
		readyUdpPorts[port] = true
	}
	for _, port := range requiredUdpPorts {
		if !readyUdpPorts[port] {
			return fmt.Errorf(
				"%s=%q does not include required UDP/%d",
				connectUdpListenersHeader,
				readyUdpPortsHeader,
				port,
			)
		}
	}
	var warpStatusResponse WarpStatusResponse
	if err := json.Unmarshal(body, &warpStatusResponse); err != nil {
		return err
	}
	if warpStatusResponse.IsError() {
		return errors.New(warpStatusResponse.Status)
	}
	return nil
}

// Before an LB with a UDP forward alias activates, require the explicit
// dynamic listener-ready signal from every Connect block. Direct block ports
// avoid random LB sampling, and the required response header prevents an old
// constant-ok Connect image from authorizing a new transport mapping.
func (self *RunWorker) pollConnectTransportReadiness(timeout time.Duration) error {
	if self.service != "lb" || len(self.forwardPorts["udp"]) == 0 {
		return nil
	}
	if self.servicesDockerNetwork == nil || self.servicesDockerNetwork.ipv4 == nil {
		return errors.New("Connect transport readiness requires the services IPv4 network")
	}

	allPortBlocks := getPortBlocks(self.env)
	connectBlocks := allPortBlocks[""]["connect"]
	if len(connectBlocks) == 0 {
		return errors.New("Connect transport readiness found no Connect blocks")
	}
	blocks := make([]string, 0, len(connectBlocks))
	for block := range connectBlocks {
		blocks = append(blocks, block)
	}
	slices.Sort(blocks)

	type statusTarget struct {
		block            string
		url              string
		requiredUdpPorts []int
	}
	targets := make([]statusTarget, 0, len(blocks))
	for _, block := range blocks {
		portBlock, ok := connectBlocks[block][80]
		if !ok || portBlock.externalPort == 0 {
			return fmt.Errorf("Connect block %s has no HTTP status allocation", block)
		}
		requiredUdpPorts := map[int]bool{}
		// Forward aliases are the exact ports the replacement LB is about
		// to expose. Include them even if the host's checked-out service
		// config is stale relative to its generated unit.
		for _, servicePort := range self.forwardPorts["udp"] {
			requiredUdpPorts[servicePort] = true
		}
		// Also require every current UDP stream allocation for this Connect
		// block, including UDP/443 and any compatibility listener.
		for servicePort, connectPortBlock := range connectBlocks[block] {
			if connectPortBlock.externalPortTypes["udp"] && connectPortBlock.lbTypes["udp"] == "stream" {
				requiredUdpPorts[servicePort] = true
			}
		}
		requiredUdpPortList := maps.Keys(requiredUdpPorts)
		slices.Sort(requiredUdpPortList)
		targets = append(targets, statusTarget{
			block: block,
			url: fmt.Sprintf(
				"http://%s/status",
				net.JoinHostPort(
					self.servicesDockerNetwork.ipv4.interfaceIp,
					strconv.Itoa(portBlock.externalPort),
				),
			),
			requiredUdpPorts: requiredUdpPortList,
		})
	}

	requestTimeout := min(5*time.Second, timeout)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: requestTimeout}).DialContext,
		},
		Timeout: requestTimeout,
	}
	host := fmt.Sprintf("%s-connect.%s", self.env, self.domain)
	endTime := time.Now().Add(timeout)
	var lastErr error
	for !self.quitEvent.IsSet() {
		allReady := true
		for _, target := range targets {
			Err.Printf("Poll Connect listener readiness %s %s\n", target.block, target.url)
			if err := pollConnectListenerStatus(client, target.url, host, target.requiredUdpPorts); err != nil {
				allReady = false
				lastErr = fmt.Errorf("Connect block %s not listener-ready: %w", target.block, err)
				Err.Printf("%s\n", lastErr)
			}
		}
		if allReady {
			return nil
		}
		if time.Now().After(endTime) {
			return lastErr
		}
		self.quitEvent.WaitForSet(WarpPollTimeout)
	}
	return errors.New("Could not poll Connect transport readiness (quit)")
}

// note "internal port" is also called "host port" in other parts of warp
func (self *RunWorker) validateRedirectPortOwnership(
	externalPortsToInternalPort map[int]int,
) error {
	if !self.hostNetworking {
		return nil
	}
	desiredPorts := map[int]bool{}
	for externalPort, internalPort := range externalPortsToInternalPort {
		desiredPorts[externalPort] = true
		desiredPorts[internalPort] = true
	}
	chainName := self.iptablesChainName()
	chainHeader := regexp.MustCompile(`^Chain\s+(\S+)\s+`)
	dnatPort := regexp.MustCompile(`\b(?:tcp|udp)\s+dpt:(\d+)\b`)
	warpChainPrefix := fmt.Sprintf("WARP-%s-", strings.ToUpper(self.env))

	for _, networkConfig := range self.getNetworkConfigs() {
		out, err := sudo2(
			networkConfig.iptablesCommand,
			"-t", "nat", "-L", "-n",
		).Output()
		if err != nil {
			return fmt.Errorf("inspect %s NAT ownership: %w", networkConfig.iptablesCommand[0], err)
		}
		currentChain := ""
		for _, line := range strings.Split(string(out), "\n") {
			if groups := chainHeader.FindStringSubmatch(line); groups != nil {
				currentChain = groups[1]
				continue
			}
			if currentChain == chainName || !strings.HasPrefix(currentChain, warpChainPrefix) {
				continue
			}
			groups := dnatPort.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			port, err := strconv.Atoi(groups[1])
			if err != nil || !desiredPorts[port] {
				continue
			}
			return fmt.Errorf(
				"refusing redirect: port %d is still owned by %s (wanted by %s)",
				port,
				currentChain,
				chainName,
			)
		}
	}
	return nil
}

// configuredRedirectPorts is the complete set of logical and per-generation
// host ports owned by the block's current allocation. Ports omitted from this
// set are from a withdrawn allocation and can be removed from the block's own
// chain. Keep every allocated internal port, not just the one selected for the
// new deployment, because an older container may still be draining on it.
func (self *RunWorker) configuredRedirectPorts(
	externalPortsToInternalPort map[int]int,
) map[int]bool {
	configuredPorts := map[int]bool{}
	for externalPort, internalPort := range externalPortsToInternalPort {
		configuredPorts[externalPort] = true
		configuredPorts[internalPort] = true
	}
	if self.portBlocks != nil {
		for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
			configuredPorts[externalPort] = true
			for _, internalPort := range internalPorts {
				configuredPorts[internalPort] = true
			}
		}
	}
	return configuredPorts
}

func (self *RunWorker) redirect(
	externalPortsToInternalPort map[int]int,
	servicePortsToInternalPort map[int]int,
	deployedContainerId string,
) error {
	for protocol, protocolForwardPorts := range self.forwardPorts {
		for publicPort := range protocolForwardPorts {
			if _, conflict := externalPortsToInternalPort[publicPort]; conflict {
				panic(fmt.Errorf("%s forward port %d conflicts with an active external port", protocol, publicPort))
			}
		}
	}
	if err := self.validateRedirectPortOwnership(externalPortsToInternalPort); err != nil {
		return err
	}

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
				// use SNAT for udp
				// - map internal port to external ip:port instead of masquerade

				// dnat
				func() {
					existingPortsToInternalPorts := map[int]map[int]bool{}
					// Capture the pre-DNAT destination as well as the dport. Only
					// unscoped rules belong to the deployment-port pool. Public LB
					// aliases share this chain but are scoped to an interface IP and
					// are reconciled separately below.
					dnatRegex := regexp.MustCompile(
						"^\\s*DNAT\\s+\\S+\\s+(?:--\\s+)?\\S+\\s+(\\S+)\\s+" + protocol +
							"\\s+dpt:(\\d+)\\s+to:\\s*(\\S+)\\s*$",
					)
					if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
						/*
						   Chain WARP-MAIN-LB-ENO2 (2 references)
						   target     prot opt source               destination
						   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::3]:443
						   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:80 to:[fd00:f1a4:349b:bc6e::3]:80
						*/
						for _, line := range strings.Split(string(out), "\n") {
							if groups := dnatRegex.FindStringSubmatch(line); groups != nil {
								wildcardDestination := "0.0.0.0/0"
								if networkConfig.ipv6 {
									wildcardDestination = "::/0"
								}
								if groups[1] != wildcardDestination {
									continue
								}
								destination := groups[3]

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
										port, err := strconv.Atoi(groups[2])
										if err != nil {
											Err.Printf("Invalid DNAT port, skipping: %s\n", groups[2])
											continue
										}
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
							"-p", protocol, "--dport", strconv.Itoa(externalPort),
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
					// Remove rules left by ports that disappeared from this block's
					// allocation. Previously Warp only updated ports that still
					// existed, so withdrawn Grafana rules could permanently steal a
					// port later allocated to Connect.
					configuredPorts := self.configuredRedirectPorts(externalPortsToInternalPort)
					for existingPort, existingInternalPorts := range existingPortsToInternalPorts {
						if configuredPorts[existingPort] {
							continue
						}
						for existingInternalPort := range existingInternalPorts {
							for {
								cmd := redirectCmd("-D", existingPort, existingInternalPort)
								if err := runAndLog(cmd); err != nil {
									break
								}
							}
						}
					}
				}()

				// FIXME detect and clean up
				// A Docker network can have IPv6 even when this public interface
				// has no IPv6 routing table. SNAT is meaningful only for a family
				// that has both sides; checking self.routingTable here used to enter
				// this branch for that IPv6 NetworkConfig and dereference its nil
				// routingTable after IPv6 DNAT had already been changed.
				if protocol == "udp" && networkConfig.routingTable != nil {

					// for externalPort, internalPort := range externalPortsToInternalPort {
					// 	runAndLog(sudo2(
					// 		networkConfig.iptablesCommand, "-t", "nat", "-I", "POSTROUTING",
					// 		"-p", protocol, "--sport", strconv.Itoa(internalPort),
					// 		"-j", "SNAT", "--to-source", fmt.Sprintf(":%d", externalPort),
					// 	))
					// }

					// snat
					func() {

						// Unlike the DNAT rules (which live in this block's own chain),
						// these SNAT rules share the global POSTROUTING chain with every
						// other service block on this host, and they all SNAT to the same
						// interface ip. Scope the parse to the internal ports this block
						// owns so `existingPortsToExternalPorts` only ever holds this
						// block's rules — otherwise cleanup below would delete other
						// blocks' active rules, dropping the source rewrite on their udp
						// return path (e.g. wg replies leave with the wrong source port
						// and the client silently drops the handshake).
						blockInternalPorts := map[int]bool{}
						if self.portBlocks != nil {
							for _, internalPorts := range self.portBlocks.externalsToInternals {
								for _, internalPort := range internalPorts {
									blockInternalPorts[internalPort] = true
								}
							}
						}

						existingPortsToExternalPorts := map[int]map[int]bool{}
						snatRegex := regexp.MustCompile("^\\s*SNAT\\s+.*\\s+" + protocol + "\\s+spt:(\\d+)\\s+to:\\s*(\\S+)\\s*$")
						if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", "POSTROUTING", "-n").Output(); err == nil {
							/*
								Chain POSTROUTING (policy ACCEPT)
								target     prot opt source               destination
								SNAT       17   --  0.0.0.0/0            0.0.0.0/0            udp spt:14368 to::7172
								SNAT       17   --  0.0.0.0/0            0.0.0.0/0            udp spt:14338 to::7171
							*/
							for _, line := range strings.Split(string(out), "\n") {
								if groups := snatRegex.FindStringSubmatch(line); groups != nil {
									source := groups[2]

									sourceAddrPort, err := netip.ParseAddrPort(source)
									if err != nil {
										Err.Printf("Invalid SNAT redirect source, skipping: %s", source)
									} else {
										switch sourceAddrPort.Addr().String() {
										case networkConfig.routingTable.interfaceIp:
											port, err := strconv.Atoi(groups[1])
											if err != nil {
												Err.Printf("Invalid SNAT port, skipping: %s\n", groups[1])
												continue
											}
											if !blockInternalPorts[port] {
												// another service block's rule (shared POSTROUTING chain)
												continue
											}
											externalPort := int(sourceAddrPort.Port())
											externalPorts, ok := existingPortsToExternalPorts[port]
											if !ok {
												externalPorts = map[int]bool{}
												existingPortsToExternalPorts[port] = externalPorts
											}
											externalPorts[externalPort] = true
										}
									}
								}
							}
						}

						for port, externalPorts := range existingPortsToExternalPorts {
							for externalPort, _ := range externalPorts {
								Err.Printf("Found existing source redirect: %d->%d\n", port, externalPort)
							}
						}

						sourceRedirectCmd := func(op string, externalPort int, internalPort int) *exec.Cmd {
							return sudo2(
								networkConfig.iptablesCommand, "-t", "nat", op, "POSTROUTING",
								"-o", networkConfig.routingTable.interfaceName,
								"-p", protocol, "--sport", strconv.Itoa(internalPort),
								"-j", "SNAT", "--to-source", net.JoinHostPort(networkConfig.routingTable.interfaceIp, strconv.Itoa(externalPort)),
							)
						}

						for externalPort, internalPort := range externalPortsToInternalPort {
							if err := runAndLog(sourceRedirectCmd("-C", externalPort, internalPort)); err != nil {
								if err := runAndLog(sourceRedirectCmd("-I", externalPort, internalPort)); err != nil {
									panic(err)
								}
							}
						}
						// remove existing with changed external port
						for externalPort, internalPort := range externalPortsToInternalPort {
							if existingExternalPorts, ok := existingPortsToExternalPorts[internalPort]; ok {
								for existingExternalPort, _ := range existingExternalPorts {
									if externalPort != existingExternalPort {
										for {
											cmd := sourceRedirectCmd("-D", existingExternalPort, internalPort)
											if err := runAndLog(cmd); err != nil {
												break
											}
										}
									}
								}
							}
						}
						// remove stale rules for internal ports no longer in use.
						// `existingPortsToExternalPorts` is already scoped to this block's
						// internal ports (see the parse above), so this never touches
						// another block's rules in the shared POSTROUTING chain.
						activeInternalPorts := map[int]bool{}
						for _, internalPort := range externalPortsToInternalPort {
							activeInternalPorts[internalPort] = true
						}
						for existingInternalPort, existingExternalPorts := range existingPortsToExternalPorts {
							if activeInternalPorts[existingInternalPort] {
								continue
							}
							for existingExternalPort, _ := range existingExternalPorts {
								for {
									cmd := sourceRedirectCmd("-D", existingExternalPort, existingInternalPort)
									if err := runAndLog(cmd); err != nil {
										break
									}
								}
							}
						}
					}()
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
							port, err := strconv.Atoi(groups[1])
							if err != nil {
								Err.Printf("Invalid REDIRECT port, skipping: %s\n", groups[1])
								continue
							}
							internalPort, err := strconv.Atoi(groups[2])
							if err != nil {
								Err.Printf("Invalid REDIRECT internal port, skipping: %s\n", groups[2])
								continue
							}
							internalPorts, ok := existingPortsToInternalPorts[port]
							if !ok {
								internalPorts = map[int]bool{}
								existingPortsToInternalPorts[port] = internalPorts
							}
							internalPorts[internalPort] = true
						}
					}
				}

				Err.Printf("Existing redirects %v\n", existingPortsToInternalPorts)

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
				configuredPorts := self.configuredRedirectPorts(externalPortsToInternalPort)
				for existingPort, existingInternalPorts := range existingPortsToInternalPorts {
					if configuredPorts[existingPort] {
						continue
					}
					for existingInternalPort := range existingInternalPorts {
						for {
							cmd := redirectCmd("-D", existingPort, existingInternalPort)
							if err := runAndLog(cmd); err != nil {
								break
							}
						}
					}
				}
			}

			if self.service == "lb" && networkConfig.routingTable != nil {
				existingPortsToDestinations := map[int]map[string]bool{}
				// Parse only rules scoped to this interface address. Unscoped
				// deployment-pool DNATs share the block chain and must not be
				// mistaken for stale public aliases during reconciliation.
				dnatRegex := regexp.MustCompile(
					"^\\s*DNAT\\s+\\S+\\s+--\\s+\\S+\\s+(\\S+)\\s+" + protocol +
						"\\s+dpt:(\\d+)\\s+to:\\s*(\\S+)\\s*$",
				)
				if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
					/*
					   Chain WARP-MAIN-LB-ENO2 (2 references)
					   target     prot opt source               destination
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::3]:443
					   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:80 to:[fd00:f1a4:349b:bc6e::3]:80
					*/
					for _, line := range strings.Split(string(out), "\n") {
						if groups := dnatRegex.FindStringSubmatch(line); groups != nil {
							if !iptablesDestinationMatchesInterface(groups[1], networkConfig.routingTable.interfaceIp) {
								continue
							}
							publicPort, err := strconv.Atoi(groups[2])
							if err != nil {
								Err.Printf("Invalid DNAT lb port, skipping: %s\n", groups[2])
								continue
							}
							destination := groups[3]
							if _, err := netip.ParseAddrPort(destination); err != nil {
								Err.Printf("Invalid DNAT destination, skipping: %s", destination)
								continue
							}
							destinations, ok := existingPortsToDestinations[publicPort]
							if !ok {
								destinations = map[string]bool{}
								existingPortsToDestinations[publicPort] = destinations
							}
							destinations[destination] = true
						}
					}
				}

				Err.Printf("Existing destinations %v\n", existingPortsToDestinations)

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

				// Redirect traffic addressed to one exact interface and public
				// port. This preserves the original source tuple for NGINX PPv2.
				publicRedirectCmd := func(op string, publicPort int, destination string) *exec.Cmd {
					// use dnat to the container ip and service port to work around the docker issue of masking the remote ip
					// https://github.com/docker/docs/issues/17312

					return sudo2(
						networkConfig.iptablesCommand, "-t", "nat", op, chainName,
						"-p", protocol, "-m", protocol, "-d", networkConfig.routingTable.interfaceIp, "--dport", strconv.Itoa(publicPort),
						"-j", "DNAT", "--to-destination", destination,
					)
				}
				publicPortTargets, err := publicPortServiceTargets(
					protocol,
					servicePortsToInternalPort,
					self.forwardPorts,
					self.privateServicePorts,
					networkConfig.ipv6,
				)
				if err != nil {
					panic(err)
				}
				desiredDestinations := map[int]string{}
				for publicPort, servicePort := range publicPortTargets {
					// do not add if already exists
					destination := containerDestination(servicePort)
					desiredDestinations[publicPort] = destination
					if err := runAndLog(publicRedirectCmd("-C", publicPort, destination)); err != nil {
						if err := runAndLog(publicRedirectCmd("-I", publicPort, destination)); err != nil {
							panic(err)
						}
					}
				}

				// Remove every stale public rule owned by this interface chain,
				// including a withdrawn forward alias and the formerly direct
				// target port. New rules are inserted first for atomic rollout.
				for publicPort, existingDestinationsMap := range existingPortsToDestinations {
					desiredDestination := desiredDestinations[publicPort]
					for existingDestination := range existingDestinationsMap {
						if desiredDestination != existingDestination {
							for {
								cmd := publicRedirectCmd("-D", publicPort, existingDestination)
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

	return nil
}

// Builds the public-interface port to LB-service-port map. Any current forward
// target or rolling private port becomes forward-only. The extra private set
// preserves that property for the previous alias target while old LBs drain
// (for example, both 4053 and 8053 stay private while IPv4 UDP/53 moves between
// them). Forward aliases are deliberately absent on IPv6 under the current
// product policy, but their targets remain private there as well.
func publicPortServiceTargets(
	protocol string,
	servicePortsToInternalPort map[int]int,
	forwardPorts map[string]map[int]int,
	privateServicePorts map[int]bool,
	ipv6 bool,
) (map[int]int, error) {
	forwardTargets := map[int]bool{}
	for servicePort := range privateServicePorts {
		if servicePort < 1 || 65535 < servicePort {
			return nil, fmt.Errorf("invalid private service port %d", servicePort)
		}
		if _, ok := servicePortsToInternalPort[servicePort]; !ok {
			return nil, fmt.Errorf("private service port %d is not active on the lb", servicePort)
		}
		forwardTargets[servicePort] = true
	}
	for configuredProtocol, protocolForwardPorts := range forwardPorts {
		if configuredProtocol != "tcp" && configuredProtocol != "udp" {
			return nil, fmt.Errorf("invalid forward protocol %q", configuredProtocol)
		}
		for publicPort, servicePort := range protocolForwardPorts {
			if publicPort < 1 || 65535 < publicPort || servicePort < 1 || 65535 < servicePort {
				return nil, fmt.Errorf("invalid %s forward %d->%d", configuredProtocol, publicPort, servicePort)
			}
			if publicPort == servicePort {
				return nil, fmt.Errorf("identity %s forward %d->%d", configuredProtocol, publicPort, servicePort)
			}
			if _, chained := protocolForwardPorts[servicePort]; chained {
				return nil, fmt.Errorf("chained %s forward %d->%d", configuredProtocol, publicPort, servicePort)
			}
			forwardTargets[servicePort] = true
		}
	}

	publicTargets := map[int]int{}
	for servicePort := range servicePortsToInternalPort {
		if !forwardTargets[servicePort] {
			publicTargets[servicePort] = servicePort
		}
	}
	if ipv6 {
		return publicTargets, nil
	}

	for publicPort, servicePort := range forwardPorts[protocol] {
		if _, ok := servicePortsToInternalPort[servicePort]; !ok {
			return nil, fmt.Errorf("%s forward %d->%d targets an inactive lb service port", protocol, publicPort, servicePort)
		}
		if directServicePort, conflict := publicTargets[publicPort]; conflict {
			return nil, fmt.Errorf("%s forward %d->%d conflicts with direct service port %d", protocol, publicPort, servicePort, directServicePort)
		}
		publicTargets[publicPort] = servicePort
	}
	return publicTargets, nil
}

func iptablesDestinationMatchesInterface(destination string, interfaceIp string) bool {
	want, err := netip.ParseAddr(interfaceIp)
	if err != nil {
		return false
	}
	if destinationAddr, err := netip.ParseAddr(destination); err == nil {
		return destinationAddr == want
	}
	if destinationPrefix, err := netip.ParsePrefix(destination); err == nil {
		return destinationPrefix.Bits() == want.BitLen() && destinationPrefix.Addr() == want
	}
	return false
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
	ContainerId string           `json:"Id"`
	HostConfig  *HostConfig      `json:"HostConfig"`
	Config      *ContainerConfig `json:"Config"`
}

type ContainerConfig struct {
	Env []string `json:"Env"`
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

func newForwardPorts() map[string]map[int]int {
	return map[string]map[int]int{
		"tcp": {},
		"udp": {},
	}
}

// parseForwardPorts parses protocol:public:service aliases. The production
// generator emits a sorted, validated string, but the runtime rejects malformed
// hand-written units too rather than constructing an unexpectedly broad rule.
func parseForwardPorts(forwardPortsStr string) map[string]map[int]int {
	forwardPorts := newForwardPorts()
	if forwardPortsStr == "" {
		return forwardPorts
	}
	for _, forwardPortStr := range strings.Split(forwardPortsStr, ";") {
		parts := strings.Split(forwardPortStr, ":")
		if len(parts) != 3 {
			panic(fmt.Sprintf("Forward port must be protocol:publicport:serviceport (%s)", forwardPortStr))
		}
		protocol := parts[0]
		protocolPorts, ok := forwardPorts[protocol]
		if !ok {
			panic(fmt.Sprintf("Forward port protocol must be tcp or udp (%s)", protocol))
		}
		publicPort, err := strconv.Atoi(parts[1])
		if err != nil || publicPort < 1 || 65535 < publicPort {
			panic(fmt.Sprintf("Forward public port must be in 1..65535 (%s)", parts[1]))
		}
		servicePort, err := strconv.Atoi(parts[2])
		if err != nil || servicePort < 1 || 65535 < servicePort {
			panic(fmt.Sprintf("Forward service port must be in 1..65535 (%s)", parts[2]))
		}
		if _, duplicate := protocolPorts[publicPort]; duplicate {
			panic(fmt.Sprintf("Forward port repeats %s/%d", protocol, publicPort))
		}
		protocolPorts[publicPort] = servicePort
	}
	return forwardPorts
}

// Parses a comma-separated port specification for compatibility listeners
// that must remain private while the preceding LB generation drains.
func parsePrivatePorts(privatePortsStr string) map[int]bool {
	privateServicePorts := map[int]bool{}
	if privatePortsStr == "" {
		return privateServicePorts
	}
	ports, err := expandPorts(privatePortsStr)
	if err != nil {
		panic(fmt.Sprintf("Invalid private ports (%s): %s", privatePortsStr, err))
	}
	for _, port := range ports {
		if port < 1 || 65535 < port {
			panic(fmt.Sprintf("Private port must be in 1..65535 (%d)", port))
		}
		if privateServicePorts[port] {
			panic(fmt.Sprintf("Private port repeats %d", port))
		}
		privateServicePorts[port] = true
	}
	return privateServicePorts
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
