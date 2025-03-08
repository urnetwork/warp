package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	// "os/signal"

	"github.com/urnetwork/warp/warpctl/dynamo"
	"golang.org/x/exp/maps"

	"github.com/coreos/go-semver/semver"
)

const WarpPollTimeout = 5 * time.Second
const KillTimeout = 15 * time.Second

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
	warpState       *WarpState
	dockerHubClient *DockerHubClient
	dynamoClient    *dynamo.Client

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

	envVars map[string]string

	deployedVersion       *semver.Version
	deployedConfigVersion *semver.Version

	quitEvent *Event
}

func (self *RunWorker) Run() {
	// on start, deploy the latest version and start the watcher loop

	self.quitEvent = NewEvent()

	closeFn := self.quitEvent.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer closeFn()

	announceRunEnter()
	defer announceRunExit()

	initNetwork := func() {
		// enable policy routing
		self.initRoutingTable()
		self.initBlockRedirect()
	}

	self.deployedVersion = nil
	self.deployedConfigVersion = nil

	// watch for new versions until killed
	for !self.quitEvent.IsSet() {
		// continually init the network to account for linux system changes
		// e.g. netplan resetting all the ip rules
		initNetwork()

		latestVersion, latestConfigVersion, err := self.getLatestVersion()
		if err != nil || latestVersion == nil {
			// the token might have expired. Try to login again.
			self.dockerHubClient.Login()
			latestVersion, latestConfigVersion, err = self.getLatestVersion()
		}

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
					return false
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
					return false
				}
			}()
		}

		if deployable {
			// deploy new version
			self.deployedVersion = latestVersion
			self.deployedConfigVersion = latestConfigVersion

			Err.Printf("Deploy version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
			func() {
				announceRunStart()
				// do not recover() errors from `deploy()`
				// the expected behavior on error is to exit the run worker
				// the control launcher should restart the run worker
				err := self.deploy()
				if err != nil {
					Err.Printf("Deploy fail version=%s, configVersion=%s: %s\n", self.deployedVersion, self.deployedConfigVersion, err)
					announceRunFail()
					// at this point, the previous version is still running
				} else {
					Err.Printf("Deploy success version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
					announceRunSuccess()
				}
			}()
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

// service version, config version
func (self *RunWorker) getLatestVersion() (latestVersion *semver.Version, latestConfigVersion *semver.Version, returnErr error) {

	v, err := self.dynamoClient.GetLatestVersion(context.Background(), self.env, self.service, self.block)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get latest version: %w", err)
	}

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
		Err.Printf("TEST CONFIG ENTRY %s\n", entry.Name())
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

func (self *RunWorker) getNetworkConfigs() []*NetworkConfig {
	return getNetworkConfigs(self.routingTable, self.dockerNetwork)
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
	externalPortsToInternalPort, servicePortsToInternalPort := self.waitForDeployPorts()
	Err.Printf(
		"Ports %s, %s\n",
		mapStr(externalPortsToInternalPort),
		mapStr(servicePortsToInternalPort),
	)

	deployedContainerId, err := self.startContainer(servicePortsToInternalPort)
	if err != nil {
		Err.Printf("Start container failed: %s\n", err)
		return err
	}
	success := false
	defer func() {
		if !success && deployedContainerId != "" {
			go NewKillWorker(deployedContainerId).Run()
		}
	}()

	if err := self.pollContainerStatus(servicePortsToInternalPort, 30*time.Second); err != nil {
		return err
	}

	runningContainers, err := self.findRunningContainers()
	if err != nil {
		return err
	}
	// verify the internal ports
	for _, internalPort := range servicePortsToInternalPort {
		if containerId, ok := runningContainers[internalPort]; !ok || deployedContainerId != containerId {
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
	Err.Printf("Found overlapping containers %s\n", strings.Join(maps.Keys(containerIds), ", "))
	for containerId, _ := range containerIds {
		if containerId != deployedContainerId {
			go NewKillWorker(containerId).Run()
		}
	}

	self.redirect(externalPortsToInternalPort, servicePortsToInternalPort, deployedContainerId)
	success = true
	return nil
}

func (self *RunWorker) waitForDeployPorts() (map[int]int, map[int]int) {
	for !self.quitEvent.IsSet() {
		externalPortsToInternalPort := map[int]int{}

		runningContainers, err := self.findRunningContainers()
		if err != nil {
			panic(err)
		}
		for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if _, ok := runningContainers[internalPort]; !ok {
					externalPortsToInternalPort[externalPort] = internalPort
					break
				}
			}
		}

		if len(externalPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
			self.quitEvent.WaitForSet(5 * time.Second)
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
		"--restart=on-failure",
	}
	for servicePort, internalPort := range servicePortsToInternalPort {
		// docker by default accepts connections on both IPv4 and IPv6
		args = append(args, []string{"-p", fmt.Sprintf("%d:%d", internalPort, servicePort)}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--network", self.dockerNetwork.networkName}...)
	} else {
		args = append(args, []string{"--network", self.servicesDockerNetwork.networkName}...)
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

	args = append(args, imageName)
	if self.service == "lb" {
		// the lb expects the path of the config to be given as an arg
		// TODO ideally this could be handled with an env var in the docker image,
		// TODO but unfortunately docker does not allow env vars in the command
		args = append(args, fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", self.block))
	} else {
		args = append(args, self.runArgs...)
	}

	runCmd := docker("run", args...)

	out, err := outAndLog(runCmd)
	// `docker run` prints the container_id as the only output
	containerId := strings.TrimSpace(string(out))

	if err != nil {
		return containerId, err
	}

	if self.dockerNetwork != nil {
		// connect to the services network
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
		statusUrl := fmt.Sprintf("http://127.0.0.1:%d%s/status", httpPort, routePrefix)
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
		self.quitEvent.WaitForSet(5 * time.Second)
	}
	panic("Could not poll container status.")
}

func (self *RunWorker) redirect(
	externalPortsToInternalPort map[int]int,
	servicePortsToInternalPort map[int]int,
	deployedContainerId string,
) {
	chainName := self.iptablesChainName()

	var containerIpv4 string
	if out, err := sudo2(
		[]string{"docker"},
		"inspect",
		"-f",
		"{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		deployedContainerId,
	).Output(); err == nil {
		containerIpv4 = strings.TrimSpace(string(out))
	}

	var containerIpv6 string
	if out, err := sudo2(
		[]string{"docker"},
		"inspect",
		"-f",
		"{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}",
		deployedContainerId,
	).Output(); err == nil {
		containerIpv6 = strings.TrimSpace(string(out))
	}

	Err.Printf("Container ipv4='%s', ipv6='%s'\n", containerIpv4, containerIpv6)

	for _, networkConfig := range self.getNetworkConfigs() {
		// find existing redirects and remove those for the owned external ports
		existingPortsToInternalPorts := map[int]map[int]bool{}
		redirectRegex := regexp.MustCompile("^\\s*REDIRECT\\s+.*\\s+tcp\\s+dpt:(\\d+)\\s+redir\\s+ports\\s+(\\d+)\\s*$")
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
				"-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(externalPort),
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

		if networkConfig.routingTable != nil {
			existingPortsToDestinations := map[int]map[string]bool{}
			dnatRegex := regexp.MustCompile("^\\s*DNAT\\s+.*\\s+tcp\\s+dpt:(\\d+)\\s+to:\\s*(\\S+)\\s*$")
			if out, err := sudo2(networkConfig.iptablesCommand, "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
				/*
				   Chain WARP-MAIN-LB-ENO2 (2 references)
				   target     prot opt source               destination
				   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::3]:443
				   DNAT       tcp      ::/0                 2001:470:173:52:e643:4bff:fe23:a341  tcp dpt:80 to:[fd00:f1a4:349b:bc6e::3]:80
				*/
				for _, line := range strings.Split(string(out), "\n") {
					if groups := dnatRegex.FindStringSubmatch(line); groups != nil {
						port, _ := strconv.Atoi(groups[1])
						destination := groups[2]
						destinations, ok := existingPortsToDestinations[port]
						if !ok {
							destinations = map[string]bool{}
							existingPortsToDestinations[port] = destinations
						}
						destinations[destination] = true
					}
				}
			}

			Err.Printf("Existing destinations %s\n", existingPortsToDestinations)

			containerDestination := func(servicePort int) string {
				if networkConfig.ipv6 {
					if containerIpv6 == "" {
						panic("Container must have ipv6")
					}
					return fmt.Sprintf("[%s]:%d", containerIpv6, servicePort)
				} else {
					if containerIpv4 == "" {
						panic("Container must have ipv4")
					}
					return fmt.Sprintf("%s:%d", containerIpv4, servicePort)
				}
			}

			// redirect for traffic to the interface ip on the service port
			publicRedirectCmd := func(op string, servicePort int, destination string) *exec.Cmd {
				// use dnat to the container ip and service port to work around the docker issue of masking the remote ip
				// https://github.com/docker/docs/issues/17312

				return sudo2(
					networkConfig.iptablesCommand, "-t", "nat", op, chainName,
					"-p", "tcp", "-m", "tcp", "-d", networkConfig.routingTable.interfaceIp, "--dport", strconv.Itoa(servicePort),
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

	// ipv4
	networkConfigs = append(networkConfigs, &NetworkConfig{
		ipv6:            false,
		routingTable:    routingTableIpv4,
		dockerNetwork:   dockerNetworkIpv4,
		ipCommand:       []string{"ip"},
		iptablesCommand: []string{"iptables"},
	})
	// ipv6
	networkConfigs = append(networkConfigs, &NetworkConfig{
		ipv6:            true,
		routingTable:    routingTableIpv6,
		dockerNetwork:   dockerNetworkIpv6,
		ipCommand:       []string{"ip", "-6"},
		iptablesCommand: []string{"ip6tables"},
	})
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
}

func NewKillWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
	}
}

func (self *KillWorker) Run() {
	// ignore errors
	runAndLog(docker(
		"update", "--restart=no", self.containerId,
	))

	// ignore errors
	runAndLog(docker(
		"stop", "container", "--time", fmt.Sprintf("%d", int(KillTimeout/time.Second)), self.containerId,
	))
}
