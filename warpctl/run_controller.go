package main


import (
	"os"
	"os/exec"
	"time"
	"strings"
	"fmt"
	"strconv"
	"errors"
	"path"
	"net"
	"net/http"
	"io"
	"encoding/json"


	"github.com/coreos/go-semver/semver"
)


// Create docker networks as follows:
// FOR NON-SERVICE NETWORKS DISABLE MASQ
// docker network create --attachable --opt 'com.docker.network.bridge.name=warp1' --opt 'com.docker.network.bridge.enable_ip_masquerade=false' warp1 
// docker network create --attachable --opt 'com.docker.network.bridge.name=warpsservices' warpsservices



// FIXME
// FIXME at run pass these in as env vars
// WARP_ENV
// WARP_VERSION
// WARP_CONFIG_VERSION



const (
	MOUNT_MODE_NO = "no"
	MOUNT_MODE_YES = "yes"
	MOUNT_MODE_ROOT = "root"
)


type RunWorker struct {
	warpState *WarpState
	dockerHubClient *DockerHubClient

	env string
	service string
	block string
	portBlocks *PortBlocks
	servicesDockerNetwork *DockerNetwork
	routingTable *RoutingTable
	dockerNetwork *DockerNetwork

	vaultMountMode string
	configMountMode string
	siteMountMode string

	deployedVersion *semver.Version
	deployedConfigVersion *semver.Version

	quit chan os.Signal
}


func (self *RunWorker) run() {
	// on start, deploy the latest version and start the watcher loop

	announceRunEnter()
	defer annountRunExit()

	// enable policy routing
	if self.routingTable != nil {
		self.initRoutingTable()
	}

	self.initBlockRedirect()

	self.deployedVersion = nil
	self.deployedConfigVersion = nil

	// watch for new versions until killed
	watcher:
	for {
		latestVersion, latestConfigVersion := self.getLatestVersion()
		fmt.Printf("Polled latest versions: %s, %s\n", latestVersion, latestConfigVersion)

		deployVersion := func()(bool) {
			if latestVersion == nil {
				return false
			}
			if self.deployedVersion != nil && *self.deployedVersion == *latestVersion {
				return false
			}
			if self.configMountMode != MOUNT_MODE_YES {
				return true
			}
			if latestConfigVersion == nil {
				return false
			}
			if self.deployedConfigVersion != nil && *self.deployedConfigVersion == *latestConfigVersion {
				return false
			}
			return true
		}()

		if deployVersion {
			// deploy new version
			self.deployedVersion = latestVersion
			self.deployedConfigVersion = latestConfigVersion

			fmt.Printf("DEPLOY VERSION %s %s\n", self.deployedVersion, self.deployedConfigVersion)
			func() {
				announceRunStart()
				defer func() {
					if err := recover(); err != nil {
						fmt.Printf("DEPlOY ERROR %s %s\n", self.deployedVersion, self.deployedConfigVersion)
						announceRunError()
					}
				}()
				err := self.deploy()
				if err != nil {
					fmt.Printf("DEPLOY FAILED %s %s %s\n", self.deployedVersion, self.deployedConfigVersion, err)
					announceRunFail()
				} else {
					fmt.Printf("DEPLOY SUCCESS %s %s\n", self.deployedVersion, self.deployedConfigVersion)
					announceRunSuccess()
				}
			}()
		} else if latestVersion == nil {
			announceRunWaitForVersion()
		} else if latestConfigVersion == nil {
			announceRunWaitForConfig()
		}
		select {
		case <- self.quit:
			fmt.Printf("Quit signal detected. Exiting run loop.\n")
			break watcher
		case <-time.After(5 * time.Second):
			// continue
		}
	}
}


// service version, config version
func (self *RunWorker) getLatestVersion() (*semver.Version, *semver.Version) {

	

	versionMeta := self.dockerHubClient.getVersionMeta(self.env, self.service)
	latestVersion := versionMeta.latestBlocks[self.block]

	var latestConfigVersion *semver.Version
	if self.warpState.warpSettings.ConfigHome == nil {
		latestConfigVersion = nil
	} else {
		entries, err := os.ReadDir(*self.warpState.warpSettings.ConfigHome)
	    if err != nil {
	    	panic(err)
	    }

	    configVersions := []*semver.Version{}
	    for _, entry := range entries {
	    	if entry.IsDir() {
	    		if version, err := semver.NewVersion(entry.Name()); err == nil {
	    			configVersions = append(configVersions, version)
	    		}
	    	}
	    }
	    semverSortWithBuild(configVersions)

	    
	    if len(configVersions) == 0 {
	    	latestConfigVersion = nil
	    } else {
	    	latestConfigVersion = configVersions[len(configVersions) - 1]
	    }
	}

    return latestVersion, latestConfigVersion
}



// docker kill --signal="<signal>"




func (self *RunWorker) initRoutingTable() {
	cmds := NewCommandList()

	cmds.sudo(
		"ip", "route", "flush",
		"table", self.routingTable.tableName,
	).ignoreErrors()

	// add routes for:
	// - interface (default)
	// - docker services interface
	// - docker interface

	cmds.sudo(
		"ip", "route", "add", self.routingTable.interfaceIpv4Subnet, 
		"dev", self.routingTable.interfaceName, 
		"src", self.routingTable.interfaceIpv4, 
		"table", self.routingTable.tableName,
	)
    cmds.sudo(
    	"ip", "route", "add", self.servicesDockerNetwork.interfaceIpv4Subnet, 
    	"dev", self.servicesDockerNetwork.interfaceName,
    	"src", self.servicesDockerNetwork.interfaceIpv4,
    	"table", self.routingTable.tableName,
    )
   	cmds.sudo(
   		"ip", "route", "add", self.dockerNetwork.interfaceIpv4Subnet, 
    	"dev", self.dockerNetwork.interfaceName,
    	"src", self.dockerNetwork.interfaceIpv4,
    	"table", self.routingTable.tableName,
    )
   	cmds.sudo(
   		"ip", "route", "add", "default",
   		"via", self.routingTable.interfaceIpv4Gateway,
   		"dev", self.routingTable.interfaceName,
   		"table", self.routingTable.tableName,
   	)

    // use the table from:
    // - interface ip (sockets bound to the interface)
    // - docker interface subnet (sockets in docker containers in the network)

   	cmds.sudo(
   		"ip", "rule", "add",
   		"from", self.routingTable.interfaceIpv4Gateway,
   		"table", self.routingTable.tableName,
   	)
	cmds.sudo(
		"ip", "rule", "add",
   		"from", self.dockerNetwork.interfaceIpv4Subnet,
   		"table", self.routingTable.tableName,
   	)

	cmds.run()
}



func (self *RunWorker) iptablesChainName() string {
	return fmt.Sprintf(
		"WARP-%s-%s-%s",
		strings.ToUpper(self.env),
		strings.ToUpper(self.service),
		strings.ToUpper(self.routingTable.interfaceName),
	)
}


// we exepct some small downtime when the run worker starts
// treat the same a host reboot or update. this is where redundant hosts are needed 
func (self *RunWorker) initBlockRedirect() {
	cmds := NewCommandList()

	chainName := self.iptablesChainName()
	cmds.sudo(
		"iptables", "-t", "nat", "-N", chainName,
	).ignoreErrors()
 
	cmds.sudo(
		"iptables", "-t", "nat", "-F", chainName,
	).ignoreErrors()


	chainCmd := func(op string, entryChainName string) *exec.Cmd {
		return sudo(
			"iptables", "-t", "nat", op, entryChainName,
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-j", chainName,
		)
	}

	// apply chain to external traffic to local
	for {
		cmd := chainCmd("-D", "PREROUTING")
		err := cmd.Run()
		if err != nil {
			break
		}
	}
	cmds.add(chainCmd("-I", "PREROUTING"))

	// cmds.sudo(
	// 	"iptables", "-t", "nat", "-I", "PREROUTING",
	// 	"-m", "addrtype", "--dst-type", "LOCAL",
	// 	"-j", chainName,
	// )

	// apply chain to local traffic to local
	for {
		cmd := chainCmd("-D", "OUTPUT")
		err := cmd.Run()
		if err != nil {
			break
		}
	}
	cmds.add(chainCmd("-I", "OUTPUT"))

	// cmds.sudo(
	// 	"iptables", "-t", "nat", "-I", "OUTPUT",
	// 	"-m", "addrtype", "--dst-type", "LOCAL",
	// 	"-j", chainName,
	// )

	cmds.run()
}



// FIXME this appears to not be working
func (self *RunWorker) deploy() error {
	externalsPortsToInternalPort, servicePortsToInternalPort := self.waitForDeployPorts()
	fmt.Printf("Ports %s, %s\n", externalsPortsToInternalPort, servicePortsToInternalPort)

    deployedContainerId, err := self.startContainer(servicePortsToInternalPort)
    if err != nil {
    	fmt.Printf("Start container failed %s\n", err)
    	return err
    }
    success := false
    defer func() {
		if !success {
	    	go newKillWorker(deployedContainerId).run()
	    }
    }()

	if err := self.pollContainerStatus(servicePortsToInternalPort, 300 * time.Second); err != nil {
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

    containerIds := map[string]bool{}
    for _, containerId := range runningContainers {
    	containerIds[containerId] = true
    }
    for containerId, _ := range containerIds {
    	if containerId != deployedContainerId {
		    go newKillWorker(containerId).run()
		}
	}

    self.redirect(externalsPortsToInternalPort)
    success = true
    return nil
}

func (self *RunWorker) waitForDeployPorts() (map[int]int, map[int]int) {
	for {
		externalsPortsToInternalPort := map[int]int{}

		runningContainers, err := self.findRunningContainers()
		if err != nil {
			fmt.Printf("FIND RUNNING CONTAINERS ERROR %s\n", err)
			panic(err)
		}
		for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if _, ok := runningContainers[internalPort]; !ok {
					externalsPortsToInternalPort[externalPort] = internalPort
					break
				}
			}
		}

		if len(externalsPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
			select {
			case <- self.quit:
				panic("Could not allocate ports.")
			case <-time.After(5 * time.Second):
				// continue
			}
		}

		servicePortsToInternalPort := map[int]int{}
		for externalPort, servicePort := range self.portBlocks.externalsToService {
			internalPort := externalsPortsToInternalPort[externalPort]
			servicePortsToInternalPort[servicePort] = internalPort
		}

		return externalsPortsToInternalPort, servicePortsToInternalPort
	}
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

	fmt.Printf("Running docker pull %s\n", imageName)

	pullCmd := docker("pull", imageName)
	err := pullCmd.Run()
	if err != nil {
		return "", err
	}


	args := []string{
		"--name", containerName,
		"-d",
		"--restart=on-failure",
	}
	for servicePort, internalPort := range servicePortsToInternalPort {
		args = append(args, []string{"-p", fmt.Sprintf("%d:%d", internalPort, servicePort)}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--network", self.dockerNetwork.networkName}...)
	} else {
		args = append(args, []string{"--network", self.servicesDockerNetwork.networkName}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.dockerNetwork.networkName, self.dockerNetwork.interfaceIpv4)}...)
	}
	args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.servicesDockerNetwork.networkName, self.servicesDockerNetwork.interfaceIpv4)}...)

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
		configVersionHome := path.Join(
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

	args = append(args, imageName)
	if self.service == "lb" {
		// the lb expects the path of the config to be given as an arg
		// TODO ideally this could be handled with an env var in the docker image, 
		// TODO but unfortunately docker does not allow env vars in the command
		args = append(args, fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", self.block))
	}

	fmt.Printf("Running docker %s (%s)\n", strings.Join(args, " "), args)

	runCmd := docker("run", args...)

	fmt.Printf("%s\n", runCmd)

	out, err := runCmd.Output()
	fmt.Printf("COMMAND OUTPUT %s %s\n", out, err)
	if err != nil {
		return "", err
	}
	// `docker run` prints the container_id as the only output
	container_id := strings.TrimSpace(string(out))
	return container_id, nil
}

func (self *RunWorker) pollContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	httpPort, ok := servicePortsToInternalPort[80]
	if !ok {
		// no http port - assume ok
		return nil
	}

	client := &http.Client{}

	poll := func()(error) {
		fmt.Printf("POLL ONE http://127.0.0.1:%d/status\n", httpPort)

		statusRequest, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://127.0.0.1:%d/status", httpPort),
			nil,
		)
		if err != nil {
			return err
		}
		// FIXME pass the domain as an argument to runworker
		// FIXME pass whether the /status route is exposed to runworker
		statusRequest.Host = fmt.Sprintf("%s-%s.bringyour.com", self.env, self.service)
		statusResponse, err := client.Do(statusRequest)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(statusResponse.Body)
		fmt.Printf("POLL STATUS %s %s\n", body, err)
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
	for {
		err := poll()
		if err == nil {
			return nil
		}
		select {
		case <- self.quit:
			return errors.New("quit")
		case <-time.After(5 * time.Second):
			// continue
		}
		if time.Now().After(endTime) {
			return err
		}
	}
}

func (self *RunWorker) redirect(externalsPortsToInternalPort map[int]int) {
	chainName := self.iptablesChainName()

	redirectCmd := func(op string, externalPort int, internalPort int) *exec.Cmd {
		return sudo(
	    	"iptables", "-t", "nat", op, chainName,
	    	"-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(externalPort),
	    	"-j", "REDIRECT", "--to-ports", strconv.Itoa(internalPort),
	    )
	}

	for externalPort, internalPort := range externalsPortsToInternalPort {
	    cmd := redirectCmd("-I", externalPort, internalPort)
	    fmt.Printf("%s\n", cmd)
	    err := cmd.Run()
	    if err != nil {
	    	panic(err)
	    }
	}

	// clear all other redirect rules in the owned block
	for externalPort, internalPort := range externalsPortsToInternalPort {
		if blockInternalPorts, ok := self.portBlocks.externalsToInternals[externalPort]; ok {
			for _, blockInternalPort := range blockInternalPorts {
				if blockInternalPort != internalPort {
					for {
						// cmd := redirectCmd("-C", externalPort, blockInternalPort)
						// fmt.Printf("%d\n", cmd)
		    			// err := cmd.Run()
		    			// if err == nil {
		    			// 	fmt.Printf("REDIRECT RULE DOES NOT EXIST (%s)\n", err)
		    			// 	break
		    			// }
		    			cmd := redirectCmd("-D", externalPort, blockInternalPort)
		    			err := cmd.Run()
		    			if err != nil {
		    				break
		    			}
		    			fmt.Printf("%s\n", cmd)
		    		}
				}
			}
		}
	}
}




/*
type ContainerList = []Container

Container
Id string
HostConfig *HostConfig

HostConfig
PortBindings map[string][]*PortBinding

PortBinding
HostIp string
HostPort string
*/


type ContainerList = []*Container

type Container struct {
	ContainerId string `json:"Id"`
	HostConfig *HostConfig `json:"HostConfig"`
}

type HostConfig struct {
	PortBindings map[string][]*PortBinding `json:"PortBindings"`
}

type PortBinding struct {
	HostIp string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}


// map internal port to running container_id for all running containers
func (self *RunWorker) findRunningContainers() (map[int]string, error) {
	psCmd := docker("ps", "--format", "{{.ID}}")
	out, err := psCmd.Output()
	if err != nil {
		fmt.Printf("RUNNING CONTAINERS ERROR 1 %s\n", err)
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		// no containers running
		return map[int]string{}, nil
	}

	containerIds := strings.Split(outStr, "\n")
	inspectCmd := docker("inspect", containerIds...)
	fmt.Printf("RUNNING CONTAINERS INSPECT %s (%s)\n", inspectCmd, containerIds)
	out, err = inspectCmd.Output()
	if err != nil {
		fmt.Printf("RUNNING CONTAINERS ERROR 2 %s\n", err)
		return nil, err
	}

	var containerList ContainerList
	err = json.Unmarshal(out, &containerList)
	if err != nil {
		fmt.Printf("RUNNING CONTAINERS ERROR 3 %s\n", err)
		return nil, err
	}

	fmt.Printf("RUNNING CONTAINERS LIST %s\n", containerList)

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

	fmt.Printf("RUNNING CONTAINERS %s\n", runningContainers)

	return runningContainers, nil
}




type PortBlocks struct {
	externalsToInternals map[int][]int
	externalsToService map[int]int
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
		externalsToService: externalsToService,
	}
}


type NetworkInterface struct {
	interfaceName string
	interfaceIpv4 string
	interfaceIpv4Subnet string
	interfaceIpv4Gateway string
}


type DockerNetwork struct {
	networkName string
	NetworkInterface
}


func parseDockerNetwork(dockerNetworkStr string) *DockerNetwork {
	// assume the network name is the interface name
	interfaceName := dockerNetworkStr

	networkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	if len(networkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not map docker interface %s to interface", interfaceName)))
	}
	if 1 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]

	return &DockerNetwork{
		networkName: dockerNetworkStr,
		NetworkInterface: *networkInterface,
	}
}

/*
DockerNetworks = []DockerNetwork

DockerNetwork
Name string
IPAM *DockerNetworkIpam

DockerNetworkIpam
Config []*DockerNetworkIpConfig

DockerNetworkIpConfig
Subnet
Gateway

*/


type RoutingTable struct {
	interfaceName string
	tableName string
	NetworkInterface
}

// interface:rt_table_name
// inspect the local interface for the ip address
func parseRoutingTable(routingTableStr string) *RoutingTable {
	routingTableStrSplit := strings.SplitN(routingTableStr, ":", 2)
	interfaceName := routingTableStrSplit[0]
	tableName := routingTableStrSplit[1]


	// ifconfig
	// see https://github.com/golang/go/issues/12551

	networkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	if len(networkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not find interface %s", interfaceName)))
	}
	if 1 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]


	return &RoutingTable{
		interfaceName: interfaceName,
		tableName: tableName,
		NetworkInterface: *networkInterface,
	}
}


func getNetworkInterfaces(interfaceName string) ([]*NetworkInterface, error) {
	// see https://github.com/golang/go/issues/12551

	fmt.Printf("GET NETWORK INTERFACES %s\n", interfaceName)

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

    addrs, err := iface.Addrs()
    if err != nil {
        return nil, err
    }

    networkInterfaces := []*NetworkInterface{}

    for _, addr := range addrs {
        if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
        	// gatewayIp, err := cidr.Host(netw, 1)
        	// if err != nil {
        	// 	return nil, err
        	// }
        	// gatewayIp := net.IP(networkIp)
        	// ipnetgen.Increment(gatewayIp)

        	zeroedIpNet := net.IPNet{
        		IP: ipNet.IP.Mask(ipNet.Mask),
        		Mask: ipNet.Mask,
        	}

        	gateway := nextIp(zeroedIpNet, 1)


        	networkInterface := &NetworkInterface{
        		interfaceName: interfaceName,
        		interfaceIpv4: ipNet.IP.String(),
            	interfaceIpv4Subnet: zeroedIpNet.String(),
            	interfaceIpv4Gateway: gateway.String(),
            }
            networkInterfaces = append(networkInterfaces, networkInterface)
        }
    }

    for _, networkInterface := range networkInterfaces {
    	fmt.Printf(
    		"%s ipv4=%s ipv4_subnet=%s ipv4_gateway=%s\n",
    		networkInterface.interfaceName,
    		networkInterface.interfaceIpv4,
    		networkInterface.interfaceIpv4Subnet,
    		networkInterface.interfaceIpv4Gateway,
    	)
    }



	return networkInterfaces, nil
}




type KillWorker struct {
	containerId string
}

func newKillWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
	}
}

func (self *KillWorker) run() {
	cmds := NewCommandList()

	cmds.docker(
		"update", "--restart=no", self.containerId,
	).ignoreErrors()

	cmds.docker(
		"stop", "container", "--time", "120", self.containerId,
	).ignoreErrors()

	cmds.run()
}

