package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/urnetwork/warp"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

var Out *log.Logger
var Err *log.Logger

func init() {
	Out = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	Err = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {

	block := os.Getenv("WARP_BLOCK")
	if block == "" {
		panic(errors.New("WARP_BLOCK must be set."))
	}

	path := fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", block)

	if hostNetwork, err := warpHostNetwork(); err == nil {
		// use a predictable path to help debugging
		outPath := fmt.Sprintf("/srv/warp/nginx.conf/%s_host.conf", block)
		err := convertNginxConfigToHostNetwork(path, outPath, hostNetwork)
		if err != nil {
			panic(err)
		}
		path = outPath
		Err.Printf("Using converted nginx config: %s", path)
	}

	event := warp.NewEvent()
	eventClose := event.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer eventClose()

	ctx, cancel := context.WithCancel(event.Ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-g", "daemon off;", "-c", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	os.Exit(cmd.ProcessState.ExitCode())
}

type HostNetwork struct {
	Ipv4      string
	Ipv6      string
	HostPorts map[int]int
}

func warpHostNetwork() (*HostNetwork, error) {
	ipv4 := os.Getenv("WARP_HOST_IPV4")
	ipv6 := os.Getenv("WARP_HOST_IPV6")
	if ipv4 == "" && ipv6 == "" {
		return nil, errors.New("WARP_HOST_IPV4 and WARP_HOST_IPV6 not set")
	} else if ipv4 == "" {
		return nil, errors.New("WARP_HOST_IPV4 not set")
	} else if ipv6 == "" {
		return nil, errors.New("WARP_HOST_IPV6 not set")
	}

	// service port -> host port
	hostPorts := map[int]int{}

	if ports := os.Getenv("WARP_PORTS"); ports != "" {
		portPairs := strings.Split(ports, ",")
		for _, portPair := range portPairs {
			parts := strings.Split(portPair, ":")
			if len(parts) != 2 {
				return nil, errors.New("Port pair must be service_port:host_port")
			}
			servicePort, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, err
			}
			hostPort, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, err
			}
			hostPorts[servicePort] = hostPort
		}
	}

	return &HostNetwork{
		Ipv4:      ipv4,
		Ipv6:      ipv6,
		HostPorts: hostPorts,
	}, nil
}

func convertNginxConfigToHostNetwork(path string, outPath string, hostNetwork *HostNetwork) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	out := []byte{}

	// groups:
	// 1 = indent
	// 2 = ip:port
	// 3 = port
	// 4 = options
	listenRe := regexp.MustCompile("(?m)^(\\s*)listen\\s+((?:[^;]+:)?(\\d+))(\\s+[^;]+)?;\\s*$")

	allSubmatches := listenRe.FindAllSubmatchIndex(content, -1)

	i := 0
	for _, submatches := range allSubmatches {
		if i < submatches[0] {
			out = append(out, content[i:submatches[0]]...)
		}
		i = submatches[1]

		addr, err := func() (netip.Addr, error) {
			ipPort := string(content[submatches[4]:submatches[5]])
			addrPort, err := netip.ParseAddrPort(ipPort)
			if err != nil {
				return netip.Addr{}, err
			}
			return addrPort.Addr(), nil
		}()

		var template string
		if err == nil {
			if addr.Is6() {
				template = fmt.Sprintf("${1}listen [%s]:${3}${4};", hostNetwork.Ipv6)
			} else {
				// v4
				template = fmt.Sprintf("${1}listen %s:${3}${4};", hostNetwork.Ipv4)
			}
		} else {
			// the default nginx interface is ipv4
			template = fmt.Sprintf("${1}listen %s:${3}${4};", hostNetwork.Ipv4)
		}
		out = listenRe.Expand(out, []byte(template), content, submatches)
	}
	if i < len(content) {
		out = append(out, content[i:len(content)]...)
	}

	Err.Printf("Converted nginx config: %s", string(out))

	err = os.WriteFile(outPath, out, 0555)
	if err != nil {
		return err
	}
	return nil
}
