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
	"time"

	"github.com/urnetwork/warp"
)

const KillTimeout = 15 * time.Second

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.Command("nginx", "-g", "daemon off;", "-c", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		panic(err)
	}
	defer cmd.Process.Kill()
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-event.Ctx.Done():
		}

		cmd.Process.Signal(syscall.SIGQUIT)

		select {
		case <-ctx.Done():
			return
		case <-time.After(KillTimeout):
		}

		cmd.Process.Kill()
	}()

	err = cmd.Wait()
	if err != nil {
		panic(err)
	}
	os.Exit(cmd.ProcessState.ExitCode())
}

type HostNetwork struct {
	Ipv4      netip.Addr
	Ipv6      netip.Addr
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

	ipv4Addr, err := netip.ParseAddr(ipv4)
	if err != nil {
		return nil, err
	}
	ipv6Addr, err := netip.ParseAddr(ipv6)
	if err != nil {
		return nil, err
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
		Ipv4:      ipv4Addr,
		Ipv6:      ipv6Addr,
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
	listenRe := regexp.MustCompile("(?m)(?:^|;)(\\s*)listen\\s+((?:[^;]+:)?(\\d+))(\\s+[^;]+)?;")

	allSubmatches := listenRe.FindAllSubmatchIndex(content, -1)

	i := 0
	for _, submatches := range allSubmatches {
		if i < submatches[0] {
			out = append(out, content[i:submatches[0]]...)
		}
		i = submatches[1]

		var addr netip.Addr
		addrOk := false
		var port int
		ipPort := string(content[submatches[4]:submatches[5]])
		addrPort, err := netip.ParseAddrPort(ipPort)
		if err == nil {
			addr = addrPort.Addr()
			addrOk = true
			port = int(addrPort.Port())
		} else {
			// just parse the port
			port, err = strconv.Atoi(string(content[submatches[6]:submatches[7]]))
			if err != nil {
				return err
			}
		}

		hostPort, portOk := hostNetwork.HostPorts[port]
		if !portOk {
			return fmt.Errorf("Missing host port for service port %d", port)
		}
		var hostAddr netip.Addr
		if addrOk {
			if addr.Is6() {
				hostAddr = hostNetwork.Ipv6
			} else {
				hostAddr = hostNetwork.Ipv4
			}
		} else {
			// the default nginx interface is ipv4
			hostAddr = hostNetwork.Ipv4
		}
		hostAddrPort := netip.AddrPortFrom(hostAddr, uint16(hostPort))

		template := fmt.Sprintf("${1}listen %s${4};", hostAddrPort)
		out = listenRe.Expand(out, []byte(template), content, submatches)
	}
	if i < len(content) {
		out = append(out, content[i:len(content)]...)
	}

	Err.Printf("Converted nginx config (%s): %s", outPath, string(out))

	err = os.WriteFile(outPath, out, 0555)
	if err != nil {
		return err
	}
	return nil
}
