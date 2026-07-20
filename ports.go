package warp

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func ExpandPortConfigPorts(portSpecs ...string) []int {
	ports := map[int]bool{}
	stablePorts := []int{}

	addPort := func(port int) {
		if _, ok := ports[port]; !ok {
			ports[port] = true
			stablePorts = append(stablePorts, port)
		}
	}

	portRe := regexp.MustCompile("^(\\d+)$")
	portPlusRe := regexp.MustCompile("^(\\d+)\\s*\\+\\s*(\\d+)$")
	portRangeRe := regexp.MustCompile("^(\\d+)\\s*-\\s*(\\d+)$")
	for _, portSpec := range portSpecs {
		portSpec = strings.TrimSpace(portSpec)
		if groups := portRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			addPort(port)
		} else if groups := portPlusRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			n, _ := strconv.Atoi(groups[2])
			for i := 0; i <= n; i += 1 {
				addPort(port + i)
			}
		} else if groups := portRangeRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			endPort, _ := strconv.Atoi(groups[2])
			for i := 0; port+i <= endPort; i += 1 {
				addPort(port + i)
			}
		} else {
			panic(fmt.Errorf("Unknown port spec: %s", portSpec))
		}
	}

	return stablePorts
}

func ExpandAnyPorts(portSpec any) ([]int, error) {
	switch v := portSpec.(type) {
	case int:
		return []int{v}, nil
	case string:
		return ExpandPorts(v)
	default:
		return nil, errors.New(fmt.Sprintf("Unknown ports type %T", v))
	}
}

func ExpandPorts(portsListStr string) ([]int, error) {
	portRangeRegex := regexp.MustCompile("^\\s*(\\d+)\\s*-\\s*(\\d+)\\s*$")
	portRegex := regexp.MustCompile("^\\s*(\\d+)\\s*$")
	ports := []int{}
	for _, portsStr := range strings.Split(portsListStr, ",") {
		if portStrs := portRangeRegex.FindStringSubmatch(portsStr); portStrs != nil {
			minPort, err := strconv.Atoi(portStrs[1])
			if err != nil {
				panic(err)
			}
			maxPort, err := strconv.Atoi(portStrs[2])
			if err != nil {
				panic(err)
			}
			for port := minPort; port <= maxPort; port += 1 {
				ports = append(ports, port)
			}
		} else if portStrs := portRegex.FindStringSubmatch(portsStr); portStrs != nil {
			port, err := strconv.Atoi(portStrs[1])
			if err != nil {
				panic(err)
			}
			ports = append(ports, port)
		} else {
			return nil, errors.New(fmt.Sprintf("Port must be either int min-max or int port (%s)", portsStr))
		}
	}
	return ports, nil
}
