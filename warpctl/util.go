package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/coreos/go-semver/semver"
)

/*
type CommandList struct {
    commands []*exec.Cmd
    ignore map[int]bool
    Dir string
}

func NewCommandList() *CommandList {
    return &CommandList{
        commands: []*exec.Cmd{},
        ignore: map[int]bool{},
    }
}

func (self *CommandList) Sudo(name string, args ...string) *CommandList {
    cmd := sudo(name, args...)
    cmd.Dir = self.Dir
    self.commands = append(self.commands, cmd)
    return self
}

func (self *CommandList) Docker(name string, args ...string) *CommandList {
    cmd := docker(name, args...)
    cmd.Dir = self.Dir
    self.commands = append(self.commands, cmd)
    return self
}

func (self *CommandList) Add(cmd *exec.Cmd) *CommandList {
    self.commands = append(self.commands, cmd)
    return self
}

func (self *CommandList) IgnoreErrors() {
    self.ignore[len(self.commands) - 1] = true
}

func (self *CommandList) Run() {
    for i, cmd := range self.commands {
        fmt.Printf("RUNNING COMMAND %s\n", cmd)
        err := cmd.Run()
        if err != nil {
            if ignore, ok := self.ignore[i]; !ok || !ignore  {
                panic(err)
            }
        }
    }
}
*/

func runAndLog(cmd *exec.Cmd) error {
	err := cmd.Run()
	if err == nil {
		Err.Printf("%s (exited 0)\n", cmd)
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			Err.Printf("%s (exited %d)\n", cmd, exitError.ExitCode())
		} else {
			Err.Printf("%s (error %s)\n", cmd, err)
		}
	}
	return err
}

func outAndLog(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.Output()
	if err == nil {
		Err.Printf("%s (exited 0): %s\n", cmd, string(out))
		return out, nil
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			Err.Printf("%s (exited %d)\n", cmd, exitError.ExitCode())
		} else {
			Err.Printf("%s (error %s)\n", cmd, err)
		}
		return nil, err
	}
}

func sudo(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}

func sudo2(name []string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name...)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}

func docker(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	switch runtime.GOOS {
	case "linux":
		return sudo("docker", flatArgs...)
	default:
		return exec.Command("docker", flatArgs...)
	}
}

func expandAnyPorts(portSpec any) ([]int, error) {
	switch v := portSpec.(type) {
	case int:
		return []int{v}, nil
	case string:
		return expandPorts(v)
	default:
		return nil, errors.New(fmt.Sprintf("Unknown ports type %T", v))
	}
}

func expandPorts(portsListStr string) ([]int, error) {
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

func collapsePorts(ports []int) string {
	parts := []string{}

	sort.Ints(ports)
	for i := 0; i < len(ports); {
		j := i + 1
		for j < len(ports) && ports[j] == ports[j-1]+1 {
			j += 1
		}
		if i == j-1 {
			parts = append(parts, fmt.Sprintf("%d", ports[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j-1]))
		}
		i = j
	}

	return strings.Join(parts, ",")
}

func templateString(text string, data ...map[string]any) string {
	unindentedText := indentAndTrimString(text, 0)
	t, err := template.New("").Parse(unindentedText)
	if err != nil {
		panic(err)
	}
	mergedData := map[string]any{}
	for _, d := range data {
		for key, value := range d {
			mergedData[key] = value
		}
	}
	out := &bytes.Buffer{}
	t.Execute(out, mergedData)
	return out.String()
}

func indentAndTrimString(text string, indent int) string {
	// use the minimum indent of a contentful line

	contentfulLineRegex := regexp.MustCompile("^(\\s*)\\S")
	minIndent := -1

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if contentfulLineStrs := contentfulLineRegex.FindStringSubmatch(line); contentfulLineStrs != nil {
			lineIndent := len(contentfulLineStrs[1])
			if minIndent < 0 || lineIndent < minIndent {
				minIndent = lineIndent
			}
		}
	}

	if minIndent < 0 {
		minIndent = 0
	}

	indentStr := strings.Repeat(" ", indent)

	indentedLines := []string{}
	for i, line := range lines {
		if len(line) <= minIndent {
			// trim first and least empty lines
			if 0 < i && i < len(lines)-1 {
				indentedLine := ""
				indentedLines = append(indentedLines, indentedLine)
			}
		} else {
			indentedLine := fmt.Sprintf("%s%s", indentStr, line[minIndent:])
			indentedLines = append(indentedLines, indentedLine)
		}

	}

	return strings.Join(indentedLines, "\n")
}

func nextIpv4(ipNet net.IPNet, count int) net.IP {
	ip := ipNet.IP.Mask(ipNet.Mask)
	ones, _ := ipNet.Mask.Size()
	i := ones / 8

	for k := 0; k < count; k += 1 {
		ip[i] += 0x01 << (ones % 8)
		// propagate the overflow bit forward
		for j := i; ip[j] == 0 && j+1 < len(ip); j += 1 {
			ip[j+1] += 0x01
		}
	}

	return ip
}

func nextIpv6(ipNet net.IPNet, count int) net.IP {
	ip := ipNet.IP.Mask(ipNet.Mask)
	ones, _ := ipNet.Mask.Size()
	i := (ones / 16) * 2

	for k := 0; k < count; k += 1 {
		f := (uint16(ip[i]) << 8) | uint16(ip[i+1])
		f += 0x01 << (ones % 16)
		ip[i] = byte(f >> 8)
		ip[i+1] = byte(f)
		// propagate the overflow bit forward
		for j := i; ip[j] == 0 && ip[j+1] == 0 && j+3 < len(ip); j += 2 {
			ip[j+1] += 0x01
			f = (uint16(ip[j+2]) << 8) | uint16(ip[j+3])
			f += 1
			ip[j+2] = byte(f >> 8)
			ip[i+3] = byte(f)
		}
	}

	return ip
}

func gateway(ipNet net.IPNet) net.IP {
	ip := ipNet.IP.Mask(ipNet.Mask)
	ip[len(ip)-1] |= 0x01
	return ip
}

func semverSortWithBuild(versions []semver.Version) {
	slices.SortStableFunc(versions, semverCmpWithBuild)
}

func semverCmpWithBuild(a semver.Version, b semver.Version) int {
	if a.Equal(b) {
		if a.Metadata == b.Metadata {
			return 0
		} else if a.Metadata < b.Metadata {
			return -1
		} else {
			return 1
		}
	} else if a.LessThan(b) {
		return -1
	} else {
		return 1
	}
}

func mapStr[KT comparable, VT any](m map[KT]VT) string {
	str := func(a any) string {
		switch v := a.(type) {
		case int:
			return strconv.Itoa(v)
		case string:
			return v
		default:
			return fmt.Sprintf("%s", v)
		}
	}
	pairStrs := []string{}
	for k, v := range m {
		pairStr := fmt.Sprintf("%s:%s", str(k), str(v))
		pairStrs = append(pairStrs, pairStr)
	}
	return fmt.Sprintf("{%s}", strings.Join(pairStrs, ", "))
}
