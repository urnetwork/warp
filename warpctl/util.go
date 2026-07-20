package main

import (
	"bytes"
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

	"github.com/urnetwork/warp"
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

func retry(n int, run func() error) (err error) {
	for range n {
		err = run()
		if err == nil {
			return
		}
	}
	// return the last error
	return
}

var runAndLogFunc func(cmd *exec.Cmd) error

func runAndLog(cmd *exec.Cmd) error {
	if runAndLogFunc != nil {
		return runAndLogFunc(cmd)
	}
	Err.Printf("[run]%s\n", cmd)
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
	Err.Printf("[run]%s\n", cmd)
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

var sudo2Func func(name []string, args ...string) *exec.Cmd

func sudo2(name []string, args ...string) *exec.Cmd {
	if sudo2Func != nil {
		return sudo2Func(name, args...)
	}
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
	if err = t.Execute(out, mergedData); err != nil {
		panic(err)
	}
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

func gateway(ipNet net.IPNet) net.IP {
	ip := ipNet.IP.Mask(ipNet.Mask)
	ip[len(ip)-1] |= 0x01
	return ip
}

func semverSortWithBuild(versions []semver.Version) {
	slices.SortStableFunc(versions, semverCmpWithBuild)
}

func semverCmpWithBuild(a semver.Version, b semver.Version) int {
	// ignore the PreRelease field
	if a.Major == b.Major && a.Minor == b.Minor && a.Patch == b.Patch {
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

// ByteCount stays an alias here so warpctl's existing ByteCount usages compile.
// The common parsing helpers live in the parent warp package; re-export the
// ones warpctl still calls so their call sites don't need qualification.
type ByteCount = int64

var (
	expandAnyPorts         = warp.ExpandAnyPorts
	expandPorts            = warp.ExpandPorts
	ParseByteCount         = warp.ParseByteCount
	ByteCountHumanReadable = warp.ByteCountHumanReadable
)
