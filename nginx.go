package warp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// **important** warpctl config should align `worker_shutdown_timeout` with this
const DefaultDrainTimeout = 60 * time.Minute

func DefaultNginxSettings() *NginxSettings {
	return &NginxSettings{
		DrainTimeout: DefaultDrainTimeout,
	}
}

type NginxSettings struct {
	// this should align with the `worker_shutdown_timeout` setting
	DrainTimeout time.Duration
}

func NginxWithDefaults(configPath string, convertedConfigPath string) (error, int) {
	return Nginx(configPath, convertedConfigPath, DefaultNginxSettings())
}

// `convertedConfigPath` is needed to support host networking
func Nginx(configPath string, convertedConfigPath string, settings *NginxSettings) (error, int) {
	path := configPath
	if hostNetwork, err := warpHostNetwork(); err == nil {
		// use a predictable path to help debugging
		err := convertNginxConfigToHostNetwork(configPath, convertedConfigPath, hostNetwork)
		if err != nil {
			return err, -1
		}
		path = convertedConfigPath
		Err.Printf("Using converted nginx config: %s", path)
	}

	event := NewEvent()
	eventClose := event.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer eventClose()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd, stderr := newNginxCmd(path)

	err := cmd.Start()
	if err != nil {
		return err, -1
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
		case <-time.After(settings.DrainTimeout):
		}

		cmd.Process.Kill()
	}()

	err = cmd.Wait()
	// Wait joins the goroutine feeding the scrubber, so a trailing entry with no
	// final newline is complete and can be flushed here without a race
	if flushErr := stderr.Flush(); flushErr != nil {
		Err.Printf("Could not flush nginx stderr: %s", flushErr)
	}
	if err != nil {
		return err, -1
	}
	return nil, cmd.ProcessState.ExitCode()
}

// nginx inherits stdout directly: the access log format already drops the
// client address (see warpctl NginxConfig), so there is nothing to rewrite on
// the hot path. The error log does need rewriting, and is low enough volume to
// afford it. The scrubber is returned so it can be flushed once nginx exits.
func newNginxCmd(path string) (*exec.Cmd, *ClientAddrScrubber) {
	cmd := exec.Command("nginx", "-g", "daemon off;", "-c", path)
	stderr := NewClientAddrScrubber(os.Stderr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr
	return cmd, stderr
}

// nginx appends the client address to request scoped error entries itself --
// `, client: <addr>` written by the http and stream error handlers -- and
// unlike the access log there is no error log format to override. Removing the
// whole field takes the address whatever family it is written in, and whatever
// nginx writes there in a future version (a unix socket peer is `client: unix:`).
var nginxErrorClientAddrRegex = regexp.MustCompile(`, client: [^,\n]*`)

// what a scrubbed address is replaced with. The field above is removed
// outright; this marks the ones found loose in an entry, where dropping the
// text would leave the entry misleading rather than redacted.
const scrubbedAddr = "[scrubbed]"

// nginx caps an error entry at NGX_MAX_ERROR_STR (2048 bytes). Flushing well
// above that bounds the buffer if something ever writes without a newline,
// while leaving every real entry intact to be matched whole.
const maxNginxErrorEntrySize = 64 * 1024

// Removes addresses from nginx error entries as they stream through, in two
// layers: the `, client: <addr>` field nginx labels itself, and then every ipv4
// and ipv6 literal left anywhere in the entry -- in a request line, a Host
// header, an `upstream:` or `server:` context, or a field a later nginx version
// may add. Nothing is exempt, so no rule about which ranges belong to users can
// be wrong; the port survives, which is what still says which service block an
// entry is about.
//
// Entries are held until their newline arrives, so an address split across two
// writes is still matched.
type ClientAddrScrubber struct {
	out io.Writer
	buf []byte
}

func NewClientAddrScrubber(out io.Writer) *ClientAddrScrubber {
	return &ClientAddrScrubber{
		out: out,
	}
}

func (self *ClientAddrScrubber) Write(b []byte) (int, error) {
	self.buf = append(self.buf, b...)

	// an address cannot span a newline, so everything up to the last one can be
	// scrubbed as a unit
	end := bytes.LastIndexByte(self.buf, '\n') + 1
	if end == 0 {
		if len(self.buf) < maxNginxErrorEntrySize {
			return len(b), nil
		}
		end = len(self.buf)
	}

	scrubbed := self.scrub(self.buf[:end])
	self.buf = append([]byte{}, self.buf[end:]...)

	if _, err := self.out.Write(scrubbed); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (self *ClientAddrScrubber) Flush() error {
	if len(self.buf) == 0 {
		return nil
	}
	scrubbed := self.scrub(self.buf)
	self.buf = nil
	_, err := self.out.Write(scrubbed)
	return err
}

func (self *ClientAddrScrubber) scrub(b []byte) []byte {
	return scrubAddrs(nginxErrorClientAddrRegex.ReplaceAll(b, []byte{}))
}

// an address is written with these and nothing else, so a maximal run of them
// is the only place one can be hiding. Scanning for the runs and parsing each
// one is what makes both families work: an ipv4 literal and every ipv6 form
// (full, compressed, ipv4 mapped) fall out of the same scan, and text that
// merely looks address shaped -- the `15:42:35` of nginx's own timestamp, the
// `0/0` of a stream byte count -- fails to parse and is left alone.
func isAddrByte(b byte) bool {
	switch {
	case '0' <= b && b <= '9':
		return true
	case 'a' <= b && b <= 'f', 'A' <= b && b <= 'F':
		return true
	case b == ':', b == '.', b == '%':
		return true
	}
	return false
}

func scrubAddrs(b []byte) []byte {
	scrubbed := make([]byte, 0, len(b))

	i := 0
	for i < len(b) {
		if !isAddrByte(b[i]) {
			scrubbed = append(scrubbed, b[i])
			i += 1
			continue
		}
		j := i
		for j < len(b) && isAddrByte(b[j]) {
			j += 1
		}

		replacement, ok := scrubAddr(b[i:j])
		if !ok {
			scrubbed = append(scrubbed, b[i:j]...)
			i = j
			continue
		}
		// ipv6 with a port is written `[addr]:port`, and the brackets belong to
		// the address that is going away
		if 0 < len(scrubbed) && scrubbed[len(scrubbed)-1] == '[' && j < len(b) && b[j] == ']' {
			scrubbed = scrubbed[:len(scrubbed)-1]
			j += 1
		}
		scrubbed = append(scrubbed, replacement...)
		i = j
	}

	return scrubbed
}

// `token` is a maximal run of address bytes, so more than the address can be in
// it
func scrubAddr(token []byte) ([]byte, bool) {
	// a zone is an interface name rather than part of the address, and only its
	// leading hex characters are in the token at all (`fe80::1%eth0` runs out at
	// the `t`), so the address ends where the zone starts
	addrEnd := len(token)
	if percent := bytes.IndexByte(token, '%'); 0 <= percent {
		addrEnd = percent
	}

	// the token can also carry a port (`10.0.0.4:80`) and trailing punctuation
	// from the surrounding text (`10.0.0.4.`), while a trailing separator can
	// equally be part of the address itself (`::`). So the longest prefix that
	// parses wins, and whatever follows it is text that stays.
	for end := addrEnd; 0 < end; end -= 1 {
		candidate := string(token[:end])

		if _, err := netip.ParseAddr(candidate); err == nil {
			return append([]byte(scrubbedAddr), token[end:]...), true
		}
		// ipv6 is only written with a port inside brackets, which are not
		// address bytes, so this is the ipv4 `addr:port` case. The port is not
		// an address and says which service block the entry is about, so it is
		// put back.
		if addrPort, err := netip.ParseAddrPort(candidate); err == nil {
			scrubbed := scrubbedAddr + ":" + strconv.Itoa(int(addrPort.Port()))
			return append([]byte(scrubbed), token[end:]...), true
		}
	}

	return nil, false
}

type HostNetwork struct {
	Ipv4      *netip.Addr
	Ipv6      *netip.Addr
	HostPorts map[int]int
}

func warpHostNetwork() (*HostNetwork, error) {
	ipv4 := os.Getenv("WARP_HOST_IPV4")
	ipv6 := os.Getenv("WARP_HOST_IPV6")
	if ipv4 == "" && ipv6 == "" {
		return nil, errors.New("WARP_HOST_IPV4 and WARP_HOST_IPV6 not set")
	}

	var ipv4Addr *netip.Addr
	var ipv6Addr *netip.Addr
	if ipv4 != "" {
		ipv4Addr_, err := netip.ParseAddr(ipv4)
		if err != nil {
			return nil, err
		}
		ipv4Addr = &ipv4Addr_
	}
	if ipv6 != "" {
		ipv6Addr_, err := netip.ParseAddr(ipv6)
		if err != nil {
			return nil, err
		}
		ipv6Addr = &ipv6Addr_
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
		return err
	}

	reusePort := false
	portCounts := map[netip.AddrPort]int{}

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
				if hostNetwork.Ipv6 == nil {
					return fmt.Errorf("IPv6 host network needed for port %d", port)
				}
				hostAddr = *hostNetwork.Ipv6
			} else {
				if hostNetwork.Ipv4 == nil {
					return fmt.Errorf("IPv4 host network needed for port %d", port)
				}
				hostAddr = *hostNetwork.Ipv4
			}
		} else {
			// the default nginx interface is ipv4
			if hostNetwork.Ipv4 == nil {
				return fmt.Errorf("IPv4 host network needed for port %d", port)
			}
			hostAddr = *hostNetwork.Ipv4
		}
		hostAddrPort := netip.AddrPortFrom(hostAddr, uint16(hostPort))

		portCounts[hostAddrPort] += 1
		firstListenOnHostPort := (portCounts[hostAddrPort] == 1)

		var template string
		// host network uses SO_REUSEPORT
		if reusePort && firstListenOnHostPort && !strings.Contains(string(content[submatches[8]:submatches[9]]), "reuseport") {
			template = fmt.Sprintf("${1}listen %s${4} reuseport;", hostAddrPort)
		} else {
			template = fmt.Sprintf("${1}listen %s${4};", hostAddrPort)
		}
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
