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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// **important** warpctl config should align `worker_shutdown_timeout` with this
const DefaultDrainTimeout = 60 * time.Minute

// What §13.4's SNI split (W1) keeps at run time beside each interface's nginx.
// warpctl's render names these paths, and the lb process makes them before
// nginx starts, since `nginx -t` needs both includes even while they are empty.
const (
	// The directory the lb process makes for the split's files.
	LbRunDir = "/run/warp-lb"
	// The http servers' 443 listener behind the split's stream server.
	LbHttpsSocketPath = "/run/warp-lb/https.sock"
	// The split map's custom-host lines, one `<host> <upstream>;` each, which
	// lbmap writes (D-TLS-12, TLS-M6-01). Empty until then.
	LbTlsCustomHostsMapPath = "/run/warp-lb/tls-custom-hosts.map"
	// The port 80 redirect server for those hosts, which lbmap writes. Empty
	// until then.
	LbTlsCustomHosts80Path = "/run/warp-lb/tls-custom-hosts-80.conf"
)

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

// Makes runDir ready for an nginx whose config renders §13.4's split, before
// nginx starts: the directory itself, open to the workers that connect to
// its socket; no https.sock left behind, since bind fails on one, and Nginx's
// kill path leaves one when it ends nginx without a drain; and both custom
// host includes, empty when absent, since `nginx -t` refuses a config whose
// include is missing and lbmap writes them only once it runs (TLS-M6-01). An
// include already there is lbmap's, and stays. A file at the socket's path
// that is not a socket is refused rather than removed.
func PrepareLbRunDir(runDir string) error {
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	socketPath := filepath.Join(runDir, filepath.Base(LbHttpsSocketPath))
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode().Type() != os.ModeSocket {
			return fmt.Errorf("%s is not a socket", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, includePath := range []string{LbTlsCustomHostsMapPath, LbTlsCustomHosts80Path} {
		path := filepath.Join(runDir, filepath.Base(includePath))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
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

// nginx also writes a url into request scoped error entries, each with its
// query string: the request line, the `upstream:` it was proxying to, and the
// `referrer:` the client sent. These cut the query out of each, so an entry
// keeps the path that says which route failed. There is no error log format to
// override, and a url nginx accepts has no space in it, so a query runs to the
// next space, past any quote in it. The referrer is a header that may have
// spaces, and it is the last field of an entry. A request line with no
// protocol is HTTP/0.9, which the second expression covers with the upstream.
var (
	nginxErrorRequestQueryRegex  = regexp.MustCompile(`(, request: "\S+ +[^?\s]*)\?\S*( +HTTP/\d\.\d")`)
	nginxErrorUrlQueryRegex      = regexp.MustCompile(`(, (?:request: "\S+ +|upstream: ")[^?\s]*)\?\S*"`)
	nginxErrorReferrerQueryRegex = regexp.MustCompile(`(, referrer: "[^?\n]*)\?[^\n]*"`)
)

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
// It also removes the query string of each url nginx writes into an entry,
// which no access log format reaches: a log_uri host keeps its query strings
// out of the access log, and an upstream failure would otherwise put them here.
// Nothing is exempt here either, whatever the host, since the entry alone does
// not always say which host it is about.
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
	b = nginxErrorClientAddrRegex.ReplaceAll(b, []byte{})
	b = nginxErrorRequestQueryRegex.ReplaceAll(b, []byte("$1$2"))
	b = nginxErrorUrlQueryRegex.ReplaceAll(b, []byte(`$1"`))
	b = nginxErrorReferrerQueryRegex.ReplaceAll(b, []byte(`$1"`))
	return scrubAddrs(b)
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

// ScrubAddrs replaces every IPv4 and IPv6 literal in b with `[scrubbed]`,
// keeping an ipv4 port. Exported so that service processes scrub their own
// logging with the same implementation the lb uses for nginx's error log
// (see server.ScrubProcessLogs) -- one scrubber, one set of tests, rather than
// a second copy that can drift from this one.
//
// The input is arbitrary text: the scan finds maximal runs of address bytes and
// keeps only the runs that actually parse, so surrounding words, timestamps and
// byte counts survive.
func ScrubAddrs(b []byte) []byte {
	return scrubAddrs(b)
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
	// 1 = where the listen starts: a line's start, or the ; that ends the
	//     directive before it on the same line or the line before. That ; is
	//     kept: a directive this does not rewrite, as §13.4's `listen unix:`
	//     is not, would otherwise lose its own ; to the listen after it
	// 2 = indent
	// 3 = ip:port
	// 4 = port
	// 5 = options
	listenRe := regexp.MustCompile("(?m)(^|;)(\\s*)listen\\s+((?:[^;]+:)?(\\d+))(\\s+[^;]+)?;")

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
		ipPort := string(content[submatches[6]:submatches[7]])
		addrPort, err := netip.ParseAddrPort(ipPort)
		if err == nil {
			addr = addrPort.Addr()
			addrOk = true
			port = int(addrPort.Port())
		} else {
			// just parse the port
			port, err = strconv.Atoi(string(content[submatches[8]:submatches[9]]))
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
		if reusePort && firstListenOnHostPort && 0 <= submatches[10] && !strings.Contains(string(content[submatches[10]:submatches[11]]), "reuseport") {
			template = fmt.Sprintf("${1}${2}listen %s${5} reuseport;", hostAddrPort)
		} else {
			template = fmt.Sprintf("${1}${2}listen %s${5};", hostAddrPort)
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
