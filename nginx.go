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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	// The split map's custom-host lines, one `<host> <upstream>;` each, and the
	// line for the map version's probe name, which lbmap writes (D-TLS-12,
	// TLS-M6-01). Empty until then.
	LbTlsCustomHostsMapPath = "/run/warp-lb/tls-custom-hosts.map"
	// The port 80 redirect's custom names, one `server_name <host>;` each,
	// which the redirect server for the roots' names includes and lbmap
	// writes. Empty until then.
	LbTlsCustomHosts80Path = "/run/warp-lb/tls-custom-hosts-80.conf"
)

func DefaultNginxSettings() *NginxSettings {
	return &NginxSettings{
		DrainTimeout:        DefaultDrainTimeout,
		WorkerCheckInterval: 100 * time.Millisecond,
	}
}

type NginxSettings struct {
	// this should align with the `worker_shutdown_timeout` setting
	DrainTimeout time.Duration
	// How often NginxControl reads the master's children while it waits for a
	// worker, at start or after a reload. A master forks its workers within
	// milliseconds of loading its config, so a tenth of a second keeps the wait
	// short without reading the process table hot. Must be positive.
	WorkerCheckInterval time.Duration
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

// The config path nginx runs: configPath, or under host networking (the
// WARP_HOST_* variables set) its conversion to the host's addresses and
// ports, written to convertedConfigPath, a predictable path to help
// debugging. `nginx -t` and a reload must read this path, never the original.
func NginxRunConfigPath(configPath string, convertedConfigPath string) (string, error) {
	hostNetwork, err := warpHostNetwork()
	if err != nil {
		return configPath, nil
	}
	if err := convertNginxConfigToHostNetwork(configPath, convertedConfigPath, hostNetwork); err != nil {
		return "", err
	}
	Err.Printf("Using converted nginx config: %s", convertedConfigPath)
	return convertedConfigPath, nil
}

// `convertedConfigPath` is needed to support host networking
func Nginx(configPath string, convertedConfigPath string, settings *NginxSettings) (error, int) {
	path, err := NginxRunConfigPath(configPath, convertedConfigPath)
	if err != nil {
		return err, -1
	}

	event := NewEvent()
	eventClose := event.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer eventClose()

	process := NewNginxProcess(path, settings)
	if err := process.Start(event.Ctx); err != nil {
		return err, -1
	}
	return process.Wait()
}

// The arguments nginx runs path with: in the foreground, which `daemon off`
// keeps the master as this process's child, so its pid needs no pid file.
func nginxArgs(path string) []string {
	return []string{"-g", "daemon off;", "-c", path}
}

// nginx inherits stdout directly: the access log format already drops the
// client address (see warpctl NginxConfig), so there is nothing to rewrite on
// the hot path. The error log does need rewriting, and is low enough volume to
// afford it. The scrubber is returned so it can be flushed once nginx exits.
func newNginxCmd(path string) (*exec.Cmd, *ClientAddrScrubber) {
	return newNginxCmdWithArgs("nginx", nginxArgs(path))
}

func newNginxCmdWithArgs(binary string, args []string) (*exec.Cmd, *ClientAddrScrubber) {
	cmd := exec.Command(binary, args...)
	stderr := NewClientAddrScrubber(os.Stderr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr
	return cmd, stderr
}

// The nginx master an lb process runs, as lbmap tests and reloads it
// (TLS-M6-01, §13.4): its pid and start time, `nginx -t` on the config path it
// runs, and a reload by SIGHUP. An lb's master runs under `daemon off`, as the
// lb process's own child, so nothing here reads a pid file.
//
// A reload is confirmed by the master's children, since the lb's error log is
// at error level and nginx says nothing there when a reload works: the master
// forks new workers only once it has loaded its config again, keeps the ones
// it has when that fails, and on success tells the old ones to stop, which
// then close their listeners and retitle themselves "is shutting down". So a
// reload is done once the master runs a child it did not run before the
// signal and every child from before it has exited or is shutting down: then
// only the new config takes connections, the rule W5's certs swap keeps too.
// Two things can stand in for that and are not caught here: a worker the
// master respawns after a crash, and a reload someone else signalled
// (sidecarctl's certs swap, W5) that read the config before lbmap rewrote its
// include. The dns edges' route probes are the check on both: an interface
// whose nginx does not route the probe name of the version it reported is not
// current for it (§13.4, FS-122).
//
// Implementations are safe for concurrent use.
type NginxControl interface {
	// Waits until the master runs a worker, which it forks only once it has
	// loaded its config, and answers the master. An error once the master has
	// exited or ctx ends.
	Master(ctx context.Context) (*NginxMaster, error)
	// Runs `nginx -t` on the config the master runs, with the master's own
	// arguments. Works before the master starts. The error carries nginx's
	// output, addresses scrubbed.
	Test(ctx context.Context) error
	// Sends the master SIGHUP and waits until it runs a child it did not run
	// before the signal and every child from before it has exited or is
	// shutting down. An error when no master runs, or that does not happen
	// before ctx ends, which is how a master that refused the config looks.
	Reload(ctx context.Context) error
}

// One nginx master: what a report names, and what changes when nginx
// restarts (§13.4: an interface whose master changed has loaded no version).
type NginxMaster struct {
	Pid int
	// When this process started it, or, for a master started elsewhere, when
	// its starter says it did.
	StartTime time.Time
}

// nginx as this process runs it: started once, then waited for. Safe for
// concurrent use; Start and Wait are each called once.
type NginxProcess struct {
	binary   string
	args     []string
	settings *NginxSettings

	stateLock sync.Mutex
	// set at Start: the master and its control
	control *nginxMasterControl
	// closed when Start has run, whether or not it started nginx
	started chan struct{}
	// closed once the master has exited and its stderr is flushed
	exited   chan struct{}
	waitErr  error
	exitCode int
}

// nginx on path, in the foreground, as the lb runs it. Not yet started.
func NewNginxProcess(path string, settings *NginxSettings) *NginxProcess {
	return newNginxProcess("nginx", nginxArgs(path), settings)
}

func newNginxProcess(binary string, args []string, settings *NginxSettings) *NginxProcess {
	return &NginxProcess{
		binary:   binary,
		args:     slices.Clone(args),
		settings: settings,
		started:  make(chan struct{}),
		exited:   make(chan struct{}),
	}
}

// Starts the master, its stderr through the address scrubber. Once stopCtx
// ends the master gets SIGQUIT, a graceful drain, and is killed if it is still
// running after the settings' DrainTimeout.
func (self *NginxProcess) Start(stopCtx context.Context) error {
	defer close(self.started)
	cmd, stderr := newNginxCmdWithArgs(self.binary, self.args)
	if err := cmd.Start(); err != nil {
		close(self.exited)
		return err
	}
	master := &NginxMaster{Pid: cmd.Process.Pid, StartTime: time.Now()}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.control = newNginxMasterControl(self.binary, self.args, master, self.exited, self.settings)
	}()
	go func() {
		err := cmd.Wait()
		// Wait joins the goroutine feeding the scrubber, so a trailing entry with
		// no final newline is complete and can be flushed here without a race
		if flushErr := stderr.Flush(); flushErr != nil {
			Err.Printf("Could not flush nginx stderr: %s", flushErr)
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if err != nil {
				self.waitErr = err
				self.exitCode = -1
			} else {
				self.exitCode = cmd.ProcessState.ExitCode()
			}
		}()
		close(self.exited)
	}()
	go func() {
		select {
		case <-self.exited:
			return
		case <-stopCtx.Done():
		}

		cmd.Process.Signal(syscall.SIGQUIT)

		select {
		case <-self.exited:
			return
		case <-time.After(self.settings.DrainTimeout):
		}

		cmd.Process.Kill()
	}()
	return nil
}

// Waits for the master to exit: an error when it could not be waited for, else
// its exit code.
func (self *NginxProcess) Wait() (error, int) {
	<-self.exited
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.control == nil {
		return errors.New("nginx was not started"), -1
	}
	return self.waitErr, self.exitCode
}

// The master's control once Start has run, or nil when it started nothing.
func (self *NginxProcess) startedControl(ctx context.Context) (*nginxMasterControl, error) {
	select {
	case <-self.started:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.control == nil {
		return nil, errors.New("nginx did not start")
	}
	return self.control, nil
}

func (self *NginxProcess) Master(ctx context.Context) (*NginxMaster, error) {
	control, err := self.startedControl(ctx)
	if err != nil {
		return nil, err
	}
	return control.Master(ctx)
}

// Needs no running master, so lbmap tests the map it loads before nginx starts.
func (self *NginxProcess) Test(ctx context.Context) error {
	return runNginxTest(ctx, self.binary, self.args)
}

func (self *NginxProcess) Reload(ctx context.Context) error {
	var control *nginxMasterControl
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		control = self.control
	}()
	if control == nil {
		return errors.New("nginx is not running")
	}
	return control.Reload(ctx)
}

// A control over a master started elsewhere: binary and args are the ones it
// runs, master its pid and start time, exited closes when it has exited (nil
// when its starter cannot tell, which leaves the pid's existence to decide).
// How a test harness that started nginx itself hands it to lbmap.
func NewNginxControl(binary string, args []string, master NginxMaster, exited <-chan struct{}, settings *NginxSettings) NginxControl {
	return newNginxMasterControl(binary, args, &master, exited, settings)
}

// One running master's control. Safe for concurrent use; it holds no mutable
// state.
type nginxMasterControl struct {
	binary   string
	args     []string
	master   *NginxMaster
	exited   <-chan struct{}
	settings *NginxSettings
}

func newNginxMasterControl(binary string, args []string, master *NginxMaster, exited <-chan struct{}, settings *NginxSettings) *nginxMasterControl {
	return &nginxMasterControl{
		binary:   binary,
		args:     slices.Clone(args),
		master:   master,
		exited:   exited,
		settings: settings,
	}
}

// Whether the master has exited: its exited channel closed, or with none,
// its pid gone.
func (self *nginxMasterControl) masterExited() bool {
	if self.exited != nil {
		select {
		case <-self.exited:
			return true
		default:
			return false
		}
	}
	return errors.Is(syscall.Kill(self.master.Pid, 0), syscall.ESRCH)
}

// Reads the master's children every WorkerCheckInterval until done says
// they are what it waits for. An error once the master exits or ctx ends.
func (self *nginxMasterControl) awaitChildren(ctx context.Context, done func(children map[int]string) bool) error {
	for {
		if self.masterExited() {
			return fmt.Errorf("nginx master %d exited", self.master.Pid)
		}
		children, err := nginxChildren(self.master.Pid)
		if err != nil {
			return err
		}
		if done(children) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.exited:
		case <-time.After(self.settings.WorkerCheckInterval):
		}
	}
}

func (self *nginxMasterControl) Master(ctx context.Context) (*NginxMaster, error) {
	err := self.awaitChildren(ctx, func(children map[int]string) bool {
		return 0 < len(children)
	})
	if err != nil {
		return nil, err
	}
	master := *self.master
	return &master, nil
}

func (self *nginxMasterControl) Test(ctx context.Context) error {
	return runNginxTest(ctx, self.binary, self.args)
}

func (self *nginxMasterControl) Reload(ctx context.Context) error {
	if self.masterExited() {
		return fmt.Errorf("nginx master %d exited", self.master.Pid)
	}
	childrenBefore, err := nginxChildren(self.master.Pid)
	if err != nil {
		return err
	}
	if err := syscall.Kill(self.master.Pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal nginx master %d: %w", self.master.Pid, err)
	}
	err = self.awaitChildren(ctx, func(children map[int]string) bool {
		newChild := false
		for pid := range children {
			if _, before := childrenBefore[pid]; !before {
				newChild = true
			}
		}
		if !newChild {
			return false
		}
		// a child from before the signal that still takes connections would
		// serve the old config beside the new one
		for pid := range childrenBefore {
			if title, running := children[pid]; running && !strings.Contains(title, nginxShuttingDownTitle) {
				return false
			}
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("nginx master %d did not move to new workers after the reload: %w", self.master.Pid, err)
	}
	return nil
}

// What nginx adds to a worker's title once it has stopped taking connections
// and drains the ones it has.
const nginxShuttingDownTitle = "is shutting down"

// The master's children, pid to process title, less those that have exited
// and wait to be reaped: from /proc on linux, where the lb runs; elsewhere
// from ps, which the tests on a desktop read.
func nginxChildren(parentPid int) (map[int]string, error) {
	children := map[int]string{}
	if runtime.GOOS != "linux" {
		output, err := exec.Command("ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "stat=", "-o", "command=").Output()
		if err != nil {
			return nil, fmt.Errorf("ps: %w", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			pid, pidErr := strconv.Atoi(fields[0])
			ppid, ppidErr := strconv.Atoi(fields[1])
			if pidErr != nil || ppidErr != nil || ppid != parentPid || strings.HasPrefix(fields[2], "Z") {
				continue
			}
			children[pid] = strings.Join(fields[3:], " ")
		}
		return children, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		// a process can exit between the listing and the read
		stat, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		// `pid (comm) state ppid ...`: comm may hold spaces and parentheses, so
		// the fields start after the last one
		closeParen := bytes.LastIndexByte(stat, ')')
		if closeParen < 0 {
			continue
		}
		fields := strings.Fields(string(stat[closeParen+1:]))
		if len(fields) < 2 || fields[0] == "Z" {
			continue
		}
		if ppid, err := strconv.Atoi(fields[1]); err != nil || ppid != parentPid {
			continue
		}
		// nginx writes its title over argv, padded with zero bytes
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		children[pid] = strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
	}
	return children, nil
}

// `nginx -t` with the master's arguments, so it reads the same config path,
// prefix and globals. Its output on a failure, addresses scrubbed.
func runNginxTest(ctx context.Context, binary string, args []string) error {
	cmd := exec.CommandContext(ctx, binary, append([]string{"-t"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("nginx -t: %w", ctx.Err())
		}
		return fmt.Errorf("nginx -t: %w: %s", err, strings.TrimSpace(string(ScrubAddrs(output))))
	}
	return nil
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
