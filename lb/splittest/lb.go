//go:build linux || darwin

package splittest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/urnetwork/warp"
)

// What one Lb runs. DefaultSettings fills every field.
type Settings struct {
	// The nginx binary, from FindBinary.
	Binary string
	// Whether the split fronts the http server, as on a flipped interface.
	// False runs the http server on the port itself, as on one not flipped:
	// splitbench's B side, the same binary and config less the split.
	Split bool
	// The split's roots and the platform names left under them, which keep
	// the http server; every other name under a root goes to the edge.
	Roots         []string
	PlatformNames []string
	// The custom-host include's lines as lbmap writes them, `<host> <upstream>;`
	// with the edge's upstream named EdgeUpstream.
	CustomHostLines []string
	// tlsedge.yml's client_hello, the split's preread bounds.
	ClientHelloTimeout  time.Duration
	ClientHelloMaxBytes int
	// The split stream server's proxy_buffer_size; 0 leaves nginx's.
	ProxyBufferByteCount int
	// How long Start waits for nginx to start its worker, and Close for it to
	// drain before it is killed.
	StartTimeout time.Duration
	StopTimeout  time.Duration
}

// The split's upstream for the edge, as the render names tlsedge's 443.
const EdgeUpstream = "stream-service-block-tlsedge-443"

// The /limited location's per-address zone: one request a minute, no burst,
// so a second request from one address is refused and one from another is not.
const limitedPath = "/limited"

// The split as the fixtures write it: one root, one platform name under it,
// §13.5's hello bounds.
func DefaultSettings(binary string) *Settings {
	return &Settings{
		Binary:              binary,
		Split:               true,
		Roots:               []string{"root.example"},
		PlatformNames:       []string{"api.root.example"},
		ClientHelloTimeout:  10 * time.Second,
		ClientHelloMaxBytes: 16384,
		StartTimeout:        10 * time.Second,
		StopTimeout:         5 * time.Second,
	}
}

// One nginx running the split on loopback, with its backends.
type Lb struct {
	settings *Settings
	// the port nginx takes on 127.0.0.1 and ::1
	Port int
	// the split's run directory: socket and includes
	RunDir string
	// nginx's prefix: its config, pid and temp files
	prefixDir string
	Edge      *EdgeBackend
	Http      *HttpBackend
	// trusts the http server's certificate, which names every root, platform
	// name and wildcard under a root
	CertPool *x509.CertPool

	stateLock sync.Mutex
	cmd       *exec.Cmd
	// nginx's stderr through warp's ClientAddrScrubber, as the lb process
	// writes it
	scrubbedLog bytes.Buffer
	// the same stderr unscrubbed, kept only in memory, so a test can show
	// the scrubber had addresses to take out
	rawLog bytes.Buffer
	exited chan struct{}
	// the last nginx run's exit, for its resource use
	processState *os.ProcessState
}

// Starts nginx with settings and fresh backends, returning once its worker
// runs. Close ends it.
func Start(settings *Settings) (*Lb, error) {
	lb := &Lb{settings: settings}
	ok := false
	defer func() {
		if !ok {
			lb.Close()
		}
	}()
	var err error
	// short: a unix socket's path has a small bound
	if lb.RunDir, err = os.MkdirTemp("", "warp-lb"); err != nil {
		return nil, err
	}
	if lb.prefixDir, err = os.MkdirTemp("", "warp-lb-nginx"); err != nil {
		return nil, err
	}
	if lb.Edge, err = NewEdgeBackend(); err != nil {
		return nil, err
	}
	if lb.Http, err = NewHttpBackend(); err != nil {
		return nil, err
	}
	if lb.Port, err = freeLoopbackPort(); err != nil {
		return nil, err
	}
	if err := lb.writeCertificate(); err != nil {
		return nil, err
	}
	if err := warp.PrepareLbRunDir(lb.RunDir); err != nil {
		return nil, err
	}
	customHosts := strings.Join(settings.CustomHostLines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(lb.RunDir, filepath.Base(warp.LbTlsCustomHostsMapPath)), []byte(customHosts), 0644); err != nil {
		return nil, err
	}
	if err := lb.writeConfig(); err != nil {
		return nil, err
	}
	if err := lb.start(); err != nil {
		return nil, err
	}
	ok = true
	return lb, nil
}

// A port free on both loopback families now.
func freeLoopbackPort() (int, error) {
	for range 16 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		ipv6Listener, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
		listener.Close()
		if err != nil {
			continue
		}
		ipv6Listener.Close()
		return port, nil
	}
	return 0, errors.New("no port free on both loopback families")
}

// The http server's names: each root, a wildcard under it and each platform
// name, so a visitor on the http branch can verify whatever name it asked for
// under a root.
func (self *Lb) certificateNames() []string {
	names := []string{}
	for _, root := range self.settings.Roots {
		names = append(names, root, "*."+root)
	}
	return append(names, self.settings.PlatformNames...)
}

// Writes a self-signed certificate for the http server and keeps its pool.
func (self *Lb) writeCertificate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "split test http server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		DNSNames:              self.certificateNames(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	self.CertPool = x509.NewCertPool()
	self.CertPool.AddCert(leaf)
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(self.prefixDir, "http.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(self.prefixDir, "http.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0600)
}

// The config: warpctl's split directives on the loopback port, and an http
// server proxying to the http upstream as the render's servers do.
var configTemplate = template.Must(template.New("nginx.conf").Parse(`
pid {{.prefixDir}}/nginx.pid;
daemon off;
worker_processes 1;
error_log stderr info;

events {
    worker_connections 1024;
}

http {
    access_log off;
    proxy_http_version 1.1;
{{- if .split}}
    # as warpctl's render: only the split's stream server reaches the socket
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;
{{- end}}
    map $remote_addr $warp_client_addr {
        default $remote_addr;
        "~:" "[$remote_addr]";
    }
    limit_req_status 429;
    limit_req_zone $binary_remote_addr zone=pervisitor:1m rate=1r/m;
    upstream http-backend {
        server {{.httpBackend}};
    }
    server {
{{- if .split}}
        listen unix:{{.socket}} ssl proxy_protocol backlog=65535;
{{- else}}
        listen 127.0.0.1:{{.port}} ssl;
        listen [::1]:{{.port}} ssl;
{{- end}}
        server_name _;
        ssl_certificate {{.prefixDir}}/http.pem;
        ssl_certificate_key {{.prefixDir}}/http.key;
        proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header Host $host;
        location {{.limitedPath}} {
            limit_req zone=pervisitor nodelay;
            proxy_pass http://http-backend;
        }
        location /ws {
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_pass http://http-backend;
        }
        location / {
            proxy_pass http://http-backend;
        }
    }
{{- if .split}}
    include {{.customHosts80}};
{{- end}}
}
{{- if .split}}

stream {
    map_hash_bucket_size 512;
    map $ssl_preread_server_name $tls_split_upstream {
        hostnames;
{{- range .httpsNames}}
        {{.}} lb-https;
{{- end}}
{{- range .roots}}
        *.{{.}} {{$.edgeUpstream}};
{{- end}}
        include {{.customHosts}};
        default lb-https;
    }
    upstream lb-https {
        server unix:{{.socket}};
    }
    upstream {{.edgeUpstream}} {
        server {{.edgeBackend}};
    }
    server {
        listen 127.0.0.1:{{.port}} reuseport backlog=65535;
        listen [::1]:{{.port}} reuseport backlog=65535;
        ssl_preread on;
        preread_timeout {{.helloTimeoutSeconds}}s;
        preread_buffer_size {{.helloMaxBytes}};
        proxy_protocol on;
        proxy_pass $tls_split_upstream;
{{- if .proxyBufferByteCount}}
        proxy_buffer_size {{.proxyBufferByteCount}};
{{- end}}
    }
}
{{- end}}
`))

// Writes nginx.conf into the prefix directory.
func (self *Lb) writeConfig() error {
	httpsNames := append(append([]string{}, self.settings.Roots...), self.settings.PlatformNames...)
	var config bytes.Buffer
	err := configTemplate.Execute(&config, map[string]any{
		"prefixDir":            self.prefixDir,
		"split":                self.settings.Split,
		"socket":               filepath.Join(self.RunDir, filepath.Base(warp.LbHttpsSocketPath)),
		"customHosts":          filepath.Join(self.RunDir, filepath.Base(warp.LbTlsCustomHostsMapPath)),
		"customHosts80":        filepath.Join(self.RunDir, filepath.Base(warp.LbTlsCustomHosts80Path)),
		"port":                 self.Port,
		"httpBackend":          self.Http.Address(),
		"edgeBackend":          self.Edge.Address(),
		"edgeUpstream":         EdgeUpstream,
		"limitedPath":          limitedPath,
		"httpsNames":           httpsNames,
		"roots":                self.settings.Roots,
		"helloTimeoutSeconds":  int(self.settings.ClientHelloTimeout / time.Second),
		"helloMaxBytes":        self.settings.ClientHelloMaxBytes,
		"proxyBufferByteCount": self.settings.ProxyBufferByteCount,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(self.prefixDir, "nginx.conf"), config.Bytes(), 0644)
}

// The config Start wrote, for a test or a report to show.
func (self *Lb) Config() (string, error) {
	config, err := os.ReadFile(filepath.Join(self.prefixDir, "nginx.conf"))
	return string(config), err
}

// nginx's line for a worker it has forked, with the worker's pid: after its
// sockets are bound, and unlike "start worker processes", after the fork, so a
// signal to the group then reaches the worker too.
var workerStartedRegex = regexp.MustCompile(`start worker process [0-9]+`)

// Starts nginx in its own process group, its stderr through the scrubber, and
// waits for its worker.
func (self *Lb) start() error {
	cmd := exec.Command(self.settings.Binary, "-p", self.prefixDir+string(os.PathSeparator), "-c", filepath.Join(self.prefixDir, "nginx.conf"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	started := make(chan struct{})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.cmd = cmd
		self.exited = exited
	}()
	go func() {
		scrubber := warp.NewClientAddrScrubber(&lockedWriter{lock: &self.stateLock, buffer: &self.scrubbedLog})
		reader := bufio.NewReader(stderr)
		startedOnce := sync.Once{}
		for {
			line, err := reader.ReadBytes('\n')
			if 0 < len(line) {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.rawLog.Write(line)
				}()
				scrubber.Write(line)
				if workerStartedRegex.Match(line) {
					startedOnce.Do(func() { close(started) })
				}
			}
			if err != nil {
				scrubber.Flush()
				break
			}
		}
		cmd.Wait()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.processState = cmd.ProcessState
		}()
		close(exited)
	}()
	select {
	case <-started:
		return nil
	case <-exited:
		return fmt.Errorf("nginx exited before its worker started:\n%s", self.ScrubbedErrorLog())
	case <-time.After(self.settings.StartTimeout):
		return fmt.Errorf("nginx did not start its worker in %v:\n%s", self.settings.StartTimeout, self.ScrubbedErrorLog())
	}
}

// Writes under a lock the reader of the buffer takes too.
type lockedWriter struct {
	lock   *sync.Mutex
	buffer *bytes.Buffer
}

func (self *lockedWriter) Write(b []byte) (int, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	return self.buffer.Write(b)
}

// nginx's error log as the lb process writes it, addresses scrubbed.
func (self *Lb) ScrubbedErrorLog() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.scrubbedLog.String()
}

// nginx's error log as nginx wrote it, which never leaves memory.
func (self *Lb) RawErrorLog() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.rawLog.String()
}

// Signals nginx's process group and waits up to timeout for it to exit.
func (self *Lb) signal(signal syscall.Signal, timeout time.Duration) error {
	var cmd *exec.Cmd
	var exited chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cmd = self.cmd
		exited = self.exited
	}()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	syscall.Kill(-cmd.Process.Pid, signal)
	select {
	case <-exited:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("nginx did not exit on %v", signal)
	}
}

// What the last nginx run used, once it has exited: CPU time, user and
// system, of the master and every worker it waited for, and the largest
// resident set among them. An error while it runs.
func (self *Lb) Usage() (cpu time.Duration, maxRssBytes int64, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.processState == nil {
		return 0, 0, errors.New("nginx has not exited")
	}
	rusage, ok := self.processState.SysUsage().(*syscall.Rusage)
	if !ok || rusage == nil {
		return 0, 0, errors.New("no resource use for nginx")
	}
	cpu = time.Duration(rusage.Utime.Nano()) + time.Duration(rusage.Stime.Nano())
	maxRssBytes = int64(rusage.Maxrss)
	// Linux counts ru_maxrss in KiB, Darwin in bytes
	if runtime.GOOS == "linux" {
		maxRssBytes *= 1024
	}
	return cpu, maxRssBytes, nil
}

// Ends nginx as Nginx's kill path does, with no drain, which leaves its
// socket behind.
func (self *Lb) Kill() error {
	return self.signal(syscall.SIGKILL, self.settings.StopTimeout)
}

// Starts nginx again on the same directories and port, as the lb process
// does: the run directory prepared first, then nginx.
func (self *Lb) Restart() error {
	if err := warp.PrepareLbRunDir(self.RunDir); err != nil {
		return err
	}
	return self.start()
}

// Drains nginx, killing it past StopTimeout, then ends the backends and
// removes the directories.
func (self *Lb) Close() error {
	var err error
	if self.settings != nil {
		if err = self.signal(syscall.SIGQUIT, self.settings.StopTimeout); err != nil {
			self.signal(syscall.SIGKILL, self.settings.StopTimeout)
		}
	}
	if self.Edge != nil {
		self.Edge.Close()
	}
	if self.Http != nil {
		self.Http.Close()
	}
	for _, dir := range []string{self.RunDir, self.prefixDir} {
		if dir != "" {
			os.RemoveAll(dir)
		}
	}
	return err
}

// The address a visitor dials: 127.0.0.1 for "tcp4", ::1 for "tcp6".
func (self *Lb) Address(network string) string {
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	return net.JoinHostPort(host, strconv.Itoa(self.Port))
}

// Dials the lb from network's loopback and completes TLS on the http branch
// for serverName, an empty one sending no SNI. insecure skips verifying the
// name, for a name the http server's certificate does not carry.
func (self *Lb) DialHttps(network string, serverName string, insecure bool) (*tls.Conn, error) {
	conn, err := net.Dial(network, self.Address(network))
	if err != nil {
		return nil, err
	}
	config := &tls.Config{ServerName: serverName, RootCAs: self.CertPool, InsecureSkipVerify: insecure || serverName == ""}
	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(self.settings.StartTimeout))
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}
