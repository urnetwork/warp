package warp

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// the lb must not record the addresses of the users passing through it. nginx
// writes them into error entries itself, so these are real entries captured
// from nginx 1.31.3 and must come out the other side without an address.
func TestClientAddrScrubber(t *testing.T) {
	out := &bytes.Buffer{}
	scrubber := NewClientAddrScrubber(out)

	// http request error
	_, err := scrubber.Write([]byte(`2026/08/12 15:42:35 [error] 73966#0: *2 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.9, server: , request: "GET /dead HTTP/1.1", upstream: "http://10.0.0.4:80/dead", host: "main-lb.bringyour.com"` + "\n"))
	assert.Equal(t, err, nil)

	// stream proxy error. `bytes from/to client:0/0` is a byte count, not an
	// address, and has to survive
	_, err = scrubber.Write([]byte(`2026/08/12 15:43:33 [error] 74084#0: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.9, server: 0.0.0.0:443, upstream: "10.0.0.4:80", bytes from/to client:0/0, bytes from/to upstream:0/0` + "\n"))
	assert.Equal(t, err, nil)

	// ipv6 address, and the client field last on the line
	_, err = scrubber.Write([]byte(`2026/08/12 15:44:01 [info] 74084#0: *3 client closed connection while waiting for request, client: 2001:db8::dead:beef` + "\n"))
	assert.Equal(t, err, nil)

	// startup entry with no client at all
	_, err = scrubber.Write([]byte("2026/08/12 15:44:02 [notice] 74084#0: using the \"epoll\" event method\n"))
	assert.Equal(t, err, nil)

	err = scrubber.Flush()
	assert.Equal(t, err, nil)

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	assert.Equal(t, len(lines), 4)

	assert.Equal(t, strings.Contains(out.String(), "203.0.113.9"), false)
	assert.Equal(t, strings.Contains(out.String(), "2001:db8::dead:beef"), false)
	assert.Equal(t, strings.Contains(out.String(), "client:"), true)

	assert.Equal(t, lines[0], `2026/08/12 15:42:35 [error] 73966#0: *2 connect() failed (111: Connection refused) while connecting to upstream, server: , request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:80/dead", host: "main-lb.bringyour.com"`)
	assert.Equal(t, lines[1], `2026/08/12 15:43:33 [error] 74084#0: *1 connect() failed (111: Connection refused) while connecting to upstream, server: [scrubbed]:443, upstream: "[scrubbed]:80", bytes from/to client:0/0, bytes from/to upstream:0/0`)
	assert.Equal(t, lines[2], `2026/08/12 15:44:01 [info] 74084#0: *3 client closed connection while waiting for request`)
	assert.Equal(t, lines[3], "2026/08/12 15:44:02 [notice] 74084#0: using the \"epoll\" event method")
}

// a user reaches the lb over either family, so both have to be recognized
// wherever they turn up in an entry. Every address goes, whatever range it is
// in -- only the port and text that merely looks address shaped survive
func TestClientAddrScrubberMatchesBothFamilies(t *testing.T) {
	entries := []struct {
		entry    string
		scrubbed string
	}{
		// the client field, whichever family nginx wrote in it
		{
			`[error] *1 upstream timed out, client: 203.0.113.9, server: 0.0.0.0:443`,
			`[error] *1 upstream timed out, server: [scrubbed]:443`,
		},
		{
			`[error] *1 upstream timed out, client: 2001:db8::dead:beef, server: [::]:443`,
			`[error] *1 upstream timed out, server: [scrubbed]:443`,
		},
		{
			`[error] *1 upstream timed out, client: 2001:0db8:0000:0000:0000:0000:dead:beef, server: [::]:443`,
			`[error] *1 upstream timed out, server: [scrubbed]:443`,
		},
		{
			`[error] *1 upstream timed out, client: ::ffff:203.0.113.9, server: [::]:443`,
			`[error] *1 upstream timed out, server: [scrubbed]:443`,
		},
		// nginx has its own formats for a peer that is not ip at all
		{
			`[error] *1 upstream timed out, client: unix:, server: `,
			`[error] *1 upstream timed out, server: `,
		},
		// loose in the request line, which the client wrote
		{
			`[error] *1 open() failed, request: "GET /probe/203.0.113.9 HTTP/1.1"`,
			`[error] *1 open() failed, request: "GET /probe/[scrubbed] HTTP/1.1"`,
		},
		{
			`[error] *1 open() failed, request: "GET /probe/2001:db8::1 HTTP/1.1"`,
			`[error] *1 open() failed, request: "GET /probe/[scrubbed] HTTP/1.1"`,
		},
		// loose in the Host header, which the client also wrote
		{
			`[error] *1 no live upstreams, host: "203.0.113.9"`,
			`[error] *1 no live upstreams, host: "[scrubbed]"`,
		},
		// the port is not an address and says which service block the entry is
		// about, so it stays. The punctuation around it is text
		{
			`[error] *1 recv() failed, peer 203.0.113.9:51234.`,
			`[error] *1 recv() failed, peer [scrubbed]:51234.`,
		},
		// no range is exempt: the private addresses the service blocks live on,
		// loopback, the unspecified listen address and the resolvers all go
		{
			`[error] *1 connect() failed while connecting to upstream, upstream: "http://10.0.0.4:80/status", host: "lb.example.com"`,
			`[error] *1 connect() failed while connecting to upstream, upstream: "http://[scrubbed]:80/status", host: "lb.example.com"`,
		},
		{
			`[error] *1 connect() failed, upstream: "http://172.17.0.2:80/", server: 0.0.0.0:443`,
			`[error] *1 connect() failed, upstream: "http://[scrubbed]:80/", server: [scrubbed]:443`,
		},
		{
			`[error] *1 connect() failed, upstream: "http://192.168.1.9:80/", server: [::]:443`,
			`[error] *1 connect() failed, upstream: "http://[scrubbed]:80/", server: [scrubbed]:443`,
		},
		{
			`[error] *1 connect() failed, upstream: "http://127.0.0.1:19999/dead"`,
			`[error] *1 connect() failed, upstream: "http://[scrubbed]:19999/dead"`,
		},
		{
			`[error] *1 recv() failed while resolving, resolver: 1.1.1.1`,
			`[error] *1 recv() failed while resolving, resolver: [scrubbed]`,
		},
		// the brackets of `[addr]:port` belong to the address, and a zone is an
		// interface name rather than part of one
		{
			`[error] *1 connect() failed, upstream: "[fc00::4]:80", peer fe80::1%eth0, self ::1`,
			`[error] *1 connect() failed, upstream: "[scrubbed]:80", peer [scrubbed]%eth0, self [scrubbed]`,
		},
		{
			`[error] *1 upstream timed out, server: [2001:db8:beef::5]:443`,
			`[error] *1 upstream timed out, server: [scrubbed]:443`,
		},
		// text that is merely address shaped
		{
			`2026/08/12 15:42:35 [error] 73966#0: *2 recv() failed (104: Connection reset by peer)`,
			`2026/08/12 15:42:35 [error] 73966#0: *2 recv() failed (104: Connection reset by peer)`,
		},
		{
			`[error] *1 upstream timed out, bytes from/to client:0/0, bytes from/to upstream:0/0`,
			`[error] *1 upstream timed out, bytes from/to client:0/0, bytes from/to upstream:0/0`,
		},
		// percent encoding in a request line is not a zone
		{
			`[error] *1 open() failed, request: "GET /a%20b.c%2ed HTTP/1.1"`,
			`[error] *1 open() failed, request: "GET /a%20b.c%2ed HTTP/1.1"`,
		},
	}

	for _, entry := range entries {
		out := &bytes.Buffer{}
		scrubber := NewClientAddrScrubber(out)

		_, err := scrubber.Write([]byte(entry.entry + "\n"))
		assert.Equal(t, err, nil)

		if out.String() != entry.scrubbed+"\n" {
			t.Errorf("scrubbing\n  %s\ngave\n  %s\nwant\n  %s", entry.entry, strings.TrimSuffix(out.String(), "\n"), entry.scrubbed)
		}
	}
}

// nginx writes each url of a request scoped entry with its query string, and
// no access log format reaches these (DESIGN 19.13, D-OPS-8). These are the
// shapes real nginx 1.31.6 writes, and every query comes out whatever is in it.
func TestClientAddrScrubberDropsQueryStrings(t *testing.T) {
	entries := []struct {
		entry    string
		scrubbed string
	}{
		// a failed upstream writes the request line and the url it proxied to
		{
			`2026/11/06 21:16:12 [error] 19842#0: *1 connect() failed (61: Connection refused) while connecting to upstream, client: 203.0.113.9, server: , request: "GET /dead?q=secret HTTP/1.1", upstream: "http://10.0.0.4:7001/dead?q=secret", host: "evs.example.com"`,
			`2026/11/06 21:16:12 [error] 19842#0: *1 connect() failed (61: Connection refused) while connecting to upstream, server: , request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com"`,
		},
		// the referrer is the client's own header, which may hold a space
		{
			`[error] *1 connect() failed, request: "GET /dead?q=secret HTTP/1.1", upstream: "http://10.0.0.4:7001/dead?q=secret", host: "evs.example.com", referrer: "https://page.example.com/start?q=secret two"`,
			`[error] *1 connect() failed, request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com", referrer: "https://page.example.com/start"`,
		},
		// nginx refuses a body past the limit with no upstream at all
		{
			`[error] *5 client intended to send too large body: 4 bytes, client: 203.0.113.9, server: , request: "POST /big?q=secret HTTP/1.1", host: "evs.example.com"`,
			`[error] *5 client intended to send too large body: 4 bytes, server: , request: "POST /big HTTP/1.1", host: "evs.example.com"`,
		},
		// the client wrote the query, so a quote or a comma in it proves nothing
		{
			`[error] *1 connect() failed, request: "GET /dead?q="secret",x HTTP/1.1", upstream: "http://10.0.0.4:7001/dead?q="secret",x", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com"`,
		},
		// HTTP/0.9 has no protocol to end the line
		{
			`[error] *1 connect() failed, request: "GET /dead?q=secret", upstream: "http://10.0.0.4:7001/dead?q=secret", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET /dead", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com"`,
		},
		// nginx accepts runs of spaces around the url
		{
			`[error] *1 connect() failed, request: "GET   /dead?q=secret  HTTP/1.1", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET   /dead  HTTP/1.1", host: "evs.example.com"`,
		},
		// h2 and h3 lines, and the absolute form
		{
			`[error] *1 connect() failed, request: "PUT /evs/v1?q=secret HTTP/2.0", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "PUT /evs/v1 HTTP/2.0", host: "evs.example.com"`,
		},
		{
			`[error] *1 connect() failed, request: "PUT /evs/v1?q=secret HTTP/3.0", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "PUT /evs/v1 HTTP/3.0", host: "evs.example.com"`,
		},
		{
			`[error] *1 connect() failed, request: "GET http://evs.example.com/dead?q=secret HTTP/1.1", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET http://evs.example.com/dead HTTP/1.1", host: "evs.example.com"`,
		},
		// an empty query, and more than one question mark
		{
			`[error] *1 connect() failed, request: "GET /dead? HTTP/1.1", upstream: "http://10.0.0.4:7001/dead?a?b", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com"`,
		},
		// an entry with no query keeps everything but the addresses, a question
		// mark outside a url field and an encoded one included
		{
			`[error] *1 open() "/srv/what?" failed (2: No such file or directory), request: "GET /what%3F HTTP/1.1", host: "evs.example.com"`,
			`[error] *1 open() "/srv/what?" failed (2: No such file or directory), request: "GET /what%3F HTTP/1.1", host: "evs.example.com"`,
		},
		{
			`[error] *1 connect() failed, request: "GET /dead HTTP/1.1", upstream: "http://10.0.0.4:7001/dead", host: "evs.example.com"`,
			`[error] *1 connect() failed, request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:7001/dead", host: "evs.example.com"`,
		},
	}

	for _, entry := range entries {
		out := &bytes.Buffer{}
		scrubber := NewClientAddrScrubber(out)

		_, err := scrubber.Write([]byte(entry.entry + "\n"))
		assert.Equal(t, err, nil)

		if out.String() != entry.scrubbed+"\n" {
			t.Errorf("scrubbing\n  %s\ngave\n  %s\nwant\n  %s", entry.entry, strings.TrimSuffix(out.String(), "\n"), entry.scrubbed)
		}
	}
}

// Entries pass through whole, so a query that arrives across writes, or beside
// other entries in one write, comes out the same, and an expression stops at
// the end of its own entry.
func TestClientAddrScrubberDropsQueryStringsAcrossWrites(t *testing.T) {
	out := &bytes.Buffer{}
	scrubber := NewClientAddrScrubber(out)

	entries := `[error] *1 connect() failed, request: "GET /one?q=secret HTTP/1.1", host: "evs.example.com", referrer: "https://page.example.com/start?q=secret"` + "\n" +
		`[error] *2 connect() failed, request: "GET /two?q=secret", upstream: "http://10.0.0.4:7001/two?q=secret"` + "\n"
	for i := range entries {
		_, err := scrubber.Write([]byte(entries[i : i+1]))
		assert.Equal(t, err, nil)
	}
	assert.Equal(t, out.String(), `[error] *1 connect() failed, request: "GET /one HTTP/1.1", host: "evs.example.com", referrer: "https://page.example.com/start"`+"\n"+
		`[error] *2 connect() failed, request: "GET /two", upstream: "http://[scrubbed]:7001/two"`+"\n")

	out.Reset()
	_, err := scrubber.Write([]byte(entries))
	assert.Equal(t, err, nil)
	if strings.Contains(out.String(), "secret") {
		t.Errorf("a query string survived in\n%s", out.String())
	}
	assert.Equal(t, strings.Count(out.String(), "\n"), 2)
}

// nginx writes to the pipe in whatever chunks it likes, so an address can
// arrive split across writes
func TestClientAddrScrubberSplitWrites(t *testing.T) {
	out := &bytes.Buffer{}
	scrubber := NewClientAddrScrubber(out)

	entry := `2026/08/12 15:42:35 [error] 73966#0: *2 upstream timed out, client: 203.0.113.9, server: 0.0.0.0:443` + "\n"
	for i := range entry {
		_, err := scrubber.Write([]byte(entry[i : i+1]))
		assert.Equal(t, err, nil)
	}

	assert.Equal(t, out.String(), `2026/08/12 15:42:35 [error] 73966#0: *2 upstream timed out, server: [scrubbed]:443`+"\n")
}

// a partial entry is held for its newline, so what nginx wrote before exiting
// still has to reach stderr -- scrubbed -- when the pipe closes
func TestClientAddrScrubberFlushesPartialEntry(t *testing.T) {
	out := &bytes.Buffer{}
	scrubber := NewClientAddrScrubber(out)

	_, err := scrubber.Write([]byte(`2026/08/12 15:42:35 [error] 73966#0: *2 upstream timed out, client: 203.0.113.9`))
	assert.Equal(t, err, nil)
	assert.Equal(t, out.String(), "")

	err = scrubber.Flush()
	assert.Equal(t, err, nil)
	assert.Equal(t, out.String(), `2026/08/12 15:42:35 [error] 73966#0: *2 upstream timed out`)

	// flushing an empty scrubber writes nothing more
	err = scrubber.Flush()
	assert.Equal(t, err, nil)
	assert.Equal(t, out.String(), `2026/08/12 15:42:35 [error] 73966#0: *2 upstream timed out`)
}

// a writer that never sends a newline must not grow the buffer without bound
func TestClientAddrScrubberBoundsPartialEntry(t *testing.T) {
	out := &bytes.Buffer{}
	scrubber := NewClientAddrScrubber(out)

	_, err := scrubber.Write(bytes.Repeat([]byte("x"), maxNginxErrorEntrySize))
	assert.Equal(t, err, nil)
	assert.Equal(t, out.Len(), maxNginxErrorEntrySize)
	assert.Equal(t, len(scrubber.buf), 0)
}

// none of the rewriting matters if nginx's stderr does not pass through it
func TestNginxCmdScrubsStderr(t *testing.T) {
	cmd, stderr := newNginxCmd("/srv/warp/nginx.conf/test.conf")

	assert.Equal(t, cmd.Stderr, stderr)
	_, isScrubber := cmd.Stderr.(*ClientAddrScrubber)
	assert.Equal(t, isScrubber, true)

	// stdout carries the access log, which nginx already writes without the
	// address, so it stays a direct fd
	assert.Equal(t, cmd.Stdout, os.Stdout)
}

// the unit tests above pin the rewriting against captured entries, which only
// holds while nginx keeps writing them that way. This drives a real nginx the
// way Nginx() does -- http and stream both failing to reach an upstream, the
// two paths that carry the client address -- and checks nothing identifying
// survives on any of the three sinks: stdout, stderr, and the main level error
// log file that stream errors fall back to.
func TestNginxLogsOmitClientAddr(t *testing.T) {
	if _, err := exec.LookPath("nginx"); err != nil {
		t.Skip("nginx not found in PATH")
	}

	httpPort := freePort(t)
	streamPort := freePort(t)
	// nothing listens here, so both proxies fail to connect and log an error
	deadPort := freePort(t)

	dir := t.TempDir()
	confPath := filepath.Join(dir, "nginx.conf")
	// the logging directives are the ones warpctl NginxConfig generates
	conf := fmt.Sprintf(`
pid %s;
error_log stderr;
events { worker_connections 16; }
http {
    log_format noclientaddr '$time_iso8601 $connection $connection_requests '
                            '$host "$request" $status $body_bytes_sent $request_time '
                            '$upstream_addr $upstream_status $upstream_response_time '
                            '"$http_user_agent"';
    access_log /dev/stdout noclientaddr;
    error_log stderr;
    upstream dead { server 127.0.0.1:%d; }
    server {
        listen %d;
        location /ok { return 200 "ok\n"; }
        location /dead { proxy_pass http://dead; }
    }
}
stream {
    upstream deadstream { server 127.0.0.1:%d; }
    server {
        listen %d;
        proxy_pass deadstream;
    }
}
`, filepath.Join(dir, "nginx.pid"), deadPort, httpPort, deadPort, streamPort)
	err := os.WriteFile(confPath, []byte(conf), 0644)
	assert.Equal(t, err, nil)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// -e sets the main level default, which is where stream errors would land
	// if the config did not send them to stderr
	defaultErrorLogPath := filepath.Join(dir, "default-error.log")
	cmd := exec.Command("nginx", "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", defaultErrorLogPath)
	// wired exactly as Nginx() wires it
	cmd.Stdout = stdout
	scrubber := NewClientAddrScrubber(stderr)
	cmd.Stderr = scrubber

	err = cmd.Start()
	assert.Equal(t, err, nil)
	defer cmd.Process.Kill()

	okUrl := fmt.Sprintf("http://127.0.0.1:%d/ok", httpPort)
	if !waitForHttp(okUrl) {
		t.Fatalf("nginx did not start: %s", stderr.String())
	}

	// a request that succeeds, so the access log has an entry whose only
	// address could be the client's
	request, err := http.NewRequest("GET", okUrl, nil)
	assert.Equal(t, err, nil)
	// $host comes from here, so an address in the entry can only be the client
	request.Host = "lb.example.com"
	response, err := http.DefaultClient.Do(request)
	assert.Equal(t, err, nil)
	response.Body.Close()

	// an http error entry
	response, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/dead", httpPort))
	assert.Equal(t, err, nil)
	response.Body.Close()

	// a stream error entry
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", streamPort))
	assert.Equal(t, err, nil)
	conn.Read(make([]byte, 1))
	conn.Close()

	cmd.Process.Signal(syscall.SIGQUIT)
	cmd.Wait()
	err = scrubber.Flush()
	assert.Equal(t, err, nil)

	// nginx appends the client address as a `, client: <addr>` field, so the
	// absence of the field is the contract, whatever the address was
	if strings.Contains(stderr.String(), ", client: ") {
		t.Errorf("nginx error entries still carry the client address:\n%s", stderr.String())
	}
	// the test client, the upstream and the listen address are all written into
	// these entries by nginx, and no address survives anywhere
	if strings.Contains(stderr.String(), "127.0.0.1") || strings.Contains(stderr.String(), "0.0.0.0") {
		t.Errorf("nginx error entries still carry an address:\n%s", stderr.String())
	}
	// and the entries still have to be worth reading
	if !strings.Contains(stderr.String(), "connecting to upstream") {
		t.Errorf("upstream diagnostics lost from the error log:\n%s", stderr.String())
	}

	// stream errors go to stderr, not to a file inside the container
	defaultErrorLog, err := os.ReadFile(defaultErrorLogPath)
	assert.Equal(t, err, nil)
	assert.Equal(t, len(defaultErrorLog), 0)
	assert.Equal(t, strings.Count(stderr.String(), "connecting to upstream"), 2)

	// the client connected from 127.0.0.1, and every other address in this
	// entry is one the test supplied
	okEntry := ""
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, "GET /ok") {
			okEntry = line
		}
	}
	assert.NotEqual(t, okEntry, "")
	if strings.Contains(okEntry, "127.0.0.1") {
		t.Errorf("access log entry carries the client address: %q", okEntry)
	}
	assert.Equal(t, strings.Contains(okEntry, "lb.example.com"), true)
}

// Drives a real nginx with the logging warpctl NginxConfig generates for a
// log_uri host, the way Nginx() runs it. A request to that host carries a query
// string through the access log and, by a failing upstream, through nginx's own
// error entries: none of it survives on any sink. Another host still logs its
// query in the access log.
func TestNginxLogsOmitQueryStringsOfLogUriHosts(t *testing.T) {
	if _, err := exec.LookPath("nginx"); err != nil {
		t.Skip("nginx not found in PATH")
	}

	httpPort := freePort(t)
	// nothing listens here, so the proxy fails to connect and logs an error
	deadPort := freePort(t)

	dir := t.TempDir()
	confPath := filepath.Join(dir, "nginx.conf")
	conf := fmt.Sprintf(`
pid %s;
error_log stderr;
events { worker_connections 16; }
http {
    log_format noclientaddr '$time_iso8601 $connection $connection_requests '
                            '$host "$warp_log_request" $status $body_bytes_sent $request_time '
                            '$upstream_addr $upstream_status $upstream_response_time '
                            '"$http_user_agent"';
    access_log /dev/stdout noclientaddr;
    error_log stderr;
    map $host $warp_log_request {
        hostnames;
        default $request;
        uri.example.com "$request_method $uri $server_protocol";
    }
    upstream dead { server 127.0.0.1:%d; }
    server {
        listen %d;
        client_max_body_size 1;
        location /ok { return 200 "ok\n"; }
        location /dead { proxy_pass http://dead; }
    }
}
`, filepath.Join(dir, "nginx.pid"), deadPort, httpPort)
	err := os.WriteFile(confPath, []byte(conf), 0644)
	assert.Equal(t, err, nil)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	defaultErrorLogPath := filepath.Join(dir, "default-error.log")
	cmd := exec.Command("nginx", "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", defaultErrorLogPath)
	// wired exactly as Nginx() wires it
	cmd.Stdout = stdout
	scrubber := NewClientAddrScrubber(stderr)
	cmd.Stderr = scrubber

	err = cmd.Start()
	assert.Equal(t, err, nil)
	defer cmd.Process.Kill()

	okUrl := fmt.Sprintf("http://127.0.0.1:%d/ok", httpPort)
	if !waitForHttp(okUrl) {
		t.Fatalf("nginx did not start: %s", stderr.String())
	}

	send := func(method string, host string, path string, body string) {
		t.Helper()
		request, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", httpPort, path), strings.NewReader(body))
		assert.Equal(t, err, nil)
		request.Host = host
		request.Header.Set("Referer", "https://page.example.com/start?referrer-marker")
		response, err := http.DefaultClient.Do(request)
		assert.Equal(t, err, nil)
		response.Body.Close()
	}

	// the access log alone, an upstream failure, and nginx's own refusal
	send("GET", "uri.example.com", "/ok?unlogged-marker", "")
	send("GET", "uri.example.com", "/dead?unlogged-marker", "")
	send("POST", "uri.example.com", "/dead?unlogged-marker", "too large")
	send("GET", "other.example.com", "/ok?logged-marker", "")

	cmd.Process.Signal(syscall.SIGQUIT)
	cmd.Wait()
	err = scrubber.Flush()
	assert.Equal(t, err, nil)

	for _, sink := range []string{stdout.String(), stderr.String()} {
		for _, marker := range []string{"unlogged-marker", "referrer-marker"} {
			if strings.Contains(sink, marker) {
				t.Errorf("a query string survived:\n%s", sink)
			}
		}
	}
	assert.Equal(t, strings.Contains(stdout.String(), `uri.example.com "GET /ok HTTP/1.1" 200 `), true)
	assert.Equal(t, strings.Contains(stdout.String(), `other.example.com "GET /ok?logged-marker HTTP/1.1" 200 `), true)

	// the error entries still say which route failed, and how
	assert.Equal(t, strings.Contains(stderr.String(), `request: "GET /dead HTTP/1.1", upstream: "http://[scrubbed]:`), true)
	assert.Equal(t, strings.Contains(stderr.String(), `client intended to send too large body`), true)
	assert.Equal(t, strings.Contains(stderr.String(), `request: "POST /dead HTTP/1.1"`), true)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHttp(url string) bool {
	endTime := time.Now().Add(10 * time.Second)
	for time.Now().Before(endTime) {
		response, err := http.Get(url)
		if err == nil {
			response.Body.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
