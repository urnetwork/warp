//go:build linux || darwin

// lbmap through a real nginx running the split (TLS-M6-01): a reload moves a
// custom host from the http branch to the edge and its removal moves it back,
// each version's probe name routing to the edge, and port 80's redirect
// taking the host's name; the dns API is a stub over HTTP, lbmap's own client
// talking to it. TLS-M6-07 runs the same through the real lb process with the
// real dns API and tlsedge.
package main_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/lb/splittest"
)

// The stub's bearer: 256 synthetic bits in unpadded base64url.
const lbMapSplitTestBearer = "c2lkZWNhci10ZXN0LWxibWFwLWJlYXJlci0wMTIzNDU"

// The interface the stub knows.
const lbMapSplitTestInterface = "edge-1-eth0"

// The dns API's two lbmap routes, as DNS-M6-03 serves them: a poll answered
// at once without applied, else held until the newest version differs from
// applied or a short hold ends with 204; reports recorded. A request without
// the bearer, or naming another interface, is refused.
type lbMapSplitTestApi struct {
	server  *httptest.Server
	reports chan *warp.LbMapReport

	stateLock sync.Mutex
	newest    *warp.LbCustomHostMap
	// closed and replaced when newest changes
	changed chan struct{}
}

func startLbMapSplitTestApi(t *testing.T) *lbMapSplitTestApi {
	t.Helper()
	api := &lbMapSplitTestApi{
		reports: make(chan *warp.LbMapReport, 64),
		changed: make(chan struct{}),
	}
	api.server = httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	return api
}

func (self *lbMapSplitTestApi) serve(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+lbMapSplitTestBearer {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == warp.LbMapCustomHostMapPath:
		query := request.URL.Query()
		if query.Get("interface") != lbMapSplitTestInterface {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		applied, hasApplied := uint64(0), query.Has("applied")
		if hasApplied {
			var err error
			if applied, err = strconv.ParseUint(query.Get("applied"), 10, 64); err != nil {
				http.Error(writer, "applied", http.StatusBadRequest)
				return
			}
		}
		hold := time.After(2 * time.Second)
		for {
			var newest *warp.LbCustomHostMap
			var changed chan struct{}
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				newest = self.newest
				changed = self.changed
			}()
			if newest != nil && (!hasApplied || newest.Version != applied) {
				json.NewEncoder(writer).Encode(newest)
				return
			}
			if !hasApplied {
				writer.WriteHeader(http.StatusNoContent)
				return
			}
			select {
			case <-changed:
			case <-hold:
				writer.WriteHeader(http.StatusNoContent)
				return
			case <-request.Context().Done():
				return
			}
		}
	case request.Method == http.MethodPost && request.URL.Path == warp.LbMapAppliedPath:
		report := &warp.LbMapReport{}
		if err := json.NewDecoder(request.Body).Decode(report); err != nil || report.Interface != lbMapSplitTestInterface {
			http.Error(writer, "report", http.StatusBadRequest)
			return
		}
		self.reports <- report
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(writer, request)
	}
}

// Makes hosts the newest version.
func (self *lbMapSplitTestApi) publish(version uint64, hosts ...string) *warp.LbCustomHostMap {
	customHostMap := &warp.LbCustomHostMap{Format: warp.LbMapFormat, Version: version, Digest: warp.LbCustomHostMapDigest(hosts), Hosts: hosts}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.newest = customHostMap
	close(self.changed)
	self.changed = make(chan struct{})
	return customHostMap
}

// The next report naming version, skipping repeats of earlier ones.
func (self *lbMapSplitTestApi) awaitReport(t *testing.T, version uint64) *warp.LbMapReport {
	t.Helper()
	timeout := time.After(splitTestTimeout)
	for {
		select {
		case report := <-self.reports:
			if report.Failure != nil {
				t.Fatalf("lbmap reports a failure: %+v", report.Failure)
			}
			if report.Version == version {
				return report
			}
		case <-timeout:
			t.Fatalf("no report of version %d", version)
			return nil
		}
	}
}

// serverName reaches the edge stand-in: its hello answered unrecognized_name,
// and the open recorded.
func requireLbMapEdgeBranch(t *testing.T, lb *splittest.Lb, network string, serverName string) {
	t.Helper()
	sendEdgeHello(t, lb, network, serverName)
	if _, err := lb.Edge.Next(splitTestTimeout); err != nil {
		t.Fatalf("%s over %s: %v", serverName, network, err)
	}
}

// serverName reaches the http branch: a TLS handshake with the http server,
// whose certificate does not name it, and a request its upstream sees.
func requireLbMapHttpBranch(t *testing.T, lb *splittest.Lb, network string, serverName string) {
	t.Helper()
	conn, err := lb.DialHttps(network, serverName, true)
	if err != nil {
		t.Fatalf("%s over %s did not reach the http branch: %v", serverName, network, err)
	}
	defer conn.Close()
	if status, body := splitGet(t, conn, serverName, "/branch"); status != http.StatusOK || body != "/branch" {
		t.Fatalf("%s over %s: %d %q", serverName, network, status, body)
	}
}

// Which port 80 server takes host: the path the http upstream saw.
func lbMapHttp80Path(t *testing.T, lb *splittest.Lb, host string) string {
	t.Helper()
	conn, err := net.Dial("tcp4", lb.Http80Address())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(splitTestTimeout))
	fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A reload moves a custom host from the http branch to the edge, with the
// version's probe name, and port 80's redirect takes its name; removing it
// moves it back at the next reload, the old probe name with it, while the
// new version's probe name reaches the edge and a platform name keeps the
// http branch throughout.
func TestLbMapReloadMovesACustomHostBetweenTheBranches(t *testing.T) {
	settings := splittest.DefaultSettings(splitBinary(t))
	lb := startSplit(t, settings)
	api := startLbMapSplitTestApi(t)
	control, err := lb.NginxControl(&warp.NginxSettings{DrainTimeout: time.Minute, WorkerCheckInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	lbMapSettings := warp.DefaultLbMapSettings()
	lbMapSettings.LoadDelay = 0
	lbMapSettings.ReloadMinInterval = 0
	lbMapSettings.PollMinInterval = 10 * time.Millisecond
	lbMapSettings.ErrorBackoffMin = 10 * time.Millisecond
	lbMapSettings.ErrorBackoffMax = 100 * time.Millisecond
	lbMapApi, err := warp.NewLbMapHttpApi(api.server.URL, lbMapSplitTestBearer, api.server.Client(), lbMapSettings)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lbMap, err := warp.NewLbMap(ctx, &warp.LbMapConfig{
		Interface:  lbMapSplitTestInterface,
		MapPath:    lb.CustomHostsMapPath(),
		Http80Path: lb.CustomHosts80Path(),
		Render: &warp.LbMapRenderConfig{
			Format:          warp.LbMapFormat,
			Roots:           settings.Roots,
			PlatformDomains: settings.PlatformNames,
			EdgeUpstream:    splittest.EdgeUpstream,
		},
	}, lbMapSettings, lbMapApi, control)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(splitTestTimeout):
			t.Error("lbmap did not stop with its context")
		}
	})

	host := "shop.customer.example"
	platformName := settings.PlatformNames[0]
	requireLbMapHttpBranch(t, lb, "tcp4", host)
	if path := lbMapHttp80Path(t, lb, host); !strings.HasPrefix(path, splittest.Http80DefaultPath) {
		t.Errorf("port 80 before the load: %s", path)
	}

	first := api.publish(1, host)
	go func() {
		defer close(runDone)
		lbMap.Run()
	}()
	report := api.awaitReport(t, 1)
	if !slices.Equal(report.Added, []string{host}) || report.Master == nil || report.Digest != first.Digest {
		t.Errorf("report %+v", report)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		requireLbMapEdgeBranch(t, lb, network, host)
		requireLbMapHttpBranch(t, lb, network, platformName)
	}
	requireLbMapEdgeBranch(t, lb, "tcp4", warp.LbMapProbeName(first.Digest))
	if path := lbMapHttp80Path(t, lb, host); !strings.HasPrefix(path, splittest.Http80RedirectPath) {
		t.Errorf("port 80 after the load: %s", path)
	}

	second := api.publish(2)
	report = api.awaitReport(t, 2)
	if !slices.Equal(report.Dropped, []string{host}) || len(report.Added) != 0 {
		t.Errorf("report %+v", report)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		requireLbMapHttpBranch(t, lb, network, host)
		requireLbMapHttpBranch(t, lb, network, platformName)
	}
	requireLbMapEdgeBranch(t, lb, "tcp4", warp.LbMapProbeName(second.Digest))
	requireLbMapHttpBranch(t, lb, "tcp4", warp.LbMapProbeName(first.Digest))
	if path := lbMapHttp80Path(t, lb, host); !strings.HasPrefix(path, splittest.Http80DefaultPath) {
		t.Errorf("port 80 after the removal: %s", path)
	}
	if strings.Contains(lb.ScrubbedErrorLog(), "[emerg]") {
		t.Errorf("nginx refused a reload:\n%s", lb.ScrubbedErrorLog())
	}
}
