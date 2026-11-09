package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// How long a test waits on the loop before it fails: a bound on a failure,
// never a pause on success.
const lbMapTestTimeout = 10 * time.Second

// Where the tests' clock starts.
var lbMapTestStart = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

// The interface the tests' lbmap runs beside.
const lbMapTestInterface = "edge-1-eth0"

// A clock the test moves. Safe for concurrent use.
type fakeLbMapClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*fakeLbMapTimer
	// closed and replaced whenever a timer is set, for awaitTimer
	timerAdded chan struct{}
}

type fakeLbMapTimer struct {
	at    time.Time
	fired chan time.Time
}

func newFakeLbMapClock() *fakeLbMapClock {
	return &fakeLbMapClock{now: lbMapTestStart, timerAdded: make(chan struct{})}
}

func (self *fakeLbMapClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *fakeLbMapClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fired := make(chan time.Time, 1)
	if timeout <= 0 {
		fired <- self.now
		return fired
	}
	self.timers = append(self.timers, &fakeLbMapTimer{at: self.now.Add(timeout), fired: fired})
	close(self.timerAdded)
	self.timerAdded = make(chan struct{})
	return fired
}

// Moves the clock forward, firing every timer it reaches.
func (self *fakeLbMapClock) Advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
	pending := []*fakeLbMapTimer{}
	for _, timer := range self.timers {
		if timer.at.After(self.now) {
			pending = append(pending, timer)
			continue
		}
		// buffered, so a timer nobody waits on any more costs nothing
		timer.fired <- timer.at
	}
	self.timers = pending
}

// Moves the clock to at.
func (self *fakeLbMapClock) AdvanceTo(at time.Time) {
	self.Advance(at.Sub(self.Now()))
}

// Returns once a timer at exactly at is set: the loop has reached its wait
// for it, so moving the clock to just before at shows what it does not do.
func (self *fakeLbMapClock) awaitTimer(t *testing.T, at time.Time) {
	t.Helper()
	deadline := time.After(lbMapTestTimeout)
	for {
		var added chan struct{}
		found := false
		pending := []time.Time{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			added = self.timerAdded
			for _, timer := range self.timers {
				pending = append(pending, timer.at)
				if timer.at.Equal(at) {
					found = true
				}
			}
		}()
		if found {
			return
		}
		select {
		case <-added:
		case <-deadline:
			t.Fatalf("no timer at %v; pending %v", at, pending)
		}
	}
}

// The dns API as the test answers it: each poll waits for the test's answer
// or its own end, and each report is recorded.
type fakeLbMapApi struct {
	gets    chan *fakeLbMapGet
	reports chan *LbMapReport

	stateLock sync.Mutex
	// what the next reports answer, in order; nil once spent
	appliedErrs []error
}

// One poll in flight.
type fakeLbMapGet struct {
	poll    *LbMapPoll
	answers chan *fakeLbMapAnswer
}

type fakeLbMapAnswer struct {
	customHostMap *LbCustomHostMap
	err           error
}

func newFakeLbMapApi() *fakeLbMapApi {
	return &fakeLbMapApi{
		gets:    make(chan *fakeLbMapGet),
		reports: make(chan *LbMapReport, 64),
	}
}

func (self *fakeLbMapApi) CustomHostMap(ctx context.Context, poll *LbMapPoll) (*LbCustomHostMap, error) {
	pollCopy := *poll
	if poll.Applied != nil {
		applied := *poll.Applied
		pollCopy.Applied = &applied
	}
	if poll.Master != nil {
		master := *poll.Master
		pollCopy.Master = &master
	}
	get := &fakeLbMapGet{poll: &pollCopy, answers: make(chan *fakeLbMapAnswer, 1)}
	select {
	case self.gets <- get:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case answer := <-get.answers:
		return answer.customHostMap, answer.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (self *fakeLbMapApi) Applied(ctx context.Context, report *LbMapReport) error {
	self.reports <- cloneLbMapReport(report)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.appliedErrs) {
		err := self.appliedErrs[0]
		self.appliedErrs = self.appliedErrs[1:]
		return err
	}
	return nil
}

func (self *fakeLbMapApi) failApplied(errs ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.appliedErrs = append(self.appliedErrs, errs...)
}

// Answers the poll with a version, or with nil, the end of a hold.
func (self *fakeLbMapGet) reply(customHostMap *LbCustomHostMap) {
	self.answers <- &fakeLbMapAnswer{customHostMap: customHostMap}
}

func (self *fakeLbMapGet) fail(err error) {
	self.answers <- &fakeLbMapAnswer{err: err}
}

// nginx as a test scripts it: each test and reload is recorded with what the
// include files held at that moment, and answers the next scripted error.
type fakeNginxControl struct {
	master     NginxMaster
	mapPath    string
	http80Path string
	calls      chan *fakeNginxCall

	stateLock  sync.Mutex
	testErrs   []error
	reloadErrs []error
}

type fakeNginxCall struct {
	kind       string
	mapText    string
	http80Text string
}

func (self *fakeNginxControl) Master(ctx context.Context) (*NginxMaster, error) {
	master := self.master
	return &master, nil
}

func (self *fakeNginxControl) record(kind string) {
	mapText, _ := os.ReadFile(self.mapPath)
	http80Text, _ := os.ReadFile(self.http80Path)
	self.calls <- &fakeNginxCall{kind: kind, mapText: string(mapText), http80Text: string(http80Text)}
}

func (self *fakeNginxControl) Test(ctx context.Context) error {
	self.record("test")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.testErrs) {
		err := self.testErrs[0]
		self.testErrs = self.testErrs[1:]
		return err
	}
	return nil
}

func (self *fakeNginxControl) Reload(ctx context.Context) error {
	self.record("reload")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.reloadErrs) {
		err := self.reloadErrs[0]
		self.reloadErrs = self.reloadErrs[1:]
		return err
	}
	return nil
}

func (self *fakeNginxControl) failTests(errs ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.testErrs = append(self.testErrs, errs...)
}

func (self *fakeNginxControl) failReloads(errs ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reloadErrs = append(self.reloadErrs, errs...)
}

// A log a test reads while lbmap writes it.
type lbMapTestLog struct {
	stateLock sync.Mutex
	buffer    bytes.Buffer
}

func (self *lbMapTestLog) Write(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.Write(b)
}

func (self *lbMapTestLog) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.String()
}

// One lbmap on fakes, its include files in a temp directory.
type lbMapHarness struct {
	t        *testing.T
	clock    *fakeLbMapClock
	api      *fakeLbMapApi
	nginx    *fakeNginxControl
	logs     *lbMapTestLog
	config   *LbMapConfig
	settings *LbMapSettings
	lbMap    *LbMap
	runDone  chan struct{}
}

// The settings the tests run: §13.4's windows, polls that never time out on
// their own, polls again at once, and short backoffs.
func lbMapTestSettings() *LbMapSettings {
	settings := DefaultLbMapSettings()
	settings.PollTimeout = 24 * time.Hour
	settings.PollMinInterval = 0
	settings.ErrorBackoffMin = time.Second
	settings.ErrorBackoffMax = 4 * time.Second
	return settings
}

// An lbmap whose map file holds held's render before it starts, or nothing,
// as a fresh run directory's empty includes do.
func newLbMapHarness(t *testing.T, held *LbCustomHostMap, settings *LbMapSettings) *lbMapHarness {
	t.Helper()
	dir := t.TempDir()
	h := &lbMapHarness{
		t:     t,
		clock: newFakeLbMapClock(),
		api:   newFakeLbMapApi(),
		logs:  &lbMapTestLog{},
	}
	h.config = &LbMapConfig{
		Interface:  lbMapTestInterface,
		MapPath:    filepath.Join(dir, "tls-custom-hosts.map"),
		Http80Path: filepath.Join(dir, "tls-custom-hosts-80.conf"),
		Render:     lbMapTestRenderConfig(),
		Clock:      h.clock,
	}
	h.config.Log = log.New(h.logs, "", 0)
	h.nginx = &fakeNginxControl{
		master:     NginxMaster{Pid: 4242, StartTime: lbMapTestStart.Add(-time.Hour)},
		mapPath:    h.config.MapPath,
		http80Path: h.config.Http80Path,
		calls:      make(chan *fakeNginxCall, 64),
	}
	mapText, http80Text := []byte{}, []byte{}
	if held != nil {
		render, err := h.config.Render.Render(held, 16)
		if err != nil {
			t.Fatal(err)
		}
		mapText, http80Text = render.Map, render.Http80
	}
	if err := os.WriteFile(h.config.MapPath, mapText, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.config.Http80Path, http80Text, 0644); err != nil {
		t.Fatal(err)
	}
	if settings == nil {
		settings = lbMapTestSettings()
	}
	h.settings = settings
	ctx, cancel := context.WithCancel(context.Background())
	lbMap, err := NewLbMap(ctx, h.config, settings, h.api, h.nginx)
	if err != nil {
		t.Fatal(err)
	}
	h.lbMap = lbMap
	t.Cleanup(func() {
		cancel()
		if h.runDone != nil {
			select {
			case <-h.runDone:
			case <-time.After(lbMapTestTimeout):
				t.Error("lbmap did not stop with its context")
			}
		}
	})
	return h
}

// The render of a version, for comparing with what the files hold.
func (self *lbMapHarness) render(customHostMap *LbCustomHostMap) *LbMapRender {
	self.t.Helper()
	render, err := self.config.Render.Render(customHostMap, 16)
	if err != nil {
		self.t.Fatal(err)
	}
	return render
}

// What the two include files hold now.
func (self *lbMapHarness) files() (string, string) {
	self.t.Helper()
	mapText, err := os.ReadFile(self.config.MapPath)
	if err != nil {
		self.t.Fatal(err)
	}
	http80Text, err := os.ReadFile(self.config.Http80Path)
	if err != nil {
		self.t.Fatal(err)
	}
	return string(mapText), string(http80Text)
}

// Runs LoadBeforeStart, answering its poll with answer, and returns its
// result.
func (self *lbMapHarness) loadBeforeStart(answer func(get *fakeLbMapGet)) error {
	self.t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- self.lbMap.LoadBeforeStart()
	}()
	answer(self.nextGet())
	select {
	case err := <-done:
		return err
	case <-time.After(lbMapTestTimeout):
		self.t.Fatal("LoadBeforeStart did not return")
		return nil
	}
}

// Starts Run, as the lb does once nginx has started.
func (self *lbMapHarness) run() {
	self.runDone = make(chan struct{})
	go func() {
		defer close(self.runDone)
		self.lbMap.Run()
	}()
}

func (self *lbMapHarness) nextGet() *fakeLbMapGet {
	self.t.Helper()
	select {
	case get := <-self.api.gets:
		return get
	case <-time.After(lbMapTestTimeout):
		self.t.Fatal("no poll")
		return nil
	}
}

func (self *lbMapHarness) noGet() {
	self.t.Helper()
	select {
	case get := <-self.api.gets:
		self.t.Fatalf("a poll: %+v", get.poll)
	default:
	}
}

func (self *lbMapHarness) nextReport() *LbMapReport {
	self.t.Helper()
	select {
	case report := <-self.api.reports:
		return report
	case <-time.After(lbMapTestTimeout):
		self.t.Fatal("no report")
		return nil
	}
}

func (self *lbMapHarness) noReport() {
	self.t.Helper()
	select {
	case report := <-self.api.reports:
		self.t.Fatalf("a report: %+v", report)
	default:
	}
}

func (self *lbMapHarness) nextCall(kind string) *fakeNginxCall {
	self.t.Helper()
	select {
	case call := <-self.nginx.calls:
		if call.kind != kind {
			self.t.Fatalf("nginx %s, want %s", call.kind, kind)
		}
		return call
	case <-time.After(lbMapTestTimeout):
		self.t.Fatalf("no nginx %s", kind)
		return nil
	}
}

func (self *lbMapHarness) noCall() {
	self.t.Helper()
	select {
	case call := <-self.nginx.calls:
		self.t.Fatalf("nginx %s", call.kind)
	default:
	}
}

// Loads first before nginx starts, then runs: answers the start's poll with
// first, takes the test that loads it and the report Run sends, and returns
// the first poll Run makes, unanswered.
func (self *lbMapHarness) startLoaded(first *LbCustomHostMap) *fakeLbMapGet {
	self.t.Helper()
	if err := self.loadBeforeStart(func(get *fakeLbMapGet) { get.reply(first) }); err != nil {
		self.t.Fatal(err)
	}
	self.nextCall("test")
	self.run()
	if report := self.nextReport(); report.Version != first.Version {
		self.t.Fatalf("the first report names version %d", report.Version)
	}
	return self.nextGet()
}

// Answers get with next, moves the clock to the load the loop schedules at
// due, and takes the test, the reload and the report. Returns the poll after
// the load, unanswered.
func (self *lbMapHarness) loadNext(get *fakeLbMapGet, next *LbCustomHostMap, due time.Time) (*LbMapReport, *fakeLbMapGet) {
	self.t.Helper()
	get.reply(next)
	// the poll in flight, which the load ends
	self.nextGet()
	self.clock.awaitTimer(self.t, due)
	self.clock.AdvanceTo(due)
	render := self.render(next)
	for _, kind := range []string{"test", "reload"} {
		if call := self.nextCall(kind); call.mapText != string(render.Map) || call.http80Text != string(render.Http80) {
			self.t.Fatalf("nginx %s read:\n%s\n%s", kind, call.mapText, call.http80Text)
		}
	}
	report := self.nextReport()
	if report.Version != next.Version {
		self.t.Fatalf("the report names version %d, want %d", report.Version, next.Version)
	}
	return report, self.nextGet()
}

// An lb restarted with an old map file loads the newest version before nginx
// serves 443: one poll answered at once, the render, `nginx -t` on the new
// files, no reload. It claims the version only once Run knows the master,
// and reports the hosts added and dropped against the old file.
func TestLbMapLoadsTheNewestVersionBeforeNginxStarts(t *testing.T) {
	h := newLbMapHarness(t, lbMapTestVersion(3, "old.customer.example", "shop.customer.example"), nil)
	newest := lbMapTestVersion(5, "new.customer.example", "shop.customer.example")
	err := h.loadBeforeStart(func(get *fakeLbMapGet) {
		if get.poll.Interface != lbMapTestInterface || get.poll.Applied != nil || get.poll.Loaded != 0 || get.poll.Master != nil {
			t.Errorf("the start's poll %+v", get.poll)
		}
		get.reply(newest)
	})
	if err != nil {
		t.Fatal(err)
	}
	render := h.render(newest)
	if call := h.nextCall("test"); call.mapText != string(render.Map) || call.http80Text != string(render.Http80) {
		t.Errorf("nginx -t read the old files:\n%s", call.mapText)
	}
	h.noCall()
	if mapText, http80Text := h.files(); mapText != string(render.Map) || http80Text != string(render.Http80) {
		t.Errorf("the files hold:\n%s\n%s", mapText, http80Text)
	}
	if status := h.lbMap.Status(); status.Loaded != 5 || status.Report != nil {
		t.Errorf("before nginx runs: %+v", status)
	}

	h.run()
	report := h.nextReport()
	want := &LbMapReport{
		Format:    LbMapFormat,
		Interface: lbMapTestInterface,
		Version:   5,
		Digest:    newest.Digest,
		Master:    &LbMapReportMaster{Pid: 4242, StartTimeMillis: lbMapTestStart.Add(-time.Hour).UnixMilli()},
		Added:     []string{"new.customer.example"},
		Dropped:   []string{"old.customer.example"},
	}
	if !lbMapReportsEqual(report, want) {
		t.Errorf("report %+v, want %+v", report, want)
	}
	get := h.nextGet()
	if get.poll.Applied == nil || *get.poll.Applied != 5 || get.poll.Loaded != 5 || get.poll.Master == nil || get.poll.Master.Pid != 4242 {
		t.Errorf("the poll after the start %+v", get.poll)
	}
}

// A version above the one nginx runs loads 5 s after it arrives, not
// before, and the poll after the load repeats the new report.
func TestLbMapWaitsLoadDelayAfterTheFirstUnappliedVersion(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	next := lbMapTestVersion(2, "a.customer.example", "b.customer.example")
	get.reply(next)
	held := h.nextGet()
	if *held.poll.Applied != 2 || held.poll.Loaded != 1 {
		t.Errorf("the poll holding version 2 %+v", held.poll)
	}
	due := lbMapTestStart.Add(5 * time.Second)
	h.clock.awaitTimer(t, due)
	h.clock.AdvanceTo(due.Add(-time.Millisecond))
	h.noCall()
	if status := h.lbMap.Status(); status.Loaded != 1 || status.Pending != 2 {
		t.Errorf("before the delay: %+v", status)
	}
	h.clock.Advance(time.Millisecond)
	render := h.render(next)
	for _, kind := range []string{"test", "reload"} {
		if call := h.nextCall(kind); call.mapText != string(render.Map) {
			t.Errorf("nginx %s read:\n%s", kind, call.mapText)
		}
	}
	report := h.nextReport()
	if report.Version != 2 || !slices.Equal(report.Added, []string{"b.customer.example"}) || len(report.Dropped) != 0 || report.Failure != nil {
		t.Errorf("report %+v", report)
	}
	after := h.nextGet()
	if after.poll.Loaded != 2 || *after.poll.Applied != 2 {
		t.Errorf("the poll after the load %+v", after.poll)
	}
}

// After a reload the next waits out the 15 min window, however soon a
// version arrives.
func TestLbMapReloadsAtMostOncePerWindow(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	reloadTime := lbMapTestStart.Add(5 * time.Second)
	_, get = h.loadNext(get, lbMapTestVersion(2, "a.customer.example", "b.customer.example"), reloadTime)

	next := lbMapTestVersion(3, "a.customer.example", "b.customer.example", "c.customer.example")
	get.reply(next)
	h.nextGet()
	windowEnd := reloadTime.Add(15 * time.Minute)
	h.clock.awaitTimer(t, windowEnd)
	h.clock.AdvanceTo(windowEnd.Add(-time.Millisecond))
	h.noCall()
	h.clock.Advance(time.Millisecond)
	h.nextCall("test")
	h.nextCall("reload")
	if report := h.nextReport(); report.Version != 3 || !slices.Equal(report.Added, []string{"c.customer.example"}) {
		t.Errorf("report %+v", report)
	}
}

// Three adds and a remove inside one window load in one reload, its lists
// against the map the last reload left.
func TestLbMapLoadsSeveralVersionsInOneReload(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	reloadTime := lbMapTestStart.Add(5 * time.Second)
	_, get = h.loadNext(get, lbMapTestVersion(2, "a.customer.example", "b.customer.example"), reloadTime)

	versions := []*LbCustomHostMap{
		lbMapTestVersion(3, "a.customer.example", "b.customer.example", "c.customer.example"),
		lbMapTestVersion(4, "a.customer.example", "b.customer.example", "c.customer.example", "d.customer.example"),
		lbMapTestVersion(5, "a.customer.example", "b.customer.example", "c.customer.example", "d.customer.example", "e.customer.example"),
		lbMapTestVersion(6, "b.customer.example", "c.customer.example", "d.customer.example", "e.customer.example"),
	}
	for _, version := range versions {
		get.reply(version)
		get = h.nextGet()
		h.clock.Advance(time.Minute)
	}
	h.noCall()
	windowEnd := reloadTime.Add(15 * time.Minute)
	h.clock.awaitTimer(t, windowEnd)
	h.clock.AdvanceTo(windowEnd)
	render := h.render(versions[3])
	for _, kind := range []string{"test", "reload"} {
		if call := h.nextCall(kind); call.mapText != string(render.Map) {
			t.Errorf("nginx %s read:\n%s", kind, call.mapText)
		}
	}
	report := h.nextReport()
	if report.Version != 6 || !slices.Equal(report.Added, []string{"c.customer.example", "d.customer.example", "e.customer.example"}) || !slices.Equal(report.Dropped, []string{"a.customer.example"}) {
		t.Errorf("report %+v", report)
	}
	h.nextGet()
	h.noCall()
}

// A render the guard refuses touches neither file nor nginx, keeps
// reporting the version nginx runs, reports the failure, and logs no host.
func TestLbMapRefusedRenderKeepsThePriorMap(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	mapBefore, http80Before := h.files()
	refused := lbMapTestVersion(2, "a.customer.example", "shop.root.example")
	get.reply(refused)
	h.nextGet()
	due := lbMapTestStart.Add(5 * time.Second)
	h.clock.awaitTimer(t, due)
	h.clock.AdvanceTo(due)
	report := h.nextReport()
	if report.Version != 1 || report.Failure == nil || *report.Failure != (LbMapFailure{Version: 2, Digest: refused.Digest, Stage: LbMapStageRender}) {
		t.Errorf("report %+v", report)
	}
	h.noCall()
	if mapText, http80Text := h.files(); mapText != mapBefore || http80Text != http80Before {
		t.Errorf("the files changed:\n%s\n%s", mapText, http80Text)
	}
	if strings.Contains(h.logs.String(), "shop.root.example") {
		t.Errorf("the log names a custom host:\n%s", h.logs.String())
	}
}

// A failing `nginx -t` read the new files, puts the prior ones back, sends
// no reload, reports the failure with nginx's text kept out of the log's
// names, and tries the same version again a window later.
func TestLbMapFailingNginxTestRestoresThePriorMap(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	mapBefore, http80Before := h.files()
	h.nginx.failTests(errors.New(`nginx -t: exit status 1: nginx: [emerg] invalid parameter "shop.customer.example" in /run/warp-lb/tls-custom-hosts.map:4`))
	next := lbMapTestVersion(2, "a.customer.example", "shop.customer.example")
	get.reply(next)
	h.nextGet()
	failTime := lbMapTestStart.Add(5 * time.Second)
	h.clock.awaitTimer(t, failTime)
	h.clock.AdvanceTo(failTime)
	render := h.render(next)
	if call := h.nextCall("test"); call.mapText != string(render.Map) || call.http80Text != string(render.Http80) {
		t.Errorf("nginx -t did not read the new files:\n%s", call.mapText)
	}
	report := h.nextReport()
	if report.Version != 1 || report.Failure == nil || *report.Failure != (LbMapFailure{Version: 2, Digest: next.Digest, Stage: LbMapStageTest}) {
		t.Errorf("report %+v", report)
	}
	h.noCall()
	if mapText, http80Text := h.files(); mapText != mapBefore || http80Text != http80Before {
		t.Errorf("the prior files are not back:\n%s\n%s", mapText, http80Text)
	}
	if logs := h.logs.String(); strings.Contains(logs, "shop.customer.example") || !strings.Contains(logs, "[custom host]") {
		t.Errorf("the log:\n%s", logs)
	}

	h.nextGet()
	retryTime := failTime.Add(15 * time.Minute)
	h.clock.awaitTimer(t, retryTime)
	h.clock.AdvanceTo(retryTime.Add(-time.Millisecond))
	h.noCall()
	h.clock.Advance(time.Millisecond)
	h.nextCall("test")
	h.nextCall("reload")
	if report := h.nextReport(); report.Version != 2 || report.Failure != nil {
		t.Errorf("the retry's report %+v", report)
	}
}

// A reload that fails puts the prior files back and keeps reporting the
// prior version, since nginx did not show it loaded the new one; the next
// try waits a window from that reload.
func TestLbMapFailingReloadRestoresThePriorMap(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(1, "a.customer.example"))
	mapBefore, http80Before := h.files()
	h.nginx.failReloads(errors.New("nginx master 4242 ran no new worker after the reload: context canceled"))
	next := lbMapTestVersion(2, "a.customer.example", "b.customer.example")
	get.reply(next)
	h.nextGet()
	reloadTime := lbMapTestStart.Add(5 * time.Second)
	h.clock.awaitTimer(t, reloadTime)
	h.clock.AdvanceTo(reloadTime)
	render := h.render(next)
	h.nextCall("test")
	if call := h.nextCall("reload"); call.mapText != string(render.Map) {
		t.Errorf("the reload did not see the new map:\n%s", call.mapText)
	}
	report := h.nextReport()
	if report.Version != 1 || report.Failure == nil || *report.Failure != (LbMapFailure{Version: 2, Digest: next.Digest, Stage: LbMapStageReload}) {
		t.Errorf("report %+v", report)
	}
	if mapText, http80Text := h.files(); mapText != mapBefore || http80Text != http80Before {
		t.Errorf("the prior files are not back:\n%s\n%s", mapText, http80Text)
	}

	h.nextGet()
	retryTime := reloadTime.Add(15 * time.Minute)
	h.clock.awaitTimer(t, retryTime)
	h.clock.AdvanceTo(retryTime)
	h.nextCall("test")
	h.nextCall("reload")
	if report := h.nextReport(); report.Version != 2 || report.Failure != nil {
		t.Errorf("the retry's report %+v", report)
	}
}

// With the dns API down at start, nginx starts on the map it holds and lbmap
// claims no version and sends no report; its polls back off and repeat the
// master; once the API answers, the newest version loads by reload, its
// lists against the old file. No address reaches the log.
func TestLbMapApiOutageAtStartClaimsNoVersion(t *testing.T) {
	h := newLbMapHarness(t, lbMapTestVersion(3, "old.customer.example"), nil)
	mapBefore, _ := h.files()
	err := h.loadBeforeStart(func(get *fakeLbMapGet) {
		get.fail(errors.New("dial tcp 198.51.100.7:443: connect: connection refused"))
	})
	if err == nil {
		t.Error("LoadBeforeStart passed with the api down")
	}
	h.noCall()
	if mapText, _ := h.files(); mapText != mapBefore {
		t.Errorf("the file changed:\n%s", mapText)
	}

	h.run()
	get := h.nextGet()
	if *get.poll.Applied != 0 || get.poll.Loaded != 0 || get.poll.Master == nil {
		t.Errorf("the first poll %+v", get.poll)
	}
	h.noReport()
	get.fail(errors.New("dial tcp 198.51.100.7:443: connect: connection refused"))
	firstRetry := lbMapTestStart.Add(time.Second)
	h.clock.awaitTimer(t, firstRetry)
	h.clock.AdvanceTo(firstRetry)
	get = h.nextGet()
	get.fail(errors.New("api answered 503"))
	secondRetry := firstRetry.Add(2 * time.Second)
	h.clock.awaitTimer(t, secondRetry)
	h.clock.AdvanceTo(secondRetry)
	get = h.nextGet()
	h.noReport()
	if status := h.lbMap.Status(); status.Loaded != 0 || status.Report != nil {
		t.Errorf("during the outage: %+v", status)
	}

	newest := lbMapTestVersion(5, "new.customer.example")
	report, _ := h.loadNext(get, newest, secondRetry.Add(5*time.Second))
	if !slices.Equal(report.Added, []string{"new.customer.example"}) || !slices.Equal(report.Dropped, []string{"old.customer.example"}) {
		t.Errorf("report %+v", report)
	}
	if strings.Contains(h.logs.String(), "198.51.100.7") {
		t.Errorf("the log holds an address:\n%s", h.logs.String())
	}
}

// An API that does not answer at start holds nginx back no longer than
// StartTimeout, and nothing is loaded.
func TestLbMapStartsNginxWhenTheApiDoesNotAnswer(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	done := make(chan error, 1)
	go func() {
		done <- h.lbMap.LoadBeforeStart()
	}()
	h.nextGet()
	timeout := lbMapTestStart.Add(10 * time.Second)
	h.clock.awaitTimer(t, timeout)
	h.clock.AdvanceTo(timeout)
	select {
	case err := <-done:
		if err == nil {
			t.Error("no error past the start's bound")
		}
	case <-time.After(lbMapTestTimeout):
		t.Fatal("LoadBeforeStart did not return at its bound")
	}
	h.noCall()
	if status := h.lbMap.Status(); status.Loaded != 0 {
		t.Errorf("status %+v", status)
	}
}

// A report the API did not take goes again before the next poll, and one it
// took does not; every poll repeats the version and the master.
func TestLbMapRepeatsItsReportUntilTaken(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	h.api.failApplied(errors.New("api answered 503"))
	if err := h.loadBeforeStart(func(get *fakeLbMapGet) { get.reply(lbMapTestVersion(1, "a.customer.example")) }); err != nil {
		t.Fatal(err)
	}
	h.nextCall("test")
	h.run()
	first := h.nextReport()
	get := h.nextGet()
	if get.poll.Loaded != 1 || get.poll.Master == nil || get.poll.Master.Pid != 4242 {
		t.Errorf("the poll does not repeat the report: %+v", get.poll)
	}
	if status := h.lbMap.Status(); status.ReportTaken {
		t.Error("a refused report counts as taken")
	}
	get.reply(nil)
	second := h.nextReport()
	if !lbMapReportsEqual(first, second) {
		t.Errorf("the report changed: %+v then %+v", first, second)
	}
	get = h.nextGet()
	get.reply(nil)
	get = h.nextGet()
	h.noReport()
	if status := h.lbMap.Status(); !status.ReportTaken {
		t.Error("the taken report is not taken")
	}
	if get.poll.Loaded != 1 {
		t.Errorf("poll %+v", get.poll)
	}
}

// Polls start no closer than PollMinInterval, so an API that answers at once
// cannot spin the loop.
func TestLbMapPollsNoFasterThanItsMinimumInterval(t *testing.T) {
	settings := lbMapTestSettings()
	settings.PollMinInterval = time.Second
	h := newLbMapHarness(t, nil, settings)
	h.run()
	h.nextGet().reply(nil)
	next := lbMapTestStart.Add(time.Second)
	h.clock.awaitTimer(t, next)
	h.noGet()
	h.clock.AdvanceTo(next)
	h.nextGet()
}

// A version at or below the one lbmap holds changes nothing: no load, no
// pending version.
func TestLbMapIgnoresAVersionItHolds(t *testing.T) {
	h := newLbMapHarness(t, nil, nil)
	get := h.startLoaded(lbMapTestVersion(5, "a.customer.example"))
	get.reply(lbMapTestVersion(4, "b.customer.example"))
	get = h.nextGet()
	get.reply(lbMapTestVersion(5, "a.customer.example"))
	get = h.nextGet()
	if *get.poll.Applied != 5 {
		t.Errorf("poll %+v", get.poll)
	}
	if status := h.lbMap.Status(); status.Loaded != 5 || status.Pending != 0 {
		t.Errorf("status %+v", status)
	}
	h.noCall()
}

// The HTTP client: the bearer on each request, the poll's query, the map
// read from 200 and nothing from 204, a refusal naming its status and never
// the bearer, and the report's JSON.
func TestLbMapHttpApiCarriesThePollAndTheReport(t *testing.T) {
	bearer := "c2lkZWNhci10ZXN0LWxibWFwLWJlYXJlci0wMTIzNDU"
	version := lbMapTestVersion(7, "shop.customer.example")
	var stateLock sync.Mutex
	requests := []*http.Request{}
	bodies := [][]byte{}
	answers := []int{http.StatusOK, http.StatusNoContent, http.StatusForbidden}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		stateLock.Lock()
		defer stateLock.Unlock()
		requests = append(requests, request)
		bodies = append(bodies, body)
		if request.Method == http.MethodPost {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		status := answers[0]
		answers = answers[1:]
		if status != http.StatusOK {
			writer.WriteHeader(status)
			return
		}
		json.NewEncoder(writer).Encode(version)
	}))
	defer server.Close()
	api, err := NewLbMapHttpApi(server.URL, bearer, server.Client(), DefaultLbMapSettings())
	if err != nil {
		t.Fatal(err)
	}
	applied := uint64(6)
	poll := &LbMapPoll{Interface: lbMapTestInterface, Applied: &applied, Loaded: 5, Master: &NginxMaster{Pid: 4242, StartTime: time.UnixMilli(1700000000123)}}
	got, err := api.CustomHostMap(context.Background(), poll)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || got.Digest != version.Digest || !slices.Equal(got.Hosts, version.Hosts) {
		t.Errorf("map %+v", got)
	}
	if got, err := api.CustomHostMap(context.Background(), &LbMapPoll{Interface: lbMapTestInterface}); got != nil || err != nil {
		t.Errorf("204: %+v %v", got, err)
	}
	_, err = api.CustomHostMap(context.Background(), poll)
	if !errors.Is(err, ErrLbMapApiRefused) || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), bearer) {
		t.Errorf("403: %v", err)
	}
	report := &LbMapReport{Format: LbMapFormat, Interface: lbMapTestInterface, Version: 7, Digest: version.Digest, Master: &LbMapReportMaster{Pid: 4242, StartTimeMillis: 1700000000123}, Added: []string{"shop.customer.example"}}
	if err := api.Applied(context.Background(), report); err != nil {
		t.Fatal(err)
	}

	stateLock.Lock()
	defer stateLock.Unlock()
	for _, request := range requests {
		if request.Header.Get("Authorization") != "Bearer "+bearer {
			t.Errorf("%s %s carries %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
	}
	first := requests[0]
	if first.Method != http.MethodGet || first.URL.Path != LbMapCustomHostMapPath {
		t.Errorf("first %s %s", first.Method, first.URL.Path)
	}
	query := first.URL.Query()
	for key, want := range map[string]string{"interface": lbMapTestInterface, "applied": "6", "loaded": "5", "master_pid": "4242", "master_start_ms": "1700000000123"} {
		if query.Get(key) != want {
			t.Errorf("query %s = %q, want %q", key, query.Get(key), want)
		}
	}
	// the start's poll holds no applied, so the API answers it at once
	if second := requests[1].URL.Query(); second.Has("applied") || second.Has("master_pid") || second.Get("loaded") != "0" {
		t.Errorf("the start's query %v", second)
	}
	last := requests[len(requests)-1]
	if last.Method != http.MethodPost || last.URL.Path != LbMapAppliedPath || last.Header.Get("Content-Type") != "application/json" {
		t.Errorf("report %s %s %s", last.Method, last.URL.Path, last.Header.Get("Content-Type"))
	}
	sent := map[string]any{}
	if err := json.Unmarshal(bodies[len(bodies)-1], &sent); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"format", "interface", "version", "digest", "master", "added"} {
		if _, ok := sent[key]; !ok {
			t.Errorf("the report lacks %s: %s", key, bodies[len(bodies)-1])
		}
	}
	if master, ok := sent["master"].(map[string]any); !ok || master["pid"] != float64(4242) || master["start_time_ms"] != float64(1700000000123) {
		t.Errorf("master %v", sent["master"])
	}
}

// An answer past AnswerMaxByteCount is refused before it is decoded.
func TestLbMapHttpApiBoundsTheAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		json.NewEncoder(writer).Encode(lbMapTestVersion(7, "shop.customer.example", "www.customer.example"))
	}))
	defer server.Close()
	settings := DefaultLbMapSettings()
	settings.AnswerMaxByteCount = 64
	api, err := NewLbMapHttpApi(server.URL, "c2lkZWNhci10ZXN0LWxibWFwLWJlYXJlci0wMTIzNDU", server.Client(), settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.CustomHostMap(context.Background(), &LbMapPoll{Interface: lbMapTestInterface}); !errors.Is(err, ErrLbMapApiRefused) {
		t.Errorf("a long answer: %v", err)
	}
	if _, err := NewLbMapHttpApi("not a url", "x", server.Client(), settings); err == nil {
		t.Error("a url that is not one")
	}
	if _, err := NewLbMapHttpApi(server.URL, "", server.Client(), settings); err == nil {
		t.Error("no credential")
	}
}

// An answer's format is read first: a newer one stops with
// ErrLbMapFormatTooNew, format zero is refused, and an unknown field at this
// format is ignored.
func TestDecodeLbCustomHostMapReadsTheFormatFirst(t *testing.T) {
	if _, err := DecodeLbCustomHostMap([]byte(`{"format":2,"version":9,"hosts":"anything"}`)); !errors.Is(err, ErrLbMapFormatTooNew) {
		t.Errorf("format 2: %v", err)
	}
	if _, err := DecodeLbCustomHostMap([]byte(`{"version":9}`)); !errors.Is(err, ErrLbMapApiRefused) {
		t.Errorf("no format: %v", err)
	}
	customHostMap, err := DecodeLbCustomHostMap([]byte(`{"format":1,"version":9,"digest":"x","hosts":["a.customer.example"],"later":true}`))
	if err != nil || customHostMap.Version != 9 || !slices.Equal(customHostMap.Hosts, []string{"a.customer.example"}) {
		t.Errorf("format 1 with a later field: %+v %v", customHostMap, err)
	}
}

// internal-lbmap.yml: the current bearer, a previous one checked too, each
// 256 bits in unpadded base64url; no error carries a bearer.
func TestLoadLbMapCredential(t *testing.T) {
	current := "c2lkZWNhci10ZXN0LWxibWFwLWJlYXJlci0wMTIzNDU"
	previous := "c2lkZWNhci10ZXN0LWxibWFwLWJlYXJlci01NDMyMTA"
	bearer, err := LoadLbMapCredential([]byte("current: " + current + "\nprevious: " + previous + "\n"))
	if err != nil || bearer != current {
		t.Errorf("%q %v", bearer, err)
	}
	for _, text := range []string{
		"previous: " + previous + "\n",
		"current: c2hvcnQ\n",
		"current: " + current + "\nprevious: c2hvcnQ\n",
		"current: " + current + "\nnext: " + previous + "\n",
		"current: [" + current + "\n",
	} {
		_, err := LoadLbMapCredential([]byte(text))
		if !errors.Is(err, ErrLbMapCredentialRefused) {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if strings.Contains(err.Error(), current) || strings.Contains(err.Error(), previous) || strings.Contains(err.Error(), "c2hvcnQ") {
			t.Errorf("the error carries a bearer: %v", err)
		}
	}
}

// The interface's name as the feed and the drained list write it: the
// block's host short, its domain cut and its dots made hyphens, the
// interface as it is.
func TestLbMapInterfaceName(t *testing.T) {
	for _, c := range []struct {
		block  string
		domain string
		want   string
	}{
		{block: "main-edge-1.example.com-eth0", domain: "example.com", want: "main-edge-1-eth0"},
		{block: "edge.site-a.example.com-eth0.100", domain: "example.com", want: "edge-site-a-eth0.100"},
		{block: "main-edge-1-eth0", domain: "example.com", want: "main-edge-1-eth0"},
		{block: "main-edge-1.example.com-eth0", domain: "", want: "main-edge-1.example.com-eth0"},
	} {
		if got := LbMapInterfaceName(c.block, c.domain); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.block, c.domain, got, c.want)
		}
	}
}

// The defaults are §13.4's values and validate; a bound that is not positive
// does not.
func TestLbMapSettingsDefaults(t *testing.T) {
	settings := DefaultLbMapSettings()
	if settings.LoadDelay != 5*time.Second || settings.ReloadMinInterval != 15*time.Minute {
		t.Errorf("defaults %+v", settings)
	}
	if err := settings.Validate(); err != nil {
		t.Error(err)
	}
	settings.ReloadTimeout = 0
	if err := settings.Validate(); err == nil {
		t.Error("a zero reload timeout validates")
	}
}
