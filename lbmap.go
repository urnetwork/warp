package warp

// lbmap (§13.4, §19.5 W1, D-TLS-2, D-TLS-12, R-TLS-1, FS-122): the loop beside
// each lb interface's nginx that loads §12.8's custom-host map into the SNI
// split, so a ready custom host's ClientHello reaches tlsedge on that
// interface, and reports which version that nginx runs.
//
// It long-polls GET /dns/internal/custom-host-map for the newest version. It
// loads the newest version before nginx serves 443 at start (LoadBeforeStart),
// and otherwise LoadDelay after the first version above the one nginx runs,
// at most once per ReloadMinInterval, since each reload keeps the old workers,
// with their connections, for up to worker_shutdown_timeout (60 min). Every
// version that arrives inside one window loads in that one reload. A load
// renders both include files from the version's rows (lbmap_render.go),
// writes each through a temp file and a rename, runs `nginx -t` on the config
// path the master runs, reloads, and reports the version with the master's pid
// and start time and the hosts it added and dropped against the map it held,
// on POST /dns/internal/custom-host-map/applied. A failed render, test or
// reload puts the prior files back, keeps reporting the prior version, and
// reports the failure; the failed version is tried again no sooner than a
// window later, and a newer version on the usual schedule. Each long-poll
// repeats the report: it carries the version nginx runs and its master, and a
// report the API did not take is sent again before the next poll.
//
// A report never claims a version nginx did not load: lbmap claims none until
// it has loaded one itself into the master that runs, so with the dns API down
// at start nginx starts on whatever map it holds and the interface is current
// for no version until a reload. The dns edges' route probes check every
// claim (§13.4).
//
// The routes sit under the dns API's internal prefix
// (plan-DNS-internal-route-credential), each request carrying the bearer from
// internal-lbmap.yml in the lb's secret_files and naming its interface, which
// the API checks against the lb inventory (plan-TLS-internal-credentials).
// The API's side is DNS-M6-03's; this file declares the shapes it serves.
//
// Every wait is on LbMapSettings and the injected clock. Logs carry versions,
// digests, counts and stages, never a custom host's name (I-13).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// The dns API's routes lbmap calls, under the internal prefix
// (plan-DNS-internal-route-credential over §12.8's /dns/custom-host-map).
const (
	LbMapCustomHostMapPath = "/dns/internal/custom-host-map"
	LbMapAppliedPath       = "/dns/internal/custom-host-map/applied"
)

// Where warpctl mounts the lb's secret_files, and lbmap's credential file
// there (plan-TLS-internal-credentials).
const LbMapCredentialPath = "/srv/warp/secrets/internal-lbmap.yml"

// A bearer's raw length: 256 random bits, as every internal caller's
// (plan-DNS-internal-route-credential).
const lbMapCredentialByteCount = 32

// A credential file lbmap cannot use. The text never holds a bearer.
var ErrLbMapCredentialRefused = errors.New("lbmap credential refused")

// The API answered something other than what the route promises.
var ErrLbMapApiRefused = errors.New("lbmap api refused")

func DefaultLbMapSettings() *LbMapSettings {
	return &LbMapSettings{
		LoadDelay:          5 * time.Second,
		ReloadMinInterval:  15 * time.Minute,
		StartTimeout:       10 * time.Second,
		PollTimeout:        30 * time.Second,
		PollMinInterval:    1 * time.Second,
		ErrorBackoffMin:    1 * time.Second,
		ErrorBackoffMax:    30 * time.Second,
		ReportTimeout:      10 * time.Second,
		TestTimeout:        60 * time.Second,
		ReloadTimeout:      60 * time.Second,
		AnswerMaxByteCount: 32 * 1024 * 1024,
		MaxHostCount:       200 * 1000,
	}
}

// lbmap's tunables. Every one is read on the injected clock.
type LbMapSettings struct {
	// How long after the first version above the one nginx runs a load
	// starts (§13.4: 5 s), so versions that arrive together load together.
	LoadDelay time.Duration
	// The least time between two reloads (§13.4: 15 min), since each keeps
	// the old workers up to worker_shutdown_timeout (60 min). Also how long a
	// version whose load failed waits before it is tried again.
	ReloadMinInterval time.Duration
	// How long LoadBeforeStart waits for the API before nginx starts on the
	// map it holds. nginx must start whether or not the API answers.
	StartTimeout time.Duration
	// A long-poll's bound. The API holds one at most 25 s, and the lb's
	// proxy_read_timeout on the dns API block is 30 s.
	PollTimeout time.Duration
	// The least time between the starts of two polls, so an API that answers
	// at once cannot spin the loop. Zero polls again at once.
	PollMinInterval time.Duration
	// The first wait after a failed poll, doubling to ErrorBackoffMax. The cap
	// keeps an interface polling well inside the API's 2 min, after which it
	// counts the interface as having loaded no version.
	ErrorBackoffMin time.Duration
	ErrorBackoffMax time.Duration
	// A report's bound.
	ReportTimeout time.Duration
	// `nginx -t`'s bound, and a reload's: how long the master may take to run
	// a worker after the signal before the reload counts as failed.
	TestTimeout   time.Duration
	ReloadTimeout time.Duration
	// The most an answer's body may hold. A map of MaxHostCount long names
	// fits.
	AnswerMaxByteCount int64
	// The most hosts one version may hold; the render refuses a larger one.
	// Far above any Team's custom hosts (v1), while bounding what one answer
	// can make nginx hash.
	MaxHostCount int
}

// Refuses settings lbmap cannot run on: a bound that is not positive, or
// a negative wait. LoadDelay, ReloadMinInterval and PollMinInterval may be
// zero, which tests use; production keeps §13.4's values.
func (self *LbMapSettings) Validate() error {
	for name, timeout := range map[string]time.Duration{
		"StartTimeout":    self.StartTimeout,
		"PollTimeout":     self.PollTimeout,
		"ErrorBackoffMin": self.ErrorBackoffMin,
		"ErrorBackoffMax": self.ErrorBackoffMax,
		"ReportTimeout":   self.ReportTimeout,
		"TestTimeout":     self.TestTimeout,
		"ReloadTimeout":   self.ReloadTimeout,
	} {
		if timeout <= 0 {
			return fmt.Errorf("lbmap settings: %s must be positive", name)
		}
	}
	for name, wait := range map[string]time.Duration{
		"LoadDelay":         self.LoadDelay,
		"ReloadMinInterval": self.ReloadMinInterval,
		"PollMinInterval":   self.PollMinInterval,
	} {
		if wait < 0 {
			return fmt.Errorf("lbmap settings: %s is negative", name)
		}
	}
	if self.ErrorBackoffMax < self.ErrorBackoffMin {
		return errors.New("lbmap settings: ErrorBackoffMax is below ErrorBackoffMin")
	}
	if self.AnswerMaxByteCount <= 0 || self.MaxHostCount <= 0 {
		return errors.New("lbmap settings: AnswerMaxByteCount and MaxHostCount must be positive")
	}
	return nil
}

// What lbmap reads time from. Implementations are safe for concurrent use.
type LbMapClock interface {
	Now() time.Time
	// Fires once the clock reaches now plus timeout; at once when timeout is
	// not positive.
	After(timeout time.Duration) <-chan time.Time
}

// The real clock.
type lbMapRealClock struct{}

func (self lbMapRealClock) Now() time.Time {
	return time.Now()
}

func (self lbMapRealClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

// The lb interface's name as the dns feed's inventory, the `<env>-lb` sets and
// config/<env>/sidecar.yml's drained list name it (TLS-M5-03):
// `<host>-<iface>` with the host short, its domain cut and its dots made
// hyphens. block is WARP_BLOCK, `<host>-<iface>` with the host as services.yml
// writes it, and domain WARP_DOMAIN. A block whose host does not end in the
// domain names itself, and the API refuses a name not in its inventory, the
// closed direction.
func LbMapInterfaceName(block string, domain string) string {
	if domain == "" {
		return block
	}
	marker := "." + domain + "-"
	at := strings.LastIndex(block, marker)
	if at < 0 {
		return block
	}
	return strings.ReplaceAll(block[:at], ".", "-") + "-" + block[at+len(marker):]
}

// One long-poll's request: GET /dns/internal/custom-host-map with
// `interface`, `applied` when set, `loaded` and, once known, `master_pid` and
// `master_start_ms`.
type LbMapPoll struct {
	// The interface's inventory name.
	Interface string
	// The newest version this lbmap holds, loaded or waiting: the API holds
	// the answer up to 25 s until its newest differs from it. Nil at start,
	// answered at once.
	Applied *uint64
	// The version nginx runs, 0 for none, and its master: the report, repeated.
	Loaded uint64
	Master *NginxMaster
}

// A load's stage, for a failure's report.
type LbMapStage string

const (
	LbMapStageRender LbMapStage = "render"
	LbMapStageTest   LbMapStage = "test"
	LbMapStageReload LbMapStage = "reload"
)

// The body of POST /dns/internal/custom-host-map/applied (§12.8, dns-1): what
// one interface's nginx runs, and the last load that failed.
type LbMapReport struct {
	// Read first, as the map's is.
	Format    int    `json:"format"`
	Interface string `json:"interface"`
	// The version the master runs, which lbmap loaded into it; 0 for none.
	Version uint64 `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	// The master, once lbmap knows it, whether or not it runs a version.
	Master *LbMapReportMaster `json:"master,omitempty"`
	// The hosts that version added and dropped against the map nginx held
	// before it, which the route probes take (§13.4) and a restore lists
	// (§19.10).
	Added   []string `json:"added,omitempty"`
	Dropped []string `json:"dropped,omitempty"`
	// The last load that failed, while its version is above Version.
	Failure *LbMapFailure `json:"failure,omitempty"`
}

// An nginx master as a report names it.
type LbMapReportMaster struct {
	Pid             int   `json:"pid"`
	StartTimeMillis int64 `json:"start_time_ms"`
}

// A load that failed: its version and digest and the stage that refused it.
type LbMapFailure struct {
	Version uint64     `json:"version"`
	Digest  string     `json:"digest,omitempty"`
	Stage   LbMapStage `json:"stage"`
}

// The dns API's routes, as lbmap calls them. Implementations are safe for
// concurrent use.
type LbMapApi interface {
	// The newest version when it differs from poll.Applied, or nil when the
	// API's hold ended with nothing newer, or it holds no version. ctx bounds
	// the call.
	CustomHostMap(ctx context.Context, poll *LbMapPoll) (*LbCustomHostMap, error)
	// Sends a report; nil once the API took it.
	Applied(ctx context.Context, report *LbMapReport) error
}

// Reads internal-lbmap.yml: `current`, and during a rotation `previous`, each
// 256 bits in unpadded base64url, as every internal caller's file is
// (plan-DNS-internal-route-credential). Returns current, the bearer lbmap
// sends.
func LoadLbMapCredential(data []byte) (string, error) {
	credential := &struct {
		Current  string `yaml:"current"`
		Previous string `yaml:"previous"`
	}{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(credential); err != nil {
		// the decoder's text can quote a value, so it is not passed on
		return "", fmt.Errorf("%w: the file is not a credential", ErrLbMapCredentialRefused)
	}
	for _, bearer := range []string{credential.Current, credential.Previous} {
		if bearer == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(bearer)
		if err != nil || len(raw) != lbMapCredentialByteCount {
			return "", fmt.Errorf("%w: a bearer that is not 256 bits in base64url", ErrLbMapCredentialRefused)
		}
	}
	if credential.Current == "" {
		return "", fmt.Errorf("%w: no current bearer", ErrLbMapCredentialRefused)
	}
	return credential.Current, nil
}

// The API over HTTP. Safe for concurrent use, as its http.Client is.
type lbMapHttpApi struct {
	baseUrl    string
	credential string
	client     *http.Client
	settings   *LbMapSettings
}

// The API at baseUrl, its scheme and host, sending credential as a bearer.
// client must not time a request out before PollTimeout; ctx bounds each
// call.
func NewLbMapHttpApi(baseUrl string, credential string, client *http.Client, settings *LbMapSettings) (LbMapApi, error) {
	parsed, err := url.Parse(baseUrl)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: the api's url is not one", ErrLbMapApiRefused)
	}
	if credential == "" {
		return nil, fmt.Errorf("%w: no credential", ErrLbMapApiRefused)
	}
	return &lbMapHttpApi{
		baseUrl:    strings.TrimSuffix(baseUrl, "/"),
		credential: credential,
		client:     client,
		settings:   settings,
	}, nil
}

// Sends request with the bearer. A status outside wants is an error that
// names the path and status, never the body or the bearer.
func (self *lbMapHttpApi) do(request *http.Request, wants ...int) (*http.Response, error) {
	request.Header.Set("Authorization", "Bearer "+self.credential)
	response, err := self.client.Do(request)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(wants, response.StatusCode) {
		response.Body.Close()
		return nil, fmt.Errorf("%w: %s answered %d", ErrLbMapApiRefused, request.URL.Path, response.StatusCode)
	}
	return response, nil
}

func (self *lbMapHttpApi) CustomHostMap(ctx context.Context, poll *LbMapPoll) (*LbCustomHostMap, error) {
	query := url.Values{
		"interface": {poll.Interface},
		"loaded":    {strconv.FormatUint(poll.Loaded, 10)},
	}
	if poll.Applied != nil {
		query.Set("applied", strconv.FormatUint(*poll.Applied, 10))
	}
	if poll.Master != nil {
		query.Set("master_pid", strconv.Itoa(poll.Master.Pid))
		query.Set("master_start_ms", strconv.FormatInt(poll.Master.StartTime.UnixMilli(), 10))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.baseUrl+LbMapCustomHostMapPath+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := self.do(request, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, self.settings.AnswerMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.settings.AnswerMaxByteCount < int64(len(data)) {
		return nil, fmt.Errorf("%w: an answer past %d bytes", ErrLbMapApiRefused, self.settings.AnswerMaxByteCount)
	}
	return DecodeLbCustomHostMap(data)
}

func (self *lbMapHttpApi) Applied(ctx context.Context, report *LbMapReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.baseUrl+LbMapAppliedPath, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := self.do(request, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}

// Reads one answer, its format first: a format above LbMapFormat stops here
// with ErrLbMapFormatTooNew, before anything else is read. Unknown fields are
// ignored, as a newer API's additions at this format are.
func DecodeLbCustomHostMap(data []byte) (*LbCustomHostMap, error) {
	var header struct {
		Format  int    `json:"format"`
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLbMapApiRefused, err)
	}
	if header.Format <= 0 {
		return nil, fmt.Errorf("%w: format %d", ErrLbMapApiRefused, header.Format)
	}
	if LbMapFormat < header.Format {
		return nil, fmt.Errorf("%w: version %d: format %d above %d", ErrLbMapFormatTooNew, header.Version, header.Format, LbMapFormat)
	}
	customHostMap := &LbCustomHostMap{}
	if err := json.Unmarshal(data, customHostMap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLbMapApiRefused, err)
	}
	return customHostMap, nil
}

// What one lbmap loads and where.
type LbMapConfig struct {
	// The interface's inventory name (LbMapInterfaceName).
	Interface string
	// The two include files nginx reads: LbTlsCustomHostsMapPath and
	// LbTlsCustomHosts80Path in the lb.
	MapPath    string
	Http80Path string
	// The guard and the edge's upstream, from the config nginx runs.
	Render *LbMapRenderConfig
	// nil reads real time.
	Clock LbMapClock
	// nil logs to Err.
	Log *log.Logger
}

// What lbmap holds now, for a test or a status line.
type LbMapStatus struct {
	// The version nginx runs, which lbmap loaded into it; 0 for none.
	Loaded uint64
	// The newest version waiting for its load; 0 for none.
	Pending uint64
	// The report as it stands, and whether the API took it.
	Report      *LbMapReport
	ReportTaken bool
}

// A version nginx runs, as lbmap loaded it.
type lbMapLoaded struct {
	version uint64
	digest  string
	added   []string
	dropped []string
	// nil while nginx has not started: a load before start, claimed once the
	// master is known
	master *NginxMaster
}

// One poll's end, from its goroutine.
type lbMapPollOutcome struct {
	answer *LbCustomHostMap
	err    error
	// the loop ended it itself, after a load, so the next poll repeats the new
	// report at once
	canceled bool
}

// The loop. LoadBeforeStart runs once, before nginx starts; Run once nginx
// has started, until ctx ends. Status is safe from any goroutine.
type LbMap struct {
	ctx      context.Context
	config   *LbMapConfig
	settings *LbMapSettings
	api      LbMapApi
	nginx    NginxControl
	clock    LbMapClock
	log      *log.Logger

	stateLock sync.Mutex
	// the hosts in the files nginx holds now, which a load adds to and drops
	// from; empty when the map file was missing or unreadable at start
	heldHosts []string
	// the version nginx runs, nil for none
	loaded *lbMapLoaded
	// the newest version above the loaded one, waiting for its load
	pending *LbCustomHostMap
	// when the first version above the loaded one arrived: LoadDelay counts
	// from here, so every version inside a window loads in one reload
	firstUnappliedTime time.Time
	// when the last reload signal went, zero for none
	lastReloadTime time.Time
	// the last failed load, while its version is above the loaded one, and
	// when it failed
	failure     *LbMapFailure
	failureTime time.Time
	// the master, once Run has it
	master *NginxMaster
	// the report as it stands, nil while there is nothing to report, and
	// whether the API took it
	report      *LbMapReport
	reportTaken bool
}

// An lbmap for config's interface, not yet running. It reads what the map
// file holds now, which the first load's added and dropped lists are against,
// and removes temp files a write that died left behind.
func NewLbMap(ctx context.Context, config *LbMapConfig, settings *LbMapSettings, api LbMapApi, nginx NginxControl) (*LbMap, error) {
	if config.Interface == "" || config.MapPath == "" || config.Http80Path == "" {
		return nil, errors.New("lbmap needs an interface and both include paths")
	}
	if config.Render == nil {
		return nil, errors.New("lbmap needs the split's render config")
	}
	if err := config.Render.Validate(); err != nil {
		return nil, err
	}
	if api == nil || nginx == nil {
		return nil, errors.New("lbmap needs an api and nginx's control")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = lbMapRealClock{}
	}
	logger := config.Log
	if logger == nil {
		logger = Err
	}
	self := &LbMap{
		ctx:      ctx,
		config:   config,
		settings: settings,
		api:      api,
		nginx:    nginx,
		clock:    clock,
		log:      logger,
	}
	for _, path := range []string{config.MapPath, config.Http80Path} {
		if err := removeLbMapTempFiles(path); err != nil {
			return nil, err
		}
	}
	mapText, err := os.ReadFile(config.MapPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		self.heldHosts = []string{}
	case err != nil:
		return nil, err
	default:
		heldHosts, parseErr := ParseLbMapHosts(mapText)
		if parseErr != nil {
			// what nginx holds is unknown, so a first load's lists are against
			// nothing
			self.log.Printf("[lbmap] %s: the map nginx holds is unreadable, so the first load lists every host as added: %s", config.Interface, parseErr)
			heldHosts = []string{}
		}
		self.heldHosts = heldHosts
	}
	return self, nil
}

// What lbmap holds now.
func (self *LbMap) Status() *LbMapStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := &LbMapStatus{ReportTaken: self.reportTaken}
	if self.loaded != nil {
		status.Loaded = self.loaded.version
	}
	if self.pending != nil {
		status.Pending = self.pending.Version
	}
	if self.report != nil {
		status.Report = cloneLbMapReport(self.report)
	}
	return status
}

func cloneLbMapReport(report *LbMapReport) *LbMapReport {
	clone := *report
	clone.Added = slices.Clone(report.Added)
	clone.Dropped = slices.Clone(report.Dropped)
	if report.Master != nil {
		master := *report.Master
		clone.Master = &master
	}
	if report.Failure != nil {
		failure := *report.Failure
		clone.Failure = &failure
	}
	return &clone
}

// A context that ends with ctx or once the injected clock passes timeout, so
// a fake clock times out calls as it times everything else.
func (self *LbMap) withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	timeoutCtx, cancel := context.WithCancel(ctx)
	fired := self.clock.After(timeout)
	go func() {
		select {
		case <-timeoutCtx.Done():
		case <-fired:
			cancel()
		}
	}()
	return timeoutCtx, cancel
}

// Loads the newest version before nginx starts, so nginx serves 443 with it:
// one poll answered at once, bounded by StartTimeout, then the render and
// `nginx -t`. No reload, since nginx reads the files when it starts. On any
// failure the files stay as they were and nginx starts on them, claimed as no
// version; the error says why, and nginx must start whatever it says.
func (self *LbMap) LoadBeforeStart() error {
	ctx, cancel := self.withTimeout(self.ctx, self.settings.StartTimeout)
	defer cancel()
	answer, err := self.api.CustomHostMap(ctx, &LbMapPoll{Interface: self.config.Interface})
	if err != nil {
		self.log.Printf("[lbmap] %s: no map before nginx starts, so nginx starts on the map it holds and the interface is current for no version: %s", self.config.Interface, ScrubAddrs([]byte(err.Error())))
		return err
	}
	if answer == nil {
		// the API holds no version: nothing to load
		return nil
	}
	self.take(answer)
	var target *LbCustomHostMap
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		target = self.pending
	}()
	if target == nil {
		return nil
	}
	return self.load(target, false)
}

// Takes an answer: a version above every one lbmap holds waits for its load.
// Anything else is stale and changes nothing.
func (self *LbMap) take(answer *LbCustomHostMap) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if answer.Version <= self.heldVersionWithLock() {
		return
	}
	if self.pending == nil {
		self.firstUnappliedTime = self.clock.Now()
	}
	self.pending = answer
}

// The newest version lbmap holds, loaded or waiting.
func (self *LbMap) heldVersionWithLock() uint64 {
	version := uint64(0)
	if self.loaded != nil {
		version = self.loaded.version
	}
	if self.pending != nil && version < self.pending.Version {
		version = self.pending.Version
	}
	return version
}

// When the pending version loads: LoadDelay after the first unapplied
// version, or for a version whose load failed, a window after the failure; and
// in both cases no sooner than a window after the last reload. false with
// nothing pending.
func (self *LbMap) loadDueWithLock() (time.Time, bool) {
	if self.pending == nil {
		return time.Time{}, false
	}
	var due time.Time
	if self.failure != nil && self.failure.Version == self.pending.Version {
		due = self.failureTime.Add(self.settings.ReloadMinInterval)
	} else {
		due = self.firstUnappliedTime.Add(self.settings.LoadDelay)
	}
	if !self.lastReloadTime.IsZero() {
		if windowEnd := self.lastReloadTime.Add(self.settings.ReloadMinInterval); due.Before(windowEnd) {
			due = windowEnd
		}
	}
	return due, true
}

// Loads target into nginx: render, write both files, `nginx -t`, and with
// reload a SIGHUP confirmed by a new worker. Any failure puts the prior files
// back and records the failure, and the loaded version stays.
func (self *LbMap) load(target *LbCustomHostMap, reload bool) error {
	render, err := self.config.Render.Render(target, self.settings.MaxHostCount)
	if err != nil {
		return self.fail(target, LbMapStageRender, err)
	}
	priorMap, err := os.ReadFile(self.config.MapPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return self.fail(target, LbMapStageRender, err)
	}
	priorHttp80, err := os.ReadFile(self.config.Http80Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return self.fail(target, LbMapStageRender, err)
	}
	var heldHosts []string
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		heldHosts = slices.Clone(self.heldHosts)
	}()
	// what a failure's log may say: nginx's output names a host at times, and
	// a log carries no custom host's name (I-13)
	scrubHosts := func(text string) string {
		text = string(ScrubAddrs([]byte(text)))
		for _, host := range append(slices.Clone(render.Hosts), heldHosts...) {
			text = strings.ReplaceAll(text, host, "[custom host]")
		}
		return text
	}
	restore := func() error {
		return errors.Join(
			writeLbMapFile(self.config.MapPath, priorMap),
			writeLbMapFile(self.config.Http80Path, priorHttp80),
		)
	}
	if err := writeLbMapFile(self.config.MapPath, render.Map); err != nil {
		return self.fail(target, LbMapStageRender, errors.Join(err, restore()))
	}
	if err := writeLbMapFile(self.config.Http80Path, render.Http80); err != nil {
		return self.fail(target, LbMapStageRender, errors.Join(err, restore()))
	}
	testCtx, testCancel := self.withTimeout(self.ctx, self.settings.TestTimeout)
	err = self.nginx.Test(testCtx)
	testCancel()
	if err != nil {
		return self.fail(target, LbMapStageTest, errors.Join(errors.New(scrubHosts(err.Error())), restore()))
	}
	if reload {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.lastReloadTime = self.clock.Now()
		}()
		reloadCtx, reloadCancel := self.withTimeout(self.ctx, self.settings.ReloadTimeout)
		err = self.nginx.Reload(reloadCtx)
		reloadCancel()
		if err != nil {
			return self.fail(target, LbMapStageReload, errors.Join(errors.New(scrubHosts(err.Error())), restore()))
		}
	}
	added, dropped := lbMapHostChanges(heldHosts, render.Hosts)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.loaded = &lbMapLoaded{
			version: render.Version,
			digest:  render.Digest,
			added:   added,
			dropped: dropped,
			master:  self.master,
		}
		self.heldHosts = render.Hosts
		if self.pending != nil && self.pending.Version <= render.Version {
			self.pending = nil
			self.firstUnappliedTime = time.Time{}
		}
		if self.failure != nil && self.failure.Version <= render.Version {
			self.failure = nil
			self.failureTime = time.Time{}
		}
		self.updateReportWithLock()
	}()
	self.log.Printf("[lbmap] %s: nginx runs custom-host map version %d (digest %s): %d hosts, %d added, %d dropped", self.config.Interface, render.Version, render.Digest, len(render.Hosts), len(added), len(dropped))
	return nil
}

// Records a failed load of target at stage and reports it. Returns cause.
func (self *LbMap) fail(target *LbCustomHostMap, stage LbMapStage, cause error) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.failure = &LbMapFailure{Version: target.Version, Digest: target.Digest, Stage: stage}
		self.failureTime = self.clock.Now()
		self.updateReportWithLock()
	}()
	self.log.Printf("[lbmap] %s: custom-host map version %d (digest %s) failed at %s, so nginx keeps the map it holds: %s", self.config.Interface, target.Version, target.Digest, stage, cause)
	return fmt.Errorf("lbmap: version %d failed at %s: %w", target.Version, stage, cause)
}

// Rebuilds the report from the state: nil while there is nothing to report,
// that is no version claimed and no failure. A changed report is untaken.
func (self *LbMap) updateReportWithLock() {
	claimed := self.loaded != nil && self.loaded.master != nil
	var report *LbMapReport
	if claimed || self.failure != nil {
		report = &LbMapReport{Format: LbMapFormat, Interface: self.config.Interface}
		if self.master != nil {
			report.Master = &LbMapReportMaster{Pid: self.master.Pid, StartTimeMillis: self.master.StartTime.UnixMilli()}
		}
		if claimed {
			report.Version = self.loaded.version
			report.Digest = self.loaded.digest
			report.Added = slices.Clone(self.loaded.added)
			report.Dropped = slices.Clone(self.loaded.dropped)
		}
		if self.failure != nil && report.Version < self.failure.Version {
			failure := *self.failure
			report.Failure = &failure
		}
	}
	if report == nil && self.report == nil {
		return
	}
	if report != nil && self.report != nil && lbMapReportsEqual(report, self.report) {
		return
	}
	self.report = report
	self.reportTaken = report == nil
}

// Whether two reports say the same.
func lbMapReportsEqual(a *LbMapReport, b *LbMapReport) bool {
	aJson, aErr := json.Marshal(a)
	bJson, bErr := json.Marshal(b)
	return aErr == nil && bErr == nil && bytes.Equal(aJson, bJson)
}

// Sends the report when the API has not taken it, bounded by ReportTimeout.
// A failure leaves it untaken, for the next try before the next poll.
func (self *LbMap) sendReport() {
	var report *LbMapReport
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.report != nil && !self.reportTaken {
			report = cloneLbMapReport(self.report)
		}
	}()
	if report == nil {
		return
	}
	ctx, cancel := self.withTimeout(self.ctx, self.settings.ReportTimeout)
	err := self.api.Applied(ctx, report)
	cancel()
	if err != nil {
		self.log.Printf("[lbmap] %s: the report of version %d was not taken, and goes again before the next poll: %s", self.config.Interface, report.Version, ScrubAddrs([]byte(err.Error())))
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// a report that changed while this one was out stays untaken
	if self.report != nil && lbMapReportsEqual(self.report, report) {
		self.reportTaken = true
	}
}

// The next poll's request: the state as it stands.
func (self *LbMap) pollWithLock() *LbMapPoll {
	applied := self.heldVersionWithLock()
	poll := &LbMapPoll{
		Interface: self.config.Interface,
		Applied:   &applied,
	}
	if self.loaded != nil && self.loaded.master != nil {
		poll.Loaded = self.loaded.version
	}
	if self.master != nil {
		master := *self.master
		poll.Master = &master
	}
	return poll
}

// Starts one poll on its own goroutine, which sends its outcome once.
func (self *LbMap) startPoll() (<-chan *lbMapPollOutcome, context.CancelFunc) {
	var poll *LbMapPoll
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		poll = self.pollWithLock()
	}()
	ctx, cancel := self.withTimeout(self.ctx, self.settings.PollTimeout)
	canceledCtx, cancelByLoop := context.WithCancel(ctx)
	done := make(chan *lbMapPollOutcome, 1)
	go func() {
		defer cancel()
		answer, err := self.api.CustomHostMap(canceledCtx, poll)
		outcome := &lbMapPollOutcome{answer: answer, err: err}
		if err != nil && ctx.Err() == nil && canceledCtx.Err() != nil {
			outcome.canceled = true
		}
		done <- outcome
	}()
	return done, cancelByLoop
}

// Runs the loop until the lbmap's ctx ends: first the master, which claims a
// version LoadBeforeStart loaded, then polls and loads. nginx must have
// started.
func (self *LbMap) Run() {
	master, err := self.nginx.Master(self.ctx)
	if err != nil {
		self.log.Printf("[lbmap] %s: no nginx master, so lbmap stops: %s", self.config.Interface, err)
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.master = master
		if self.loaded != nil && self.loaded.master == nil {
			self.loaded.master = master
		}
		self.updateReportWithLock()
	}()

	var pollDone <-chan *lbMapPollOutcome
	var pollCancel context.CancelFunc
	defer func() {
		if pollCancel != nil {
			pollCancel()
		}
	}()
	nextPollTime := self.clock.Now()
	pollStartTime := time.Time{}
	backoff := time.Duration(0)
	for {
		if self.ctx.Err() != nil {
			return
		}
		now := self.clock.Now()

		var due time.Time
		var hasDue bool
		var target *LbCustomHostMap
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			due, hasDue = self.loadDueWithLock()
			target = self.pending
		}()
		if hasDue && !now.Before(due) {
			self.load(target, true)
			// the poll in flight repeats the old report: end it, and poll again
			// once it has ended
			if pollCancel != nil {
				pollCancel()
			}
			self.sendReport()
			continue
		}

		if pollDone == nil && !now.Before(nextPollTime) {
			// a report the API has not taken goes before the poll that repeats
			// it
			self.sendReport()
			now = self.clock.Now()
			pollStartTime = now
			pollDone, pollCancel = self.startPoll()
		}

		var loadTimer <-chan time.Time
		if hasDue {
			loadTimer = self.clock.After(due.Sub(now))
		}
		var pollTimer <-chan time.Time
		if pollDone == nil {
			pollTimer = self.clock.After(nextPollTime.Sub(now))
		}

		select {
		case <-self.ctx.Done():
			return
		case outcome := <-pollDone:
			pollDone = nil
			pollCancel = nil
			if self.ctx.Err() != nil {
				return
			}
			now := self.clock.Now()
			switch {
			case outcome.canceled:
				nextPollTime = now
			case outcome.err != nil:
				if backoff == 0 {
					backoff = self.settings.ErrorBackoffMin
				} else {
					backoff = min(2*backoff, self.settings.ErrorBackoffMax)
				}
				nextPollTime = now.Add(backoff)
				if errors.Is(outcome.err, ErrLbMapFormatTooNew) {
					self.log.Printf("[lbmap] %s: the api serves a map format this lb does not read, so nothing loads until it does: %s", self.config.Interface, outcome.err)
				} else {
					self.log.Printf("[lbmap] %s: poll failed, again in %v: %s", self.config.Interface, backoff, ScrubAddrs([]byte(outcome.err.Error())))
				}
			default:
				backoff = 0
				nextPollTime = pollStartTime.Add(self.settings.PollMinInterval)
				if outcome.answer != nil {
					self.take(outcome.answer)
				}
			}
		case <-loadTimer:
		case <-pollTimer:
		}
	}
}
