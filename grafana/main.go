package main

// The Warp Grafana service bundles Grafana, Loki, and Mimir behind a Go HTTP
// front. Host-managed Fluent Bit ships container journals into the push route.
// on the warp allocated port for service port 80 (WARP_PORTS):
//   /status         -> warp status (no auth)
//   /loki/api/v1/push -> loki, basic auth for service users with the push role
//   /loki/...       -> loki, basic auth for service users with the query role
//   /metrics/job/... -> stats push receiver (see push.go), push role
//   /api/v1/push    -> mimir remote write, push role
//   /prometheus/... -> mimir query api, query role
//   /stats          -> public dashboards directory (html, no auth)
//   /stats.json     -> public stats feed (json, no auth): the network
//                      operator stats contract fields derived from mimir
//                      (see stats.go) plus the public dashboards directory
//   /               -> grafana ui (grafana handles its own auth)
// on :<local_port from grafana.yml> (SO_REUSEPORT, stable across redeploys),
// bound to loopback, the host's LAN route, and any explicitly configured
// publish route such as its management VPN address — the publish port for
// services on the host (and fluent-bit on non-grafana hosts):
//   /loki/api/v1/push -> loki, push role
//   /metrics/job/... -> stats push receiver (see push.go), push role
//   /api/v1/push    -> mimir remote write, push role
// and, on the loopback binding of that port only, the read routes the
// co-located grafana provisions as its datasources — the loki/mimir child
// ports rotate per deploy and per host, and grafana's datasource rows are
// shared fleet-wide through the env postgres, so the datasources must name
// this stable port instead (see renderGrafanaConfig):
//   /loki/...       -> loki query api (no auth, loopback only)
//   /prometheus/... -> mimir query api (no auth, loopback only)
// grafana, loki, and mimir listen on the warp allocated internal ports for
// the service ports declared in services.yml (WARP_PORTS)
//
// grafana state lives in the env postgres (see vault grafana.yml).
// loki instances on the service hosts form a ring over the host lan
// (settings.yml routes) and store chunks in minio (s3).
//
// The parent and all children run as the image's fixed unprivileged identity.
// Ordinary settings come from config; only grafana.yml is mounted from vault.

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp"
)

// alert rules for grafana unified alerting, written to the
// provisioning/alerting dir at start (see renderGrafanaConfig).
// the rules query the provisioned warp-mimir datasource.
// contact points and notification policies are not provisioned:
// they are managed in the grafana ui and live in the grafana database
//
//go:embed alerting/*.yml
var alertingFs embed.FS

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

const runDir = "/run/warp-grafana"
const grafanaSecretsPath = "/srv/warp/secrets/grafana.yml"

// service ports declared in services.yml.
// warp allocates a unique internal port per deploy for each,
// exposed via WARP_PORTS. grafana, loki, and mimir listen on the
// allocated internal ports (see `servicePortToHostPort`)
const grafanaServicePort = 3000
const lokiServicePort = 3101
const mimirServicePort = 3201

// the default stable local publish address (local_port in grafana.yml).
// the go front owns this listener with SO_REUSEPORT, so that the old and new
// containers both serve it during a redeployment overlap (loki and mimir
// expose no reuseport option). alloy pushes logs here, and services on the
// host publish logs and stats to grafana here
const defaultLocalPort = 3100

// loki/mimir ring ports the front binds on the route net. They MUST stay below
// the ephemeral range (net.ipv4.ip_local_port_range = "20000 60999", see xops
// main/ansible/playbook-edges.yml) and outside warp's 7000-20000 allocation;
// otherwise the co-located connect service grabs them as ephemeral SOURCE ports
// and the front's LISTEN bind loses the race ("address already in use"). 6490-
// 6493 is the free gap between redis (6379) and warp (7000): grpc=6490/6491,
// gossip=6492/6493.
const defaultGrpcPort = 6490
const defaultMimirGrpcPort = 6491
const defaultGossipPort = 6492
const defaultMimirGossipPort = 6493
const defaultMinioPort = 23900
const defaultReplicationFactor = 3
const defaultRetention = "744h"
const defaultMimirRetention = "2160h"
const lokiDatasourceUid = "warp-loki"
const logsDrilldownPluginID = "grafana-lokiexplore-app"
const logsDrilldownExplorePath = "/a/grafana-lokiexplore-app/explore"
const maxLokiPushBodyBytes = 16 * 1024 * 1024
const maxMimirPushBodyBytes = 32 * 1024 * 1024
const maxStatsPushBodyBytes = 4 * 1024 * 1024
const maxRingTcpSessions = 256
const maxRingUdpSessions = 256
const maxRingUdpDatagramsPerSecond = 1024
const ringTcpKeepAlivePeriod = 30 * time.Second
const ringTcpWriteTimeout = 60 * time.Second
const ringUdpIdleTimeout = 60 * time.Second
const childListenAddress = "127.0.0.1"

// Child readiness, used for two different jobs off the same probes.
//
// The deploy poll (warpctl pollContainerStatus, 120s budget) reads /status to
// decide this container may take over from the old one. A front that answers
// ok the moment it binds installs a container whose loki or mimir never
// finished starting, and the deploy reads as a success: front=200 graf=200
// up=1 restarts=0 while every log query 503s (SIGNALS.md 11.2, and 11.13 for
// the variant where the child process is up but some of its modules are not).
// So /status stays an error until each child has answered its own readiness
// endpoint at least once.
//
// The supervisor (warp.Child HealthCheck) reuses the same probes to restart a
// child that is running but wedged. Exit is otherwise the only signal, and a
// wedged loki never exits.
const childReadyTimeout = 5 * time.Second
const readinessCheckInterval = 2 * time.Second
const childHealthCheckInterval = 30 * time.Second

// A child that has been failing its readiness endpoint this long is restarted.
// Well under the 16h a wedged loki survived on 2026-08-17, and well over both
// a cold start and the unready window a rolling fleet deploy opens: loki and
// mimir gate /ready on their rings, which go unhealthy while peers cycle.
const childUnhealthyTimeout = 10 * time.Minute

// External ports are advertised to peers and owned by the Go front with
// reuse-port so old and new containers coexist during a redeploy. Internal
// ports are unique child listeners; the front proxies each external port to
// its loopback child because Loki and Mimir cannot set reuse-port themselves.
type ringProxyPorts struct {
	grpcExternal   int
	grpcInternal   int
	gossipExternal int
	gossipInternal int
}

// Fixed-capacity tokens are safe for concurrent stream accept/release calls.
type ringSessionLimiter struct {
	tokens chan struct{}
}

// Creates a nonblocking fixed-capacity limiter.
func newRingSessionLimiter(capacity int) *ringSessionLimiter {
	return &ringSessionLimiter{tokens: make(chan struct{}, capacity)}
}

// Reserves a session without stalling the accept loop.
func (self *ringSessionLimiter) tryAcquire() bool {
	select {
	case self.tokens <- struct{}{}:
		return true
	default:
		return false
	}
}

// Returns one previously acquired session.
func (self *ringSessionLimiter) release() {
	<-self.tokens
}

// Fixed one-second source-address window for datagram admission.
type ringDatagramRate struct {
	windowStart time.Time
	datagrams   int
}

// Admits at most the configured count per one-second window.
func (self *ringDatagramRate) allow(now time.Time, limit int) bool {
	if self.windowStart.IsZero() || time.Second <= now.Sub(self.windowStart) {
		self.windowStart = now
		self.datagrams = 0
	}
	if limit <= self.datagrams {
		return false
	}
	self.datagrams += 1
	return true
}

// Enforces the aggregate datagram source-session cap.
func ringUdpSessionAvailable(sessionCount int) bool {
	return sessionCount < maxRingUdpSessions
}

// Per-host settings from config/<env>/settings.yml.
type HostSettings struct {
	EnvVars map[string]string `yaml:"env_vars,omitempty"`
	Routes  map[string]string `yaml:"routes,omitempty"`
}

// Ordinary fields come from config/<env>/grafana.yml; credential fields are
// overlaid from the scoped /srv/warp/secrets/grafana.yml mount.
type GrafanaConfig struct {
	// the stable local publish port on every host
	LocalPort int `yaml:"local_port,omitempty"`
	// PublishRoutes maps a host to an additional exact address that may accept
	// authenticated ingestion. Production uses the management VPN address so
	// offsite Planetoid never sends backup telemetry through the public front.
	PublishRoutes map[string]string `yaml:"publish_routes,omitempty"`
	Grafana       *GrafanaUiConfig  `yaml:"grafana,omitempty"`
	Postgres      *PostgresConfig   `yaml:"postgres,omitempty"`
	Redis         *RedisConfig      `yaml:"redis,omitempty"`
	Minio         *MinioConfig      `yaml:"minio,omitempty"`
	Loki          *LokiConfig       `yaml:"loki,omitempty"`
	Mimir         *MimirConfig      `yaml:"mimir,omitempty"`
	Users         []*ServiceUser    `yaml:"users,omitempty"`
}

// Administrator credential for the dashboard child.
type GrafanaUiConfig struct {
	AdminPassword string `yaml:"admin_password,omitempty"`
}

// Database topology with its password overlaid from scoped secrets.
type PostgresConfig struct {
	Hostname string `yaml:"hostname,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	Database string `yaml:"database,omitempty"`
}

// Cache topology with its optional password overlaid from scoped secrets.
type RedisConfig struct {
	Hostname string `yaml:"hostname,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	// the redis database for grafana, apart from the other redis users
	Database int    `yaml:"database,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// Object-storage topology with credentials overlaid from scoped secrets.
type MinioConfig struct {
	Hostname  string `yaml:"hostname,omitempty"`
	Port      int    `yaml:"port,omitempty"`
	AccessKey string `yaml:"access_key,omitempty"`
	SecretKey string `yaml:"secret_key,omitempty"`
	Bucket    string `yaml:"bucket,omitempty"`
}

// Log storage replication, retention, and quota settings.
type LokiConfig struct {
	ReplicationFactor int    `yaml:"replication_factor,omitempty"`
	Retention         string `yaml:"retention,omitempty"`
	// a hard quota on the minio bucket,
	// applied by the minio playbook (not by this service).
	// retention is the primary control and should keep usage
	// well below the quota
	MaxStorage string `yaml:"max_storage,omitempty"`
}

// Metrics storage replication, retention, and quota settings.
type MimirConfig struct {
	ReplicationFactor int    `yaml:"replication_factor,omitempty"`
	Retention         string `yaml:"retention,omitempty"`
	// see LokiConfig.MaxStorage
	MaxStorage string `yaml:"max_storage,omitempty"`
	Bucket     string `yaml:"bucket,omitempty"`
}

// One role-scoped HTTP Basic Auth identity.
type ServiceUser struct {
	Name     string   `yaml:"name,omitempty"`
	Password string   `yaml:"password,omitempty"`
	Roles    []string `yaml:"roles,omitempty"`
}

// Requires a nonempty process environment setting.
func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(errors.New(fmt.Sprintf("%s must be set.", name)))
	}
	return value
}

// Resolves the Warp-allocated internal port for a declared service port, with
// the service port itself as the non-host-networking fallback.
func servicePortToHostPort(servicePort int) int {
	if hostPort, err := warp.ServiceHostPort(servicePort); err == nil {
		return hostPort
	}
	return servicePort
}

// requireServiceHostPort returns the unique internal port warp allocated for a
// declared service port. Unlike servicePortToHostPort it does NOT fall back to
// the service port itself: a ring port missing from WARP_PORTS means it was not
// declared in services.yml {tcp,udp}_stream_ports, which would otherwise
// silently bind the wrong port, so fail loudly at startup instead.
func requireServiceHostPort(servicePort int) int {
	hostPort, err := warp.ServiceHostPort(servicePort)
	if err != nil {
		panic(fmt.Errorf("ring port %d must be declared in services.yml {tcp,udp}_stream_ports: %w", servicePort, err))
	}
	return hostPort
}

func loadYaml(path string, out any) {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		panic(err)
	}
}

func writeFile(path string, data string, mode os.FileMode) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		panic(err)
	}
}

// Overlays only credentials from the scoped secret file and joins service users
// by name so the secret document cannot add or change an authorization role.
func mergeGrafanaConfig(config GrafanaConfig, secrets GrafanaConfig) (GrafanaConfig, error) {
	if config.Grafana != nil && config.Grafana.AdminPassword != "" {
		return GrafanaConfig{}, errors.New("ordinary Grafana config contains the admin password")
	}
	if config.Postgres != nil && config.Postgres.Password != "" {
		return GrafanaConfig{}, errors.New("ordinary Grafana config contains the PostgreSQL password")
	}
	if config.Redis != nil && config.Redis.Password != "" {
		return GrafanaConfig{}, errors.New("ordinary Grafana config contains the Redis password")
	}
	if config.Minio != nil && (config.Minio.AccessKey != "" || config.Minio.SecretKey != "") {
		return GrafanaConfig{}, errors.New("ordinary Grafana config contains object-storage credentials")
	}
	if secrets.Grafana != nil {
		if config.Grafana == nil {
			config.Grafana = &GrafanaUiConfig{}
		}
		config.Grafana.AdminPassword = secrets.Grafana.AdminPassword
	}
	if secrets.Postgres != nil {
		if config.Postgres == nil {
			config.Postgres = &PostgresConfig{}
		}
		config.Postgres.Password = secrets.Postgres.Password
	}
	if secrets.Redis != nil {
		if config.Redis == nil {
			config.Redis = &RedisConfig{}
		}
		config.Redis.Password = secrets.Redis.Password
	}
	if secrets.Minio != nil {
		if config.Minio == nil {
			config.Minio = &MinioConfig{}
		}
		config.Minio.AccessKey = secrets.Minio.AccessKey
		config.Minio.SecretKey = secrets.Minio.SecretKey
	}

	configUsers := map[string]*ServiceUser{}
	for _, configUser := range config.Users {
		if configUser == nil || configUser.Name == "" {
			return GrafanaConfig{}, errors.New("ordinary Grafana config has an unnamed service user")
		}
		if configUser.Password != "" {
			return GrafanaConfig{}, fmt.Errorf("ordinary Grafana config contains password for %q", configUser.Name)
		}
		if configUsers[configUser.Name] != nil {
			return GrafanaConfig{}, fmt.Errorf("ordinary Grafana config repeats service user %q", configUser.Name)
		}
		configUsers[configUser.Name] = configUser
	}
	secretUsers := map[string]bool{}
	for _, secretUser := range secrets.Users {
		if secretUser == nil || secretUser.Name == "" {
			return GrafanaConfig{}, errors.New("Grafana secret has an unnamed service user")
		}
		if 0 < len(secretUser.Roles) {
			return GrafanaConfig{}, fmt.Errorf("Grafana secret contains roles for %q", secretUser.Name)
		}
		if secretUsers[secretUser.Name] {
			return GrafanaConfig{}, fmt.Errorf("Grafana secret repeats service user %q", secretUser.Name)
		}
		secretUsers[secretUser.Name] = true
		configUser := configUsers[secretUser.Name]
		if configUser == nil {
			return GrafanaConfig{}, fmt.Errorf("Grafana secret user %q is absent from ordinary config", secretUser.Name)
		}
		configUser.Password = secretUser.Password
	}
	for _, configUser := range config.Users {
		if 0 < len(configUser.Roles) && configUser.Password == "" {
			return GrafanaConfig{}, fmt.Errorf("Grafana service user %q has roles but no password", configUser.Name)
		}
	}
	slices.SortFunc(config.Users, func(a *ServiceUser, b *ServiceUser) int {
		return strings.Compare(a.Name, b.Name)
	})
	return config, nil
}

// requireRingHosts reads the placement computed by warpctl. Keeping services.yml
// out of this container prevents topology metadata from expanding vault access.
func requireRingHosts() []string {
	ringHostsValue := requireEnv("WARP_RING_HOSTS")
	ringHosts := []string{}
	for _, ringHost := range strings.Split(ringHostsValue, ",") {
		ringHost = strings.TrimSpace(ringHost)
		if ringHost != "" {
			ringHosts = append(ringHosts, ringHost)
		}
	}
	if len(ringHosts) == 0 {
		panic(errors.New("WARP_RING_HOSTS must contain at least one host"))
	}
	slices.Sort(ringHosts)
	return ringHosts
}

// main renders the three child configurations and owns their authenticated
// front, exact-address local publisher, and bounded route-network ring proxies.
func main() {
	env := requireEnv("WARP_ENV")
	domain := requireEnv("WARP_DOMAIN")
	host := requireEnv("WARP_HOST")
	configHome := requireEnv("WARP_CONFIG")

	allHostSettings := map[string]*HostSettings{}
	loadYaml(filepath.Join(configHome, "settings.yml"), &allHostSettings)
	hostSettings, ok := allHostSettings[host]
	if !ok || hostSettings == nil {
		panic(errors.New(fmt.Sprintf("Host %s not present in settings.yml", host)))
	}

	lanIp, ok := hostSettings.Routes[host]
	if !ok {
		panic(errors.New(fmt.Sprintf("Host %s not present in settings.yml routes", host)))
	}

	var ordinaryGrafanaConfig GrafanaConfig
	loadYaml(filepath.Join(configHome, "grafana.yml"), &ordinaryGrafanaConfig)
	var secretGrafanaConfig GrafanaConfig
	loadYaml(grafanaSecretsPath, &secretGrafanaConfig)
	grafanaConfig, err := mergeGrafanaConfig(ordinaryGrafanaConfig, secretGrafanaConfig)
	if err != nil {
		panic(err)
	}

	lokiHttpPort := servicePortToHostPort(lokiServicePort)
	grafanaHttpPort := servicePortToHostPort(grafanaServicePort)
	mimirHttpPort := servicePortToHostPort(mimirServicePort)

	localPort := defaultLocalPort
	if grafanaConfig.LocalPort != 0 {
		localPort = grafanaConfig.LocalPort
	}
	publishIps, err := configuredPublishIps(host, lanIp, grafanaConfig.PublishRoutes)
	if err != nil {
		panic(err)
	}

	ringHosts := requireRingHosts()
	warp.Err.Printf("Ring hosts for grafana: %v\n", ringHosts)

	lokiConfigPath, lokiRing := renderLokiConfig(host, lanIp, lokiHttpPort, hostSettings, ringHosts, &grafanaConfig)
	mimirConfigPath, mimirRing := renderMimirConfig(host, lanIp, mimirHttpPort, hostSettings, ringHosts, &grafanaConfig)
	grafanaIniPath := renderGrafanaConfig(env, domain, grafanaHttpPort, localPort, hostSettings, &grafanaConfig)

	event := warp.NewEvent()
	eventClose := event.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer eventClose()

	childWaitGroup := &sync.WaitGroup{}

	// loki and mimir are supervised on readiness as well as on exit: both
	// start their modules asynchronously, so either can end up alive and
	// permanently useless with nothing to restart it (SIGNALS.md 11.13).
	// Grafana is deliberately left on exit-only supervision -- its health
	// tracks the shared postgres, and restarting it does not fix what it is
	// reporting
	readyChecks := childReadyChecks(
		lokiHttpPort,
		mimirHttpPort,
		grafanaHttpPort,
		grafanaConfig.Grafana.AdminPassword,
	)

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		lokiSettings := warp.DefaultChildSettings()
		// flush chunks to minio on stop
		lokiSettings.StopTimeout = 120 * time.Second
		lokiSettings.HealthCheck = childHealthCheck(requireChildReadyCheck(readyChecks, "loki"))
		lokiSettings.HealthCheckInterval = childHealthCheckInterval
		lokiSettings.UnhealthyTimeout = childUnhealthyTimeout
		warp.Child(event, "loki", lokiSettings, "/usr/local/sbin/loki", fmt.Sprintf("-config.file=%s", lokiConfigPath))
	}()

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		mimirSettings := warp.DefaultChildSettings()
		// flush blocks to minio on stop
		mimirSettings.StopTimeout = 120 * time.Second
		mimirSettings.HealthCheck = childHealthCheck(requireChildReadyCheck(readyChecks, "mimir"))
		mimirSettings.HealthCheckInterval = childHealthCheckInterval
		mimirSettings.UnhealthyTimeout = childUnhealthyTimeout
		warp.Child(event, "mimir", mimirSettings, "/usr/local/sbin/mimir", fmt.Sprintf("-config.file=%s", mimirConfigPath))
	}()

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		warp.Child(
			event,
			"grafana",
			warp.DefaultChildSettings(),
			"/usr/share/grafana/bin/grafana",
			"server",
			fmt.Sprintf("--config=%s", grafanaIniPath),
			"--homepath=/usr/share/grafana",
		)
	}()

	err = serve(event, env, lanIp, publishIps, ringHosts, hostSettings, &grafanaConfig, readyChecks, lokiHttpPort, grafanaHttpPort, mimirHttpPort, localPort, lokiRing, mimirRing)

	// stop the children and wait for the loki flush
	event.Set()
	childWaitGroup.Wait()

	if err != nil {
		panic(err)
	}
}

// envInterpolateRe matches the vault `{{ env:KEY }}` value convention
// (server env.go translateString): grafana.yml values may thread env vars,
// e.g. `minio.hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME }}"` threaded from
// config settings.yml env_vars.
var envInterpolateRe = regexp.MustCompile(`{{\s*env:([^}\s]+)\s*}}`)

// interpolateEnv expands `{{ env:KEY }}` in a config value, resolving each key
// from the host's settings.yml env_vars first and the process environment
// second. settings.yml is the only source that carries the BRINGYOUR_* values
// into this container: warpctl emits `--envvar=` for services.yml env_vars
// only, so the per-host settings env_vars never reach the process
// environment. (The server binary reads the same values off the process
// environment because server env.go loads settings env_vars with os.Setenv at
// init; this front has no equivalent step, so it must read them directly --
// the postgres and redis hostnames in renderGrafanaConfig already do.) A
// referenced but unset key panics: writing a loki/mimir config with a literal
// template as its s3 endpoint would fail far less legibly at runtime.
func interpolateEnv(value string, envVars map[string]string) string {
	return envInterpolateRe.ReplaceAllStringFunc(value, func(match string) string {
		key := envInterpolateRe.FindStringSubmatch(match)[1]
		envValue := envVars[key]
		if envValue == "" {
			envValue = os.Getenv(key)
		}
		if envValue == "" {
			panic(fmt.Errorf("missing env var %s for grafana.yml value %q", key, value))
		}
		return envValue
	})
}

func resolveMinioEndpoint(hostSettings *HostSettings, grafanaConfig *GrafanaConfig) (string, int) {
	minio := grafanaConfig.Minio
	if minio == nil {
		panic(errors.New("grafana.yml must have a minio section."))
	}
	// expand `{{ env:... }}` then route the minio hostname over the host
	// lan. A raw ip value (the current settings convention) is not a routes
	// key and passes through unchanged.
	minioHostname := interpolateEnv(minio.Hostname, hostSettings.EnvVars)
	minioIp := minioHostname
	if routeIp, ok := hostSettings.Routes[minioHostname]; ok {
		minioIp = routeIp
	}
	// the callers format the endpoint as host:port; a bare ipv6 literal
	// must be bracketed to survive that
	if strings.Contains(minioIp, ":") && !strings.HasPrefix(minioIp, "[") {
		minioIp = "[" + minioIp + "]"
	}
	minioPort := minio.Port
	if minioPort == 0 {
		minioPort = defaultMinioPort
	}
	return minioIp, minioPort
}

// ringJoinMembers seeds the Loki/Mimir memberlist with only the hosts in the
// placement supplied by warpctl, resolved to their route-network addresses.
// Seeding every routed host instead pulls in pg/minio/subtensor/offline hosts,
// which run no gossip listener: memberlist tolerates the dead seeds but retries
// them every rejoin_interval, producing a steady "Push/Pull with <ip> failed:
// connection refused" drip. A host with no route entry is skipped.
func ringJoinMembers(hostSettings *HostSettings, ringHosts []string, gossipPort int) []string {
	joinMembers := []string{}
	for _, host := range ringHosts {
		peerIp, ok := hostSettings.Routes[host]
		if !ok {
			// services.yml names hosts by fqdn; settings.yml routes use the
			// short host name
			shortHost, _, _ := strings.Cut(host, ".")
			peerIp, ok = hostSettings.Routes[shortHost]
		}
		if ok {
			joinMembers = append(joinMembers, fmt.Sprintf("%s:%d", peerIp, gossipPort))
		}
	}
	if len(joinMembers) == 0 {
		// an empty seed list silently strands a solo-restarted host outside the
		// gossip mesh (it can only be bridged in by a deploy overlap). memberlist
		// tolerates dead seeds, so degrade to every routed host instead.
		warp.Err.Printf("Ring join members resolved empty; falling back to all routed hosts\n")
		for _, peerIp := range hostSettings.Routes {
			joinMembers = append(joinMembers, fmt.Sprintf("%s:%d", peerIp, gossipPort))
		}
	}
	slices.Sort(joinMembers)
	return joinMembers
}

// ringAllowedIps converts the configured placement into a strict peer source
// allowlist. Missing and malformed routes fail closed rather than widening it.
func ringAllowedIps(hostSettings *HostSettings, ringHosts []string) (map[netip.Addr]bool, error) {
	allowedIps := map[netip.Addr]bool{}
	for _, ringHost := range ringHosts {
		ringIp, ok := hostSettings.Routes[ringHost]
		if !ok {
			shortHost, _, _ := strings.Cut(ringHost, ".")
			ringIp, ok = hostSettings.Routes[shortHost]
		}
		if !ok {
			return nil, fmt.Errorf("ring host %q has no route", ringHost)
		}
		parsedIp, err := netip.ParseAddr(ringIp)
		if err != nil {
			return nil, fmt.Errorf("ring host %q route %q: %w", ringHost, ringIp, err)
		}
		allowedIps[parsedIp.Unmap()] = true
	}
	return allowedIps, nil
}

// startRingReusePortProxy binds only the exact route address and forwards only
// allowlisted ring peers to the unique child port on loopback.
func startRingReusePortProxy(event *warp.Event, lanIp string, allowedIps map[netip.Addr]bool, externalPort int, internalPort int, gossip bool) {
	listenAddr := net.JoinHostPort(lanIp, fmt.Sprintf("%d", externalPort))
	backendAddr := fmt.Sprintf("127.0.0.1:%d", internalPort)
	go serveRingTcpProxy(event, listenAddr, backendAddr, allowedIps)
	if gossip {
		go serveRingUdpProxy(event, listenAddr, backendAddr, allowedIps)
	}
}

// ringRemoteAllowed checks the parsed source address without trusting a
// hostname or a proxy-supplied identity.
func ringRemoteAllowed(remoteAddr net.Addr, allowedIps map[netip.Addr]bool) bool {
	remoteHost, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return false
	}
	remoteIp, err := netip.ParseAddr(remoteHost)
	if err != nil {
		return false
	}
	return allowedIps[remoteIp.Unmap()]
}

// serveRingTcpProxy retries reuseport binds during deployment overlap and caps
// concurrent sessions before dialing any child backend.
func serveRingTcpProxy(event *warp.Event, listenAddr string, backendAddr string, allowedIps map[netip.Addr]bool) {
	sessionLimiter := newRingSessionLimiter(maxRingTcpSessions)
	for !event.IsSet() {
		listener, err := warp.ListenReusePort(listenAddr)
		if err != nil {
			warp.Err.Printf("Ring tcp reuseport %s bind pending (%s); retrying\n", listenAddr, err)
			event.WaitForSet(2 * time.Second)
			continue
		}
		warp.Err.Printf("Ring tcp reuseport %s -> %s\n", listenAddr, backendAddr)
		go func() {
			<-event.Ctx.Done()
			listener.Close()
		}()
		for {
			client, err := listener.Accept()
			if err != nil {
				break
			}
			if !ringRemoteAllowed(client.RemoteAddr(), allowedIps) {
				client.Close()
				continue
			}
			if sessionLimiter.tryAcquire() {
				go func() {
					defer sessionLimiter.release()
					proxyRingTcp(client, backendAddr)
				}()
			} else {
				client.Close()
			}
		}
		listener.Close()
		event.WaitForSet(1 * time.Second)
	}
}

// serveRingUdpProxy retries deployment-overlap binds without busy-spinning.
func serveRingUdpProxy(event *warp.Event, listenAddr string, backendAddr string, allowedIps map[netip.Addr]bool) {
	for !event.IsSet() {
		if err := proxyRingUdp(event, listenAddr, backendAddr, allowedIps); err != nil {
			warp.Err.Printf("Ring udp reuseport %s bind pending (%s); retrying\n", listenAddr, err)
			event.WaitForSet(2 * time.Second)
		}
	}
}

// copyRingTcp deliberately has no read deadline. Loki and Mimir use long-lived
// HTTP/2/gRPC streams that may carry no application bytes for minutes; treating
// that valid idle period as a dead session closes every backend tail stream on
// a 60-second grid and creates observation gaps. TCP keepalive on both sockets
// detects dead peers. Keep only a bounded write deadline so a destination that
// stops consuming cannot retain a proxy slot forever.
func copyRingTcp(destination net.Conn, source net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		readSize, err := source.Read(buffer)
		if readSize != 0 {
			destination.SetWriteDeadline(time.Now().Add(ringTcpWriteTimeout))
			if _, writeErr := destination.Write(buffer[:readSize]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

type ringTcpKeepAliveConn interface {
	SetKeepAlive(bool) error
	SetKeepAlivePeriod(time.Duration) error
}

func enableRingTcpKeepAlive(connection net.Conn) {
	if tcpConnection, ok := connection.(ringTcpKeepAliveConn); ok {
		_ = tcpConnection.SetKeepAlive(true)
		_ = tcpConnection.SetKeepAlivePeriod(ringTcpKeepAlivePeriod)
	}
}

// proxyRingTcp owns both endpoints until either bounded copy direction ends.
func proxyRingTcp(client net.Conn, backendAddr string) {
	enableRingTcpKeepAlive(client)
	defer client.Close()
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return
	}
	enableRingTcpKeepAlive(backend)
	defer backend.Close()
	done := make(chan struct{}, 2)
	go func() { copyRingTcp(backend, client); done <- struct{}{} }()
	go func() { copyRingTcp(client, backend); done <- struct{}{} }()
	<-done
}

// proxyRingUdp relays memberlist gossip datagrams between the route-net
// reuseport socket and loopback. It applies source, session, rate, and idle
// bounds before allocating or retaining per-client backend sockets.
func proxyRingUdp(event *warp.Event, listenAddr string, backendAddr string, allowedIps map[netip.Addr]bool) error {
	packetConn, err := warp.ListenReusePortPacket(listenAddr)
	if err != nil {
		return err
	}
	warp.Err.Printf("Ring udp reuseport %s -> %s\n", listenAddr, backendAddr)
	go func() {
		<-event.Ctx.Done()
		packetConn.Close()
	}()
	backendUdpAddr, err := net.ResolveUDPAddr("udp", backendAddr)
	if err != nil {
		packetConn.Close()
		return err
	}

	type udpSession struct {
		backend *net.UDPConn
	}
	sessions := map[string]*udpSession{}
	rates := map[netip.Addr]*ringDatagramRate{}
	var stateLock sync.Mutex

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := packetConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		if !ringRemoteAllowed(clientAddr, allowedIps) {
			continue
		}
		remoteHost, _, err := net.SplitHostPort(clientAddr.String())
		if err != nil {
			continue
		}
		clientIp, err := netip.ParseAddr(remoteHost)
		if err != nil {
			continue
		}
		clientIp = clientIp.Unmap()
		key := clientAddr.String()
		var session *udpSession
		allowed := func() bool {
			stateLock.Lock()
			defer stateLock.Unlock()
			now := time.Now()
			rate := rates[clientIp]
			if rate == nil {
				rate = &ringDatagramRate{}
				rates[clientIp] = rate
			}
			if !rate.allow(now, maxRingUdpDatagramsPerSecond) {
				return false
			}
			session = sessions[key]
			if session == nil && !ringUdpSessionAvailable(len(sessions)) {
				return false
			}
			return true
		}()
		if !allowed {
			continue
		}
		if session == nil {
			backend, dialErr := net.DialUDP("udp", nil, backendUdpAddr)
			if dialErr != nil {
				continue
			}
			newSession := &udpSession{backend: backend}
			inserted := func() bool {
				stateLock.Lock()
				defer stateLock.Unlock()
				if sessions[key] != nil || !ringUdpSessionAvailable(len(sessions)) {
					return false
				}
				sessions[key] = newSession
				return true
			}()
			if !inserted {
				backend.Close()
				continue
			}
			session = newSession
			go func() {
				replyBuf := make([]byte, 64*1024)
				for {
					session.backend.SetReadDeadline(time.Now().Add(ringUdpIdleTimeout))
					replyN, readErr := session.backend.Read(replyBuf)
					if readErr != nil {
						func() {
							stateLock.Lock()
							defer stateLock.Unlock()
							if sessions[key] == session {
								delete(sessions, key)
							}
						}()
						session.backend.Close()
						return
					}
					packetConn.WriteTo(replyBuf[:replyN], clientAddr)
				}
			}()
		}
		session.backend.SetWriteDeadline(time.Now().Add(ringUdpIdleTimeout))
		session.backend.Write(buf[:n])
	}
}

func renderLokiConfig(host string, lanIp string, lokiHttpPort int, hostSettings *HostSettings, ringHosts []string, grafanaConfig *GrafanaConfig) (string, ringProxyPorts) {
	lokiSettings := grafanaConfig.Loki
	if lokiSettings == nil {
		lokiSettings = &LokiConfig{}
	}
	// The ring ports are the four named constants (the role->port map); they are
	// NOT configurable via grafana.yml. services.yml declares them so warp
	// allocates a unique-per-deploy internal port, and requireServiceHostPort
	// fails hard if a ring port is missing from WARP_PORTS -- no silent default.
	// The front binds the external port on the route net with SO_REUSEPORT; loki
	// listens on the internal port and advertises the external port to the ring.
	grpcPort := defaultGrpcPort
	gossipPort := defaultGossipPort
	grpcListenPort := requireServiceHostPort(grpcPort)
	gossipBindPort := requireServiceHostPort(gossipPort)
	replicationFactor := lokiSettings.ReplicationFactor
	if replicationFactor == 0 {
		replicationFactor = defaultReplicationFactor
	}
	retention := configuredLokiRetention(grafanaConfig)

	minio := grafanaConfig.Minio
	minioIp, minioPort := resolveMinioEndpoint(hostSettings, grafanaConfig)
	minioBucket := minio.Bucket
	if minioBucket == "" {
		minioBucket = "loki"
	}

	joinMembers := ringJoinMembers(hostSettings, ringHosts, gossipPort)

	lokiConfig := map[string]any{
		"auth_enabled": false,
		"server": map[string]any{
			// Only the authenticated Go front reaches child HTTP listeners.
			"http_listen_address": childListenAddress,
			"http_listen_port":    lokiHttpPort,
			// Ring peers use the source-allowlisted route-network front; the child
			// backend remains private to the container network namespace.
			"grpc_listen_address": childListenAddress,
			"grpc_listen_port":    grpcListenPort,
		},
		"common": map[string]any{
			"path_prefix":        "/var/lib/loki",
			"replication_factor": replicationFactor,
			"storage": map[string]any{
				"s3": map[string]any{
					"endpoint":          fmt.Sprintf("http://%s:%d", minioIp, minioPort),
					"bucketnames":       minioBucket,
					"access_key_id":     minio.AccessKey,
					"secret_access_key": minio.SecretKey,
					"s3forcepathstyle":  true,
				},
			},
			"ring": map[string]any{
				"instance_addr": lanIp,
				// advertise the stable external grpc port; we listen on the
				// internal port (server.grpc_listen_port) behind the lb
				"instance_port": grpcPort,
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
		"memberlist": map[string]any{
			"node_name":      host,
			"cluster_label":  fmt.Sprintf("%s-loki", os.Getenv("WARP_ENV")),
			"bind_addr":      []string{childListenAddress},
			"bind_port":      gossipBindPort,
			"advertise_addr": lanIp,
			"advertise_port": gossipPort,
			"join_members":   joinMembers,
			// the first instance to boot forms the cluster alone,
			// and periodic rejoin merges any startup race
			"abort_if_cluster_join_fails": false,
			"rejoin_interval":             "1m",
		},
		"ingester": map[string]any{
			"wal": map[string]any{
				// the wal dir does not survive redeploys, so flush all chunks to
				// minio on clean stop and rely on the replication factor for
				// unclean stops. flush_on_shutdown is a field of the WAL config
				// (loki 3.7 ingester.wal); placing it directly under `ingester`
				// ingester.Config").
				"flush_on_shutdown": true,
			},
			"autoforget_unhealthy": true,
		},
		"schema_config": map[string]any{
			"configs": []any{
				map[string]any{
					"from":         "2026-07-01",
					"store":        "tsdb",
					"object_store": "s3",
					"schema":       "v13",
					"index": map[string]any{
						"prefix": "index_",
						"period": "24h",
					},
				},
			},
		},
		"compactor": map[string]any{
			"working_directory":    "/var/lib/loki/compactor",
			"retention_enabled":    true,
			"delete_request_store": "s3",
		},
		"limits_config": map[string]any{
			"retention_period": retention,
			// the defaults 429 on deploy restart bursts
			"ingestion_rate_mb":           16,
			"ingestion_burst_size_mb":     32,
			"per_stream_rate_limit":       "5MB",
			"per_stream_rate_limit_burst": "20MB",
			"max_global_streams_per_user": 10000,
			// allow `warpctl logs` to page with large limits
			"max_entries_limit_per_query": 20000,
			// the monitor holds a standing tail per service (9), so the
			// default 10 leaves no headroom for human `warpctl logs -f`
			// plus reconnect churn
			"max_concurrent_tail_requests": 64,
			"reject_old_samples":           true,
			"reject_old_samples_max_age":   "168h",
			"query_timeout":                "2m",
		},
		"analytics": map[string]any{
			"reporting_enabled": false,
		},
		// the query-frontend and query-scheduler must advertise the EXTERNAL ring
		// grpc port (front-proxied), not their internal grpc_listen_port (the
		// default). internal ports are local-only -- firewalled cross-host -- so a
		// remote querier can't reach a frontend/scheduler advertised on the
		// internal port; the healthcheck times out and that host reads only its
		// local ingester (empty on the no-lb hosts crisp/fireside, which run no
		// log-producing services). 6490 is reachable from every host via the front
		// SO_REUSEPORT proxy, exactly like the ingester ring above.
		"frontend": map[string]any{
			// NOTE the yaml keys are address/port even though the flags are
			// -frontend.instance-addr / -frontend.instance-port
			"address": lanIp,
			"port":    grpcPort,
		},
		// loki calls this block scheduler_ring (mimir calls it ring)
		"query_scheduler": map[string]any{
			"scheduler_ring": map[string]any{
				"instance_addr": lanIp,
				"instance_port": grpcPort,
				// pin memberlist like the other rings (loki's default ring
				// kvstore is consul, which we don't run)
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
	}
	enableLogsDrilldownLokiFeatures(lokiConfig)

	lokiConfigYaml, err := yaml.Marshal(lokiConfig)
	if err != nil {
		panic(err)
	}
	lokiConfigPath := filepath.Join(runDir, "loki.yml")
	writeFile(lokiConfigPath, string(lokiConfigYaml), 0600)

	if err := os.MkdirAll("/var/lib/loki", 0755); err != nil {
		panic(err)
	}

	return lokiConfigPath, ringProxyPorts{
		grpcExternal:   grpcPort,
		grpcInternal:   grpcListenPort,
		gossipExternal: gossipPort,
		gossipInternal: gossipBindPort,
	}
}

// configuredLokiRetention is shared by Loki and Logs Drilldown so the UI does
// not offer time ranges that Loki has already expired.
func configuredLokiRetention(grafanaConfig *GrafanaConfig) string {
	if grafanaConfig != nil && grafanaConfig.Loki != nil && grafanaConfig.Loki.Retention != "" {
		return grafanaConfig.Loki.Retention
	}
	return defaultRetention
}

// enableLogsDrilldownLokiFeatures turns on the Loki APIs and ingestion metadata
// used by Grafana Logs Drilldown. Keep this explicit: relying on changing Loki
// defaults can leave the UI installed but unable to list volumes, levels, or
// patterns after an upgrade.
func enableLogsDrilldownLokiFeatures(lokiConfig map[string]any) {
	limitsConfig, ok := lokiConfig["limits_config"].(map[string]any)
	if !ok {
		panic(errors.New("loki config must have limits_config before enabling Logs Drilldown"))
	}
	limitsConfig["allow_structured_metadata"] = true
	limitsConfig["volume_enabled"] = true
	limitsConfig["discover_log_levels"] = true
	limitsConfig["discover_service_name"] = []string{"service"}
	lokiConfig["pattern_ingester"] = map[string]any{
		"enabled": true,
	}
}

func mimirFrontendConfig(lanIp string, grpcPort int) map[string]any {
	return map[string]any{
		// The single-binary fleet evaluates roughly 170 short alert-rule queries
		// each minute. Mimir's default query-frontend statistics emit one info
		// record for every request. Metrics retain query health, so disable this
		// per-request diagnostic stream instead of raising Loki's bounded queues
		// or changing alert evaluation cadence. Mimir 3.1.1's streaming evaluator
		// has a separate unconditional info record; mimirServerConfig suppresses
		// that at the component's source.
		"query_stats_enabled": false,
		// NOTE the yaml keys are address/port even though the flags are
		// -frontend.instance-addr / -frontend.instance-port.
		"address": lanIp,
		"port":    grpcPort,
	}
}

func mimirServerConfig(mimirHttpPort int, grpcListenPort int) map[string]any {
	return map[string]any{
		// Mimir 3.1.1's streaming PromQL evaluator logs `evaluation stats` at
		// info for every evaluation, independent of frontend.query_stats_enabled.
		// The six single-binary replicas turned the alert-rule workload into
		// hundreds of self-ingested Loki records per minute and overloaded the
		// bounded live-tail path. Keep warnings and errors (plus the complete
		// metrics surface) while dropping component-wide routine info at source.
		"log_level":           "warn",
		"http_listen_address": childListenAddress,
		"http_listen_port":    mimirHttpPort,
		"grpc_listen_address": childListenAddress,
		"grpc_listen_port":    grpcListenPort,
	}
}

func mimirBucketStoreConfig() map[string]any {
	return map[string]any{
		"sync_dir": "/var/lib/mimir/tsdb-sync",
		// Every replica runs both a querier and a store-gateway. With Mimir's
		// 15-minute default plus independent jitter, a querier that had loaded a
		// new bucket index sent that version to store-gateways still carrying the
		// previous generation. Each affected query then emitted the same warning
		// (an observed 882-second gap) and prolonged incomplete block discovery.
		// There is one tenant and one small index, so refresh it every minute to
		// bound convergence without hiding a warning that remains actionable.
		"sync_interval": "1m",
	}
}

func mimirTSDBConfig() map[string]any {
	return map[string]any{
		// The deploy deliberately leaves the Mimir data directory ephemeral so
		// overlapping generations never write the same WAL/TSDB. Mimir's false
		// default assumes that an incomplete head will be reused after restart;
		// with an ephemeral directory that instead discards every sample not yet
		// uploaded to object storage. Flush the partial head during the bounded
		// clean shutdown before the old container is removed.
		"dir":                      "/var/lib/mimir/tsdb",
		"flush_blocks_on_shutdown": true,
	}
}

func renderMimirConfig(host string, lanIp string, mimirHttpPort int, hostSettings *HostSettings, ringHosts []string, grafanaConfig *GrafanaConfig) (string, ringProxyPorts) {
	mimirSettings := grafanaConfig.Mimir
	if mimirSettings == nil {
		mimirSettings = &MimirConfig{}
	}
	// see renderLokiConfig: ring ports are the named constants, declared in
	// services.yml, validated against WARP_PORTS (no silent default).
	grpcPort := defaultMimirGrpcPort
	gossipPort := defaultMimirGossipPort
	grpcListenPort := requireServiceHostPort(grpcPort)
	gossipBindPort := requireServiceHostPort(gossipPort)
	replicationFactor := mimirSettings.ReplicationFactor
	if replicationFactor == 0 {
		replicationFactor = defaultReplicationFactor
	}
	retention := mimirSettings.Retention
	if retention == "" {
		retention = defaultMimirRetention
	}

	minioIp, minioPort := resolveMinioEndpoint(hostSettings, grafanaConfig)
	minioBucket := mimirSettings.Bucket
	if minioBucket == "" {
		minioBucket = "mimir"
	}

	joinMembers := ringJoinMembers(hostSettings, ringHosts, gossipPort)

	mimirConfig := map[string]any{
		"target":               "all",
		"multitenancy_enabled": false,
		"usage_stats": map[string]any{
			"enabled": false,
		},
		// Only the authenticated Go front reaches child HTTP listeners.
		"server": mimirServerConfig(mimirHttpPort, grpcListenPort),
		"common": map[string]any{
			"storage": map[string]any{
				"backend": "s3",
				"s3": map[string]any{
					"endpoint":          fmt.Sprintf("%s:%d", minioIp, minioPort),
					"bucket_name":       minioBucket,
					"access_key_id":     grafanaConfig.Minio.AccessKey,
					"secret_access_key": grafanaConfig.Minio.SecretKey,
					"insecure":          true,
				},
			},
		},
		"memberlist": map[string]any{
			"node_name":      host,
			"cluster_label":  fmt.Sprintf("%s-mimir", os.Getenv("WARP_ENV")),
			"bind_addr":      []string{childListenAddress},
			"bind_port":      gossipBindPort,
			"advertise_addr": lanIp,
			"advertise_port": gossipPort,
			"join_members":   joinMembers,
			// the first instance to boot forms the cluster alone,
			// and periodic rejoin merges any startup race
			"abort_if_cluster_join_fails": false,
			"rejoin_interval":             "1m",
		},
		"ingester": map[string]any{
			"ring": map[string]any{
				"replication_factor": replicationFactor,
				"instance_addr":      lanIp,
				"instance_port":      grpcPort,
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
		"distributor": map[string]any{
			"ring": map[string]any{
				"instance_addr": lanIp,
				"instance_port": grpcPort,
			},
		},
		"store_gateway": map[string]any{
			"sharding_ring": map[string]any{
				"replication_factor": replicationFactor,
				"instance_addr":      lanIp,
				"instance_port":      grpcPort,
			},
		},
		"compactor": map[string]any{
			"data_dir": "/var/lib/mimir/compactor",
			"sharding_ring": map[string]any{
				"instance_addr": lanIp,
				"instance_port": grpcPort,
			},
		},
		"blocks_storage": map[string]any{
			"storage_prefix": "blocks",
			"tsdb":           mimirTSDBConfig(),
			"bucket_store":   mimirBucketStoreConfig(),
		},
		"ruler_storage": map[string]any{
			"storage_prefix": "ruler",
		},
		// The ruler stages rule files on local disk at rule_path, which
		// defaults to the RELATIVE ./data-ruler/ -- the working directory is
		// "/" (the image sets no WORKDIR), so the default is unwritable to the
		// unprivileged runtime uid and mimir's startup sanity-check fails the
		// whole process: "ruler: failed to access directory ./data-ruler/:
		// open .check: permission denied". That took every mimir down on
		// 2026-08-11. It was latent for as long as the container still ran as
		// root and only surfaced when the bundle moved to USER 65532. Pin it
		// under /var/lib/mimir like every other directory here -- the image
		// chowns that tree to the runtime uid.
		"ruler": map[string]any{
			"rule_path": "/var/lib/mimir/ruler",
		},
		"activity_tracker": map[string]any{
			"filepath": "/var/lib/mimir/metrics-activity.log",
		},
		"limits": map[string]any{
			// retention is enforced by the compactor
			"compactor_blocks_retention_period": retention,
		},
		// advertise the EXTERNAL ring grpc port for the query-frontend and
		// query-scheduler too (see the matching note in renderLokiConfig): the
		// default is the internal grpc_listen_port, which is local-only and
		// firewalled cross-host, so remote queriers can't reach it. 6491 is
		// front-proxied and reachable from every host, like the rings above.
		"frontend": mimirFrontendConfig(lanIp, grpcPort),
		"query_scheduler": map[string]any{
			"ring": map[string]any{
				"instance_addr": lanIp,
				"instance_port": grpcPort,
				// pin memberlist like the other rings (loki's default ring
				// kvstore is consul, which we don't run)
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
	}

	mimirConfigYaml, err := yaml.Marshal(mimirConfig)
	if err != nil {
		panic(err)
	}
	mimirConfigPath := filepath.Join(runDir, "mimir.yml")
	writeFile(mimirConfigPath, string(mimirConfigYaml), 0600)

	if err := os.MkdirAll("/var/lib/mimir", 0755); err != nil {
		panic(err)
	}

	return mimirConfigPath, ringProxyPorts{
		grpcExternal:   grpcPort,
		grpcInternal:   grpcListenPort,
		gossipExternal: gossipPort,
		gossipInternal: gossipBindPort,
	}
}

// renderDatasourcesYaml builds the provisioned grafana datasources, which
// address the front's stable local publish port and NOT the loki/mimir child
// ports. Grafana state lives in the shared env postgres and file provisioning
// upserts by uid, so every host writes these same two rows and the host that
// starts last wins for the whole fleet. The child ports are warp allocated per
// deploy (WARP_PORTS), so they differ between hosts and across redeploys: a
// child port written here resolves only on the host that happened to write it
// and is a dead port everywhere else -- "connection refused", which grafana
// renders as an empty panel with no hint that the port is the problem. The
// local publish port is fixed by grafana.yml, so it is identical on every host
// and every deploy and the shared rows stay correct fleet-wide. The loopback
// publisher serves the matching read routes (see serve).
func renderDatasourcesYaml(localPort int) string {
	datasourceUrl := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	datasources := map[string]any{
		"apiVersion": 1,
		"datasources": []any{
			map[string]any{
				"name":      "Loki",
				"uid":       lokiDatasourceUid,
				"type":      "loki",
				"access":    "proxy",
				"url":       datasourceUrl,
				"isDefault": false,
				"editable":  false,
			},
			map[string]any{
				"name":      "Mimir",
				"uid":       "warp-mimir",
				"type":      "prometheus",
				"access":    "proxy",
				"url":       datasourceUrl + "/prometheus",
				"isDefault": true,
				"editable":  false,
			},
		},
	}
	datasourcesYaml, err := yaml.Marshal(datasources)
	if err != nil {
		panic(err)
	}
	return string(datasourcesYaml)
}

// renderLogsDrilldownPluginYaml enables the standard Grafana log explorer and
// points it at the stable provisioned Loki datasource. This app setting does
// not register datasource type "loki"; the native image plugin above is a
// separate invariant. Plugin provisioning is file-backed so every Grafana
// replica converges on the same configuration.
func renderLogsDrilldownPluginYaml(grafanaConfig *GrafanaConfig) string {
	pluginConfig := map[string]any{
		"apiVersion": 1,
		"apps": []any{
			map[string]any{
				"type":     logsDrilldownPluginID,
				"org_id":   1,
				"disabled": false,
				"jsonData": map[string]any{
					"dataSource": lokiDatasourceUid,
					"defaultTimeRange": map[string]any{
						"from": "now-1h",
						"to":   "now",
					},
					"interval":         configuredLokiRetention(grafanaConfig),
					"patternsDisabled": false,
				},
			},
		},
	}
	pluginYaml, err := yaml.Marshal(pluginConfig)
	if err != nil {
		panic(err)
	}
	return string(pluginYaml)
}

// withLogsDrilldownDatasourceDefault repairs app URLs generated while Grafana
// had no registered Loki implementation. Logs Drilldown treats an explicitly
// empty var-ds as a URL override, so its provisioned warp-loki default cannot
// recover that stale URL after the native plugin is deployed. Redirect only
// the exact GET route and preserve every other drilldown variable.
func withLogsDrilldownDatasourceDefault(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == logsDrilldownExplorePath {
			query := r.URL.Query()
			if query.Has("var-ds") && strings.TrimSpace(query.Get("var-ds")) == "" {
				query.Set("var-ds", lokiDatasourceUid)
				redirect := *r.URL
				redirect.RawQuery = query.Encode()
				http.Redirect(w, r, redirect.RequestURI(), http.StatusTemporaryRedirect)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// renderRemoteCacheSection points grafana's remote cache at the state
// database. The cache is shared by every grafana in the fleet, and the only
// shared store this env can offer it is the postgres that already holds that
// state. The env redis is NOT usable: it runs in cluster mode, where grafana
// fails every cache write with "ERR SELECT is not allowed in cluster mode".
// Grafana's redis remote cache client is a plain, non-cluster one, so dropping
// the database index would only trade SELECT for MOVED on every key outside
// the connected node's slots. Pointing at redis was silent -- the cache simply
// never held anything, and the id-service logged a failed write per token mint.
func renderRemoteCacheSection(grafanaConfig *GrafanaConfig) string {
	if grafanaConfig.Redis != nil {
		warp.Err.Printf(
			"grafana.yml redis is ignored: the remote cache uses the grafana database (cluster-mode redis rejects SELECT).\n",
		)
	}
	if grafanaConfig.Postgres == nil {
		// sqlite state, single instance: nothing to share a cache through
		return ""
	}
	return strings.Join([]string{
		"[remote_cache]",
		"type = database",
	}, "\n")
}

func renderGrafanaConfig(env string, domain string, grafanaHttpPort int, localPort int, hostSettings *HostSettings, grafanaConfig *GrafanaConfig) string {
	if grafanaConfig.Grafana == nil || grafanaConfig.Grafana.AdminPassword == "" {
		panic(errors.New("grafana.yml must have grafana.admin_password."))
	}

	var databaseSection string
	if postgres := grafanaConfig.Postgres; postgres != nil {
		postgresHostname := postgres.Hostname
		if postgresHostname == "" {
			postgresHostname = hostSettings.EnvVars["BRINGYOUR_POSTGRES_HOSTNAME"]
		}
		if postgresHostname == "" {
			panic(errors.New("No postgres hostname in grafana.yml or settings.yml env_vars."))
		}
		postgresPort := postgres.Port
		if postgresPort == 0 {
			postgresPort = 5432
		}
		postgresUser := postgres.User
		if postgresUser == "" {
			postgresUser = "grafana"
		}
		postgresDatabase := postgres.Database
		if postgresDatabase == "" {
			postgresDatabase = "grafana"
		}
		databaseSection = strings.Join([]string{
			"[database]",
			"type = postgres",
			fmt.Sprintf("host = %s:%d", postgresHostname, postgresPort),
			fmt.Sprintf("name = %s", postgresDatabase),
			fmt.Sprintf("user = %s", postgresUser),
			fmt.Sprintf(`password = """%s"""`, postgres.Password),
			"ssl_mode = disable",
		}, "\n")
	} else {
		// single instance fallback. state does not survive redeploys
		warp.Err.Printf("No postgres in grafana.yml. Grafana state will not survive redeploys.\n")
		databaseSection = strings.Join([]string{
			"[database]",
			"type = sqlite3",
		}, "\n")
	}

	remoteCacheSection := renderRemoteCacheSection(grafanaConfig)

	grafanaHostname := fmt.Sprintf("%s-grafana.%s", env, domain)

	grafanaIni := fmt.Sprintf(`
[server]
protocol = http
; the authenticated go front is the only intended caller
http_addr = 127.0.0.1
http_port = %d
domain = %s
root_url = https://%s/

%s

%s

[security]
admin_user = admin
admin_password = """%s"""
cookie_secure = true

[users]
allow_sign_up = false

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[plugins]
; Logs Drilldown and the Grafana-13 standalone Prometheus and Loki datasources
; are checksum-pinned and baked into the image. Do not make container readiness
; depend on Grafana's asynchronous internet downloader.
preinstall_disabled = true

[paths]
data = /var/lib/grafana
logs = /var/lib/grafana/logs
plugins = /var/lib/grafana/plugins
provisioning = %s/provisioning
`,
		grafanaHttpPort,
		grafanaHostname,
		grafanaHostname,
		databaseSection,
		remoteCacheSection,
		grafanaConfig.Grafana.AdminPassword,
		runDir,
	)
	grafanaIniPath := filepath.Join(runDir, "grafana.ini")
	writeFile(grafanaIniPath, grafanaIni, 0640)

	datasourcesYaml := renderDatasourcesYaml(localPort)
	for _, provisioningDir := range []string{"datasources", "dashboards", "plugins", "alerting"} {
		if err := os.MkdirAll(filepath.Join(runDir, "provisioning", provisioningDir), 0755); err != nil {
			panic(err)
		}
	}
	writeFile(filepath.Join(runDir, "provisioning", "datasources", "loki.yml"), datasourcesYaml, 0644)
	writeFile(
		filepath.Join(runDir, "provisioning", "plugins", "logs-drilldown.yml"),
		renderLogsDrilldownPluginYaml(grafanaConfig),
		0644,
	)

	// alert rules (grafana unified alerting file provisioning).
	// grafana loads provisioning/alerting/*.yml at startup, so the rules
	// re-provision on every deploy. file provisioned rules are read only in
	// the ui; edit grafana/alerting in the warp repo and redeploy.
	// (dashboards are not file provisioned: they load into the grafana
	// database with `bringyourctl grafana load-defaults` in the server repo)
	alertingEntries, err := alertingFs.ReadDir("alerting")
	if err != nil {
		panic(err)
	}
	for _, entry := range alertingEntries {
		alertingYaml, err := alertingFs.ReadFile(fmt.Sprintf("alerting/%s", entry.Name()))
		if err != nil {
			panic(err)
		}
		writeFile(filepath.Join(runDir, "provisioning", "alerting", entry.Name()), string(alertingYaml), 0644)
	}

	if err := os.MkdirAll("/var/lib/grafana", 0755); err != nil {
		panic(err)
	}

	return grafanaIniPath
}

// the go http front

// authenticatedPushHandler applies authentication before exposing a bounded
// request body to an ingestion backend.
func authenticatedPushHandler(users []*ServiceUser, maxBodyBytes int64, next http.Handler) http.Handler {
	return requireRole(users, "push", http.MaxBytesHandler(next, maxBodyBytes))
}

// publishHandlers carries the backends the stable publish listeners share.
type publishHandlers struct {
	users            []*ServiceUser
	lokiProxy        http.Handler
	mimirProxy       http.Handler
	statsPushHandler http.Handler
}

// newPublishMux serves the ingestion routes carried by every binding of the
// stable publish port. Each one uses the same credentials as the public front
// even when the caller is local.
func newPublishMux(handlers publishHandlers) *http.ServeMux {
	publishMux := http.NewServeMux()
	publishMux.Handle("/loki/api/v1/push", authenticatedPushHandler(handlers.users, maxLokiPushBodyBytes, handlers.lokiProxy))
	publishMux.Handle("/metrics/job/", authenticatedPushHandler(handlers.users, maxStatsPushBodyBytes, handlers.statsPushHandler))
	publishMux.Handle("/api/v1/push", authenticatedPushHandler(handlers.users, maxMimirPushBodyBytes, handlers.mimirProxy))
	return publishMux
}

// newLoopbackPublishMux adds the datasource read routes to the ingestion
// routes. The co-located grafana provisions these paths on the stable publish
// port because it is the only address identical on every host, and grafana's
// datasource rows are shared fleet-wide through the env postgres (see
// renderDatasourcesYaml). They carry no credentials because this mux is served
// ONLY on the loopback binding, where the loki and mimir children it proxies
// already answer unauthenticated on the same host loopback
// (childListenAddress) -- which is exactly what the datasources dialed
// directly before. The lan binding must keep using newPublishMux: it is
// reachable from every routed host, and these routes read all logs and
// metrics. The longer /loki/api/v1/push pattern still wins over /loki/, so
// ingestion on this mux stays authenticated.
func newLoopbackPublishMux(handlers publishHandlers) *http.ServeMux {
	loopbackMux := newPublishMux(handlers)
	loopbackMux.Handle("/loki/", handlers.lokiProxy)
	loopbackMux.Handle("/prometheus/", handlers.mimirProxy)
	return loopbackMux
}

// Rejects an empty, hostname, or wildcard service address so a missing host-
// networking environment cannot silently restore the original exposure.
func validateExactListenAddrs(listenAddrs []string) error {
	if len(listenAddrs) == 0 {
		return errors.New("service has no listen addresses")
	}
	for _, listenAddr := range listenAddrs {
		listenHost, _, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return fmt.Errorf("invalid service listen address %q: %w", listenAddr, err)
		}
		listenIp, err := netip.ParseAddr(listenHost)
		if err != nil || listenIp.IsUnspecified() {
			return fmt.Errorf("service listen address %q is not an exact IP", listenAddr)
		}
	}
	return nil
}

// configuredPublishIps returns the exact non-loopback addresses that carry
// authenticated ingestion. The LAN identity is always present for the local
// fleet; a configured VPN identity adds the private offsite path without
// restoring a wildcard listener.
func configuredPublishIps(host string, lanIp string, publishRoutes map[string]string) ([]string, error) {
	lanAddr, err := netip.ParseAddr(strings.TrimSpace(lanIp))
	if err != nil || lanAddr.IsUnspecified() || lanAddr.IsLoopback() {
		return nil, fmt.Errorf("invalid LAN publish address %q for %s", lanIp, host)
	}
	publishIps := []string{lanAddr.String()}
	vpnIp, ok := publishRoutes[host]
	if !ok {
		return publishIps, nil
	}
	vpnAddr, err := netip.ParseAddr(strings.TrimSpace(vpnIp))
	if err != nil || vpnAddr.IsUnspecified() || vpnAddr.IsLoopback() {
		return nil, fmt.Errorf("invalid configured publish address %q for %s", vpnIp, host)
	}
	if vpnAddr != lanAddr {
		publishIps = append(publishIps, vpnAddr.String())
	}
	return publishIps, nil
}

// serve exposes public traffic only on Warp's exact service addresses, exposes
// authenticated push-only traffic on loopback plus the exact configured LAN
// and VPN addresses, and starts source-allowlisted ring proxies on the LAN.
// One child or cross-datasource readiness request on Grafana's loopback port.
type childReadyCheck struct {
	name                       string
	url                        string
	method                     string
	body                       string
	username                   string
	password                   string
	requireDatasourceQueryBody bool
}

// childReadyChecks returns the readiness probe for each child. Loki and Mimir
// answer /ready with the modules still starting; Grafana answers /api/health.
// The final POST crosses Grafana's datasource implementation and both
// provisioned backends. A datasource database row alone is insufficient:
// Grafana returns plugin.notRegistered when the corresponding executable
// plugin is absent from a custom image.
func childReadyChecks(lokiHttpPort int, mimirHttpPort int, grafanaHttpPort int, adminPassword string) []childReadyCheck {
	datasourceQuery, err := json.Marshal(map[string]any{
		"from": "now-1m",
		"to":   "now",
		"queries": []any{
			map[string]any{
				"refId":      "M",
				"datasource": map[string]string{"uid": "warp-mimir", "type": "prometheus"},
				"expr":       "vector(1)",
				"instant":    true,
				"range":      false,
				"format":     "time_series",
			},
			map[string]any{
				"refId":      "L",
				"datasource": map[string]string{"uid": lokiDatasourceUid, "type": "loki"},
				"expr":       `sum(count_over_time({service="web"}[1m]))`,
				"instant":    true,
				"range":      false,
				"queryType":  "instant",
				"maxLines":   1,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return []childReadyCheck{
		{
			name: "loki",
			url:  fmt.Sprintf("http://%s:%d/ready", childListenAddress, lokiHttpPort),
		},
		{
			name: "mimir",
			url:  fmt.Sprintf("http://%s:%d/ready", childListenAddress, mimirHttpPort),
		},
		{
			name: "grafana",
			url:  fmt.Sprintf("http://%s:%d/api/health", childListenAddress, grafanaHttpPort),
		},
		{
			name:                       "grafana-datasources",
			url:                        fmt.Sprintf("http://%s:%d/api/ds/query", childListenAddress, grafanaHttpPort),
			method:                     http.MethodPost,
			body:                       string(datasourceQuery),
			username:                   "admin",
			password:                   adminPassword,
			requireDatasourceQueryBody: true,
		},
	}
}

// requireChildReadyCheck returns the named probe. The names are fixed in
// childReadyChecks, so a miss is a programming error.
func requireChildReadyCheck(checks []childReadyCheck, name string) childReadyCheck {
	for _, check := range checks {
		if check.name == name {
			return check
		}
	}
	panic(errors.New(fmt.Sprintf("No child ready check named %s", name)))
}

func newChildReadyClient() *http.Client {
	return &http.Client{Timeout: childReadyTimeout}
}

// checkChildReady reports the child unready unless its endpoint answers 2xx.
// The body of a 503 names what is still starting, which is the whole
// diagnostic value of the probe, so a bounded prefix of it goes in the error.
func checkChildReady(ctx context.Context, client *http.Client, check childReadyCheck) error {
	method := check.method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, check.url, strings.NewReader(check.body))
	if err != nil {
		return fmt.Errorf("%s: %s", check.name, err)
	}
	if check.username != "" || check.password != "" {
		request.SetBasicAuth(check.username, check.password)
	}
	if check.body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %s", check.name, err)
	}
	defer response.Body.Close()
	bodyLimit := int64(256)
	if check.requireDatasourceQueryBody && 200 <= response.StatusCode && response.StatusCode < 300 {
		bodyLimit = 64 * 1024
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, bodyLimit))
	if response.StatusCode < 200 || 300 <= response.StatusCode {
		return fmt.Errorf(
			"%s: %d %s",
			check.name,
			response.StatusCode,
			strings.Join(strings.Fields(string(body)), " "),
		)
	}
	if check.requireDatasourceQueryBody {
		if err := validateDatasourceQueryResponse(body, "M", "L"); err != nil {
			return fmt.Errorf("%s: %s", check.name, err)
		}
	}
	return nil
}

// validateDatasourceQueryResponse rejects Grafana's HTTP-200 result envelopes
// when one datasource failed inside the request. Empty Loki frames are valid:
// the readiness contract is executable query plumbing, not recent traffic.
func validateDatasourceQueryResponse(body []byte, refIds ...string) error {
	var response struct {
		Results map[string]struct {
			Status int               `json:"status"`
			Error  string            `json:"error"`
			Frames []json.RawMessage `json:"frames"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("invalid query response: %w", err)
	}
	for _, refId := range refIds {
		result, ok := response.Results[refId]
		if !ok {
			return fmt.Errorf("query response omitted result %s", refId)
		}
		if result.Error != "" {
			return fmt.Errorf("query %s: %s", refId, strings.Join(strings.Fields(result.Error), " "))
		}
		if result.Status < 200 || 300 <= result.Status {
			return fmt.Errorf("query %s returned status %d", refId, result.Status)
		}
	}
	return nil
}

// childHealthCheck adapts a readiness probe to warp.ChildSettings.
func childHealthCheck(check childReadyCheck) func(ctx context.Context) error {
	client := newChildReadyClient()
	return func(ctx context.Context) error {
		return checkChildReady(ctx, client, check)
	}
}

// readinessLatch gates the deploy poll on the children, once. The latch is one
// way: after every child has been ready, /status stays ok, so a later blip
// cannot pull an already serving container out of rotation. Runtime health
// belongs to the supervisor and the monitor, not to the deploy poll. Same
// shape as the api and taskworker readiness latches.
type readinessLatch struct {
	stateLock sync.Mutex
	ready     bool
	err       error
}

// notReadyStatusJson names the child that is holding the deploy poll. The
// status MUST start with the word "error": that prefix is the whole contract
// with warpctl, whose WarpStatusResponse.IsError matches "^(?i)error(\\s|:)" and
// is the only thing that fails a poll -- the http status code is not read on
// the deploy path.
func notReadyStatusJson(readyErr error) []byte {
	body, err := json.Marshal(map[string]string{
		"version":        os.Getenv("WARP_VERSION"),
		"config_version": os.Getenv("WARP_CONFIG_VERSION"),
		"status":         fmt.Sprintf("error not ready (%s)", readyErr),
	})
	if err != nil {
		return []byte(`{"status":"error not ready"}`)
	}
	return body
}

func newReadinessLatch() *readinessLatch {
	return &readinessLatch{
		err: errors.New("starting"),
	}
}

func (self *readinessLatch) setReady() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ready = true
	self.err = nil
}

func (self *readinessLatch) setUnready(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ready {
		return
	}
	self.err = err
}

func (self *readinessLatch) status() (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ready, self.err
}

// watch latches ready the first round every check passes. A check that flaps
// while the fleet cycles is fine: one passing round inside the deploy poll
// budget is all the latch needs.
func (self *readinessLatch) watch(event *warp.Event, checks []childReadyCheck) {
	client := newChildReadyClient()
	for !event.IsSet() {
		var err error
		for _, check := range checks {
			checkCtx, checkCancel := context.WithTimeout(event.Ctx, childReadyTimeout)
			err = checkChildReady(checkCtx, client, check)
			checkCancel()
			if err != nil {
				break
			}
		}
		if err == nil {
			warp.Err.Printf("Ready. Every child answered its readiness endpoint.\n")
			self.setReady()
			return
		}
		self.setUnready(err)
		event.WaitForSet(readinessCheckInterval)
	}
}

func serve(event *warp.Event, env string, lanIp string, publishIps []string, ringHosts []string, hostSettings *HostSettings, grafanaConfig *GrafanaConfig, readyChecks []childReadyCheck, lokiHttpPort int, grafanaHttpPort int, mimirHttpPort int, localPort int, lokiRing ringProxyPorts, mimirRing ringProxyPorts) error {
	lokiUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", lokiHttpPort))
	if err != nil {
		return err
	}
	grafanaUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", grafanaHttpPort))
	if err != nil {
		return err
	}
	mimirUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mimirHttpPort))
	if err != nil {
		return err
	}

	newProxy := func(target *url.URL) *httputil.ReverseProxy {
		proxy := httputil.NewSingleHostReverseProxy(target)
		// stream long responses and tails
		proxy.FlushInterval = 100 * time.Millisecond
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			warp.Err.Printf("Proxy error %s (%s)\n", r.URL.Path, err)
			http.Error(w, "Bad gateway.", http.StatusBadGateway)
		}
		return proxy
	}
	lokiProxy := newProxy(lokiUrl)
	grafanaProxy := newProxy(grafanaUrl)
	mimirProxy := newProxy(mimirUrl)
	statsPushHandler := newStatsPushHandler(mimirUrl)

	var adminPassword string
	if grafanaConfig.Grafana != nil {
		adminPassword = grafanaConfig.Grafana.AdminPassword
	}
	publicStats := newPublicIndex(grafanaUrl, adminPassword)
	publicStatsFeed := newStatsFeed(mimirUrl, env)

	status, err := json.Marshal(map[string]string{
		"version":        os.Getenv("WARP_VERSION"),
		"config_version": os.Getenv("WARP_CONFIG_VERSION"),
		"status":         "ok",
	})
	if err != nil {
		return err
	}

	// hold the deploy poll until loki, mimir, and grafana are all up. Until
	// then the status names the child that is not, so the failing poll in the
	// journal says which one
	readiness := newReadinessLatch()
	go readiness.watch(event, readyChecks)

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if ready, readyErr := readiness.status(); !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write(notReadyStatusJson(readyErr))
			return
		}
		w.Write(status)
	})
	mux.Handle("/loki/api/v1/push", authenticatedPushHandler(grafanaConfig.Users, maxLokiPushBodyBytes, lokiProxy))
	mux.Handle("/loki/", requireRole(grafanaConfig.Users, "query", lokiProxy))
	mux.Handle("/metrics/job/", authenticatedPushHandler(grafanaConfig.Users, maxStatsPushBodyBytes, statsPushHandler))
	mux.Handle("/api/v1/push", authenticatedPushHandler(grafanaConfig.Users, maxMimirPushBodyBytes, mimirProxy))
	mux.Handle("/prometheus/", requireRole(grafanaConfig.Users, "query", mimirProxy))
	mux.HandleFunc("/stats", publicStats.serveHtml)
	mux.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		serveStatsJson(w, r, publicStats, publicStatsFeed)
	})
	mux.Handle("/", withLogsDrilldownDatasourceDefault(grafanaProxy))

	server := &http.Server{
		Handler: mux,
		// no write timeout, to support tail
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	// SO_REUSEPORT lets old and new containers overlap on the stable publisher.
	handlers := publishHandlers{
		users:            grafanaConfig.Users,
		lokiProxy:        lokiProxy,
		mimirProxy:       mimirProxy,
		statsPushHandler: statsPushHandler,
	}

	localMux := newPublishMux(handlers)
	localServer := &http.Server{
		Handler:           localMux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	loopbackMux := newLoopbackPublishMux(handlers)
	loopbackServer := &http.Server{
		Handler:           loopbackMux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	mainListenAddrs, err := warp.ServiceListenAddrs(80)
	if err != nil {
		return err
	}
	if err := validateExactListenAddrs(mainListenAddrs); err != nil {
		return err
	}
	publishListeners := []struct {
		listenAddr string
		server     *http.Server
	}{
		{net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", localPort)), loopbackServer},
	}
	for _, publishIp := range publishIps {
		publishListeners = append(publishListeners, struct {
			listenAddr string
			server     *http.Server
		}{net.JoinHostPort(publishIp, fmt.Sprintf("%d", localPort)), localServer})
	}

	serveErrors := make(chan error, len(mainListenAddrs)+len(publishListeners))
	for _, mainListenAddr := range mainListenAddrs {
		go func() {
			warp.Err.Printf("Listening on %s\n", mainListenAddr)
			listener, err := net.Listen("tcp", mainListenAddr)
			if err != nil {
				serveErrors <- err
				return
			}
			serveErrors <- server.Serve(listener)
		}()
	}
	for _, publishListener := range publishListeners {
		go func() {
			warp.Err.Printf("Listening on %s (reuseport)\n", publishListener.listenAddr)
			localListener, err := warp.ListenReusePort(publishListener.listenAddr)
			if err != nil {
				serveErrors <- err
				return
			}
			serveErrors <- publishListener.server.Serve(localListener)
		}()
	}

	allowedRingIps, err := ringAllowedIps(hostSettings, ringHosts)
	if err != nil {
		return err
	}
	for _, r := range []ringProxyPorts{lokiRing, mimirRing} {
		startRingReusePortProxy(event, lanIp, allowedRingIps, r.grpcExternal, r.grpcInternal, false)
		startRingReusePortProxy(event, lanIp, allowedRingIps, r.gossipExternal, r.gossipInternal, true)
	}

	select {
	case <-event.Ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		localServer.Shutdown(shutdownCtx)
		loopbackServer.Shutdown(shutdownCtx)
		return nil
	case err := <-serveErrors:
		return err
	}
}

// requireRole enforces basic auth against the service users with the role
func requireRole(users []*ServiceUser, role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, password, ok := r.BasicAuth()
		if ok {
			for _, user := range users {
				if user.Name == "" || user.Password == "" || !slices.Contains(user.Roles, role) {
					continue
				}
				nameMatch := subtle.ConstantTimeCompare([]byte(user.Name), []byte(name)) == 1
				passwordMatch := subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1
				if nameMatch && passwordMatch {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="warp grafana"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
	})
}

// the public dashboards directory, served at /stats (html) and merged into
// /stats.json (see stats.go for the flat stats side of that feed).
// it lists the grafana public dashboards (dashboards tagged "public" in the
// server repo, published by `bringyourctl grafana load-defaults`), read live
// from grafana's public dashboards api with the admin credentials and cached
// briefly. these are the exact paths /stats and /stats.json; grafana's own
// assets under /public/ and its /public-dashboards/<token> views stay on "/"

const publicIndexTtl = 30 * time.Second

type publicDashboard struct {
	AccessToken  string `json:"accessToken"`
	Title        string `json:"title"`
	DashboardUid string `json:"dashboardUid"`
	IsEnabled    bool   `json:"isEnabled"`
}

type publicIndex struct {
	grafanaUrl    *url.URL
	adminPassword string
	httpClient    *http.Client

	mu         sync.Mutex
	cached     []publicDashboard
	cachedAt   time.Time
	haveCached bool
}

func newPublicIndex(grafanaUrl *url.URL, adminPassword string) *publicIndex {
	return &publicIndex{
		grafanaUrl:    grafanaUrl,
		adminPassword: adminPassword,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

// list returns the enabled public dashboards sorted by title, cached for
// publicIndexTtl. on a fetch error a stale cache is served if present
func (self *publicIndex) list() ([]publicDashboard, error) {
	self.mu.Lock()
	if self.haveCached && time.Since(self.cachedAt) < publicIndexTtl {
		cached := self.cached
		self.mu.Unlock()
		return cached, nil
	}
	self.mu.Unlock()

	dashboards, err := self.fetch()
	if err != nil {
		self.mu.Lock()
		defer self.mu.Unlock()
		if self.haveCached {
			return self.cached, nil
		}
		return nil, err
	}

	self.mu.Lock()
	self.cached = dashboards
	self.cachedAt = time.Now()
	self.haveCached = true
	self.mu.Unlock()
	return dashboards, nil
}

// fetch reads all enabled public dashboards from the grafana api
func (self *publicIndex) fetch() ([]publicDashboard, error) {
	enabled := []publicDashboard{}
	// page through the list
	for page := 1; page <= 1000; page += 1 {
		listUrl := fmt.Sprintf("%s/api/dashboards/public-dashboards?page=%d&perpage=100", self.grafanaUrl.String(), page)
		request, err := http.NewRequest(http.MethodGet, listUrl, nil)
		if err != nil {
			return nil, err
		}
		request.SetBasicAuth("admin", self.adminPassword)
		response, err := self.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
		response.Body.Close()
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list public dashboards (%d)", response.StatusCode)
		}
		var list struct {
			PublicDashboards []publicDashboard `json:"publicDashboards"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, err
		}
		for _, d := range list.PublicDashboards {
			if d.IsEnabled && d.AccessToken != "" {
				enabled = append(enabled, d)
			}
		}
		if len(list.PublicDashboards) < 100 {
			break
		}
	}
	slices.SortFunc(enabled, func(a publicDashboard, b publicDashboard) int {
		return strings.Compare(a.Title, b.Title)
	})
	return enabled, nil
}

func (self *publicIndex) serveHtml(w http.ResponseWriter, r *http.Request) {
	dashboards, err := self.list()
	if err != nil {
		warp.Err.Printf("Public stats index error (%s)\n", err)
		http.Error(w, "Stats unavailable.", http.StatusBadGateway)
		return
	}

	var b strings.Builder
	b.WriteString(publicIndexHead)
	if len(dashboards) == 0 {
		b.WriteString(`<p class="empty">No public dashboards yet.</p>`)
	} else {
		b.WriteString("<ul>")
		for _, d := range dashboards {
			fmt.Fprintf(&b, `<li><a href="/public-dashboards/%s">%s</a></li>`,
				url.PathEscape(d.AccessToken), html.EscapeString(d.Title))
		}
		b.WriteString("</ul>")
	}
	b.WriteString(publicIndexFoot)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

const publicIndexHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>urnetwork stats</title>
<style>
:root { color-scheme: light dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1.25rem; line-height: 1.5; }
h1 { font-size: 1.4rem; margin: 0 0 0.25rem; }
p.sub { margin: 0 0 1.5rem; opacity: 0.7; font-size: 0.95rem; }
ul { list-style: none; padding: 0; margin: 0; }
li a { display: block; padding: 0.85rem 1rem; border: 1px solid rgba(127,127,127,0.3); border-radius: 0.5rem; margin-bottom: 0.6rem; text-decoration: none; color: inherit; font-weight: 500; }
li a:hover { border-color: rgba(127,127,127,0.7); }
p.empty { opacity: 0.6; }
footer { margin-top: 2rem; font-size: 0.8rem; opacity: 0.5; }
footer a { color: inherit; }
</style>
</head>
<body>
<h1>urnetwork stats</h1>
<p class="sub">Public, read-only. No login required.</p>
`

const publicIndexFoot = `
<footer>JSON feed: <a href="/stats.json">/stats.json</a></footer>
</body>
</html>
`
