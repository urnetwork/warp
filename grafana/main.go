package main

// the warp grafana service bundles grafana, loki, mimir, and the alloy
// collector behind a go http front.
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
// on :<local_port from grafana.yml> (SO_REUSEPORT, stable across redeploys,
// all interfaces so off-host pushers reach a host's lan ip) — the publish port
// for services on the host (and fluent-bit on non-grafana hosts):
//   /loki/...       -> the local loki api, used by alloy
//   /metrics/job/... -> stats push receiver (see push.go)
//   /api/v1/push    -> mimir remote write
// grafana, loki, and mimir listen on the warp allocated internal ports for
// the service ports declared in services.yml (WARP_PORTS)
//
// grafana state lives in the env postgres (see vault grafana.yml).
// loki instances on the service hosts form a ring over the host lan
// (settings.yml routes) and store chunks in minio (s3).
//
// alloy ships the docker container logs of its host to the local loki.
// alloy discovers containers via the docker api (mount_docker) and reads
// their logs regardless of the container log driver.
// container labels warp.env, warp.service, warp.block become loki labels,
// with the host added from WARP_HOST.
// read positions are stored under WARP_DATA (mount_data), so log shipping
// resumes where it stopped across redeploys.
// see grafana/README.md

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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp"
	warpservices "github.com/urnetwork/warp/services"
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

// pickAlloyHttpListenAddr returns a real, free loopback address for alloy's
// http server (ui, /metrics, single-node clustering) -- which is internal-only
// and referenced by nothing else. it must not be a FIXED port: during a redeploy
// overlap the draining old container still holds it, so the new alloy would
// crash-loop on the bind (alloy is a child binary, so unlike the ring ports it
// can't SO_REUSEPORT, and unlike loki/mimir it has no warp per-deploy port). it
// also can't be ephemeral ":0": alloy's clustering derives its advertise address
// from this port and rejects a zero port ("Failed to get final advertise
// address: missing real listen port"). so bind :0 once to let the kernel pick a
// free port, then hand alloy that concrete number -- the kernel won't pick a
// port the old container's alloy still holds, so old and new never collide.
func pickAlloyHttpListenAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// ringProxyPorts carries a loki/mimir ring backend's external port (advertised
// to peers on the route net, owned by the go front with SO_REUSEPORT so the old
// and new containers coexist during a redeploy overlap) and its internal port
// (where loki/mimir actually listen, unique per deploy). The front reuseport-
// proxies external -> 127.0.0.1:internal. loki/mimir cannot set SO_REUSEPORT
// themselves, which is why the front owns the reuseport socket.
type ringProxyPorts struct {
	grpcExternal   int
	grpcInternal   int
	gossipExternal int
	gossipInternal int
}

// per host settings from config/<env>/settings.yml
type HostSettings struct {
	EnvVars map[string]string `yaml:"env_vars,omitempty"`
	Routes  map[string]string `yaml:"routes,omitempty"`
}

// vault/<env>/grafana.yml
type GrafanaConfig struct {
	// the stable local publish port on every host
	LocalPort int              `yaml:"local_port,omitempty"`
	Grafana   *GrafanaUiConfig `yaml:"grafana,omitempty"`
	Postgres  *PostgresConfig  `yaml:"postgres,omitempty"`
	Redis     *RedisConfig     `yaml:"redis,omitempty"`
	Minio     *MinioConfig     `yaml:"minio,omitempty"`
	Loki      *LokiConfig      `yaml:"loki,omitempty"`
	Mimir     *MimirConfig     `yaml:"mimir,omitempty"`
	Users     []*ServiceUser   `yaml:"users,omitempty"`
}

type GrafanaUiConfig struct {
	AdminPassword string `yaml:"admin_password,omitempty"`
}

type PostgresConfig struct {
	Hostname string `yaml:"hostname,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	Database string `yaml:"database,omitempty"`
}

type RedisConfig struct {
	Hostname string `yaml:"hostname,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	// the redis database for grafana, apart from the other redis users
	Database int    `yaml:"database,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type MinioConfig struct {
	Hostname  string `yaml:"hostname,omitempty"`
	Port      int    `yaml:"port,omitempty"`
	AccessKey string `yaml:"access_key,omitempty"`
	SecretKey string `yaml:"secret_key,omitempty"`
	Bucket    string `yaml:"bucket,omitempty"`
}

type LokiConfig struct {
	ReplicationFactor int    `yaml:"replication_factor,omitempty"`
	Retention         string `yaml:"retention,omitempty"`
	// a hard quota on the minio bucket,
	// applied by the minio playbook (not by this service).
	// retention is the primary control and should keep usage
	// well below the quota
	MaxStorage string `yaml:"max_storage,omitempty"`
}

type MimirConfig struct {
	ReplicationFactor int    `yaml:"replication_factor,omitempty"`
	Retention         string `yaml:"retention,omitempty"`
	// see LokiConfig.MaxStorage
	MaxStorage string `yaml:"max_storage,omitempty"`
	Bucket     string `yaml:"bucket,omitempty"`
}

type ServiceUser struct {
	Name     string   `yaml:"name,omitempty"`
	Password string   `yaml:"password,omitempty"`
	Roles    []string `yaml:"roles,omitempty"`
}

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(errors.New(fmt.Sprintf("%s must be set.", name)))
	}
	return value
}

// the warp allocated internal port for a service port declared in
// services.yml. without host networking, the service port itself
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

func main() {
	env := requireEnv("WARP_ENV")
	domain := requireEnv("WARP_DOMAIN")
	host := requireEnv("WARP_HOST")
	vaultHome := requireEnv("WARP_VAULT")
	configHome := requireEnv("WARP_CONFIG")
	// WARP_DATA is provided by newer warpctl (mount_data=yes) and points at a
	// persistent docker volume that survives redeploys. Fall back to the same
	// path the mount targets when it is unset, so the bundle also runs under an
	// OLDER warpctl that predates mount_data (shadow deploy / version skew).
	// Without the mount, alloy read positions live in the container layer and
	// do not persist across redeploys — the only cost is possibly re-shipping
	// recent logs after a restart, never data loss.
	dataHome := os.Getenv("WARP_DATA")
	if dataHome == "" {
		dataHome = "/srv/warp/data"
	}

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

	var grafanaConfig GrafanaConfig
	// WARP_VAULT is already the env-specific vault (the mount source is
	// /srv/warp/<env>/vault), so the secrets live at its top level alongside
	// pg.yml/jwt.yml/connect.yml. Prefer that; fall back to the <env> subdir
	// for layouts that nest it. Reading only the subdir (the original) panicked
	// on the standard deploy where grafana.yml is at the vault root.
	grafanaYamlPath := filepath.Join(vaultHome, "grafana.yml")
	if _, err := os.Stat(grafanaYamlPath); err != nil {
		grafanaYamlPath = filepath.Join(vaultHome, env, "grafana.yml")
	}
	loadYaml(grafanaYamlPath, &grafanaConfig)

	lokiHttpPort := servicePortToHostPort(lokiServicePort)
	grafanaHttpPort := servicePortToHostPort(grafanaServicePort)
	mimirHttpPort := servicePortToHostPort(mimirServicePort)

	localPort := defaultLocalPort
	if grafanaConfig.LocalPort != 0 {
		localPort = grafanaConfig.LocalPort
	}

	// discover the ring peers from the vault's services.yml at runtime -- the
	// hosts that actually run the grafana bundle -- rather than seeding the
	// memberlist with every routed host (see ringHostsForService)
	ringHosts := ringHostsForService(vaultHome, env, "grafana", hostSettings)
	warp.Err.Printf("Ring hosts for grafana: %v\n", ringHosts)

	lokiConfigPath, lokiRing := renderLokiConfig(host, lanIp, lokiHttpPort, hostSettings, ringHosts, &grafanaConfig)
	mimirConfigPath, mimirRing := renderMimirConfig(host, lanIp, mimirHttpPort, hostSettings, ringHosts, &grafanaConfig)
	grafanaIniPath := renderGrafanaConfig(env, domain, lokiHttpPort, grafanaHttpPort, mimirHttpPort, hostSettings, &grafanaConfig)
	alloyConfigPath := renderAlloyConfig(host, localPort)

	alloyStoragePath := filepath.Join(dataHome, "alloy")
	if err := os.MkdirAll(alloyStoragePath, 0755); err != nil {
		panic(err)
	}

	event := warp.NewEvent()
	eventClose := event.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer eventClose()

	childWaitGroup := &sync.WaitGroup{}

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		lokiSettings := warp.DefaultChildSettings()
		// flush chunks to minio on stop
		lokiSettings.StopTimeout = 120 * time.Second
		warp.Child(event, "loki", lokiSettings, "/usr/local/sbin/loki", fmt.Sprintf("-config.file=%s", lokiConfigPath))
	}()

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		mimirSettings := warp.DefaultChildSettings()
		// flush blocks to minio on stop
		mimirSettings.StopTimeout = 120 * time.Second
		warp.Child(event, "mimir", mimirSettings, "/usr/local/sbin/mimir", fmt.Sprintf("-config.file=%s", mimirConfigPath))
	}()

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		grafanaSettings := warp.DefaultChildSettings()
		grafanaSettings.Username = "grafana"
		warp.Child(
			event,
			"grafana",
			grafanaSettings,
			"/usr/share/grafana/bin/grafana",
			"server",
			fmt.Sprintf("--config=%s", grafanaIniPath),
			"--homepath=/usr/share/grafana",
		)
	}()

	// a real, free loopback port for alloy (see pickAlloyHttpListenAddr)
	alloyHttpAddr := pickAlloyHttpListenAddr()
	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		warp.Child(
			event,
			"alloy",
			warp.DefaultChildSettings(),
			"/usr/bin/alloy",
			"run",
			fmt.Sprintf("--server.http.listen-addr=%s", alloyHttpAddr),
			fmt.Sprintf("--storage.path=%s", alloyStoragePath),
			"--disable-reporting",
			alloyConfigPath,
		)
	}()

	err := serve(event, env, &grafanaConfig, lokiHttpPort, grafanaHttpPort, mimirHttpPort, localPort, lokiRing, mimirRing)

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

// interpolateEnv expands `{{ env:KEY }}` in a config value. A referenced but
// unset env var panics: writing a loki/mimir config with a literal template
// as its s3 endpoint would fail far less legibly at runtime.
func interpolateEnv(value string) string {
	return envInterpolateRe.ReplaceAllStringFunc(value, func(match string) string {
		key := envInterpolateRe.FindStringSubmatch(match)[1]
		envValue := os.Getenv(key)
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
	minioHostname := interpolateEnv(minio.Hostname)
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

// ringHostsForService discovers, from the vault's services.yml at runtime, which
// hosts actually run `service`. warpservices.HostsForService reproduces warpctl's
// own placement rule (every lb interface host, minus host_services hosts that do
// not list the service, minus per-service host excludes), so this stays correct
// as the topology changes -- no hand-maintained peer list to drift.
//
// On any read/parse failure it falls back to every routed host, which is the
// previous behavior: memberlist tolerates dead seeds, so a degraded discovery
// still forms the ring rather than leaving loki/mimir with no peers.
func ringHostsForService(vaultHome string, env string, service string, hostSettings *HostSettings) []string {
	servicesConfig, err := warpservices.LoadServicesConfigFrom(vaultHome, env)
	if err != nil {
		warp.Err.Printf(
			"Ring discovery for %s falling back to all routes (could not load services.yml): %s\n",
			service,
			err,
		)
		hosts := []string{}
		for host := range hostSettings.Routes {
			hosts = append(hosts, host)
		}
		slices.Sort(hosts)
		return hosts
	}
	return warpservices.HostsForService(servicesConfig.Latest(), service)
}

// ringJoinMembers seeds the loki/mimir memberlist with ONLY the hosts that run
// the grafana bundle (see ringHostsForService), resolved to their route-net ip.
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

// startRingReusePortProxy proxies a ring port from the route net (all
// interfaces, SO_REUSEPORT) to the backend's unique internal port on loopback.
// grpc is tcp-only; memberlist gossip also needs udp.
func startRingReusePortProxy(event *warp.Event, externalPort int, internalPort int, gossip bool) {
	listenAddr := fmt.Sprintf(":%d", externalPort)
	backendAddr := fmt.Sprintf("127.0.0.1:%d", internalPort)
	go serveRingTcpProxy(event, listenAddr, backendAddr)
	if gossip {
		go serveRingUdpProxy(event, listenAddr, backendAddr)
	}
}

// serveRingTcpProxy owns a ring port on the route net with SO_REUSEPORT and
// proxies to the backend's internal port. It RETRIES the bind instead of
// failing the front: when deploying from a version that binds the port WITHOUT
// SO_REUSEPORT, the draining old container still holds it, so the new front
// must stay healthy on its main port and keep retrying until warp drains the
// old and the port frees. Once every version binds with SO_REUSEPORT the old
// and new coexist and there is no gap.
func serveRingTcpProxy(event *warp.Event, listenAddr string, backendAddr string) {
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
			go proxyRingTcp(client, backendAddr)
		}
		listener.Close()
		event.WaitForSet(1 * time.Second)
	}
}

func serveRingUdpProxy(event *warp.Event, listenAddr string, backendAddr string) {
	for !event.IsSet() {
		if err := proxyRingUdp(event, listenAddr, backendAddr); err != nil {
			warp.Err.Printf("Ring udp reuseport %s bind pending (%s); retrying\n", listenAddr, err)
			event.WaitForSet(2 * time.Second)
		}
	}
}

func proxyRingTcp(client net.Conn, backendAddr string) {
	defer client.Close()
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return
	}
	defer backend.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, client); done <- struct{}{} }()
	go func() { io.Copy(client, backend); done <- struct{}{} }()
	<-done
}

// proxyRingUdp relays memberlist gossip datagrams between the route-net
// reuseport socket and the backend's internal udp port, keeping a short-lived
// backend socket per client source address so replies route back.
func proxyRingUdp(event *warp.Event, listenAddr string, backendAddr string) error {
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
	var mu sync.Mutex

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := packetConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		key := clientAddr.String()
		mu.Lock()
		session := sessions[key]
		if session == nil {
			backend, dialErr := net.DialUDP("udp", nil, backendUdpAddr)
			if dialErr != nil {
				mu.Unlock()
				continue
			}
			session = &udpSession{backend: backend}
			sessions[key] = session
			go func(clientAddr net.Addr, session *udpSession) {
				replyBuf := make([]byte, 65535)
				for {
					session.backend.SetReadDeadline(time.Now().Add(60 * time.Second))
					replyN, readErr := session.backend.Read(replyBuf)
					if readErr != nil {
						mu.Lock()
						delete(sessions, clientAddr.String())
						mu.Unlock()
						session.backend.Close()
						return
					}
					packetConn.WriteTo(replyBuf[:replyN], clientAddr)
				}
			}(clientAddr, session)
		}
		session.backend.Write(buf[:n])
		mu.Unlock()
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
	retention := lokiSettings.Retention
	if retention == "" {
		retention = defaultRetention
	}

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
			// bind 0.0.0.0, not 127.0.0.1: the loki http api is reached only
			// through the go front's loopback proxy, but a 127.0.0.1-bound listener
			// is REFUSED on the edges (RST despite LISTEN) while 0.0.0.0-bound
			// sockets -- e.g. the grpc port below -- accept fine, including on
			// loopback. so the front proxy still reaches it via 127.0.0.1. this
			// leaves the api lan-reachable, like the front's own local port; the
			// wan is firewalled.
			"http_listen_address": "0.0.0.0",
			"http_listen_port":    lokiHttpPort,
			// bind all interfaces on the unique internal port: the lb stream
			// upstream proxies to WARP_HOST_IPV4 (services_docker_network), and
			// mimir/loki's own in-process query-frontend<->scheduler grpc dials
			// loopback, so neither is reachable if we bind lanIp only. ring peers
			// reach the stable external port on the host lan and the lb forwards
			// it here; the rings still advertise lanIp:<external> (instance_addr
			// / instance_port), not this listen address.
			"grpc_listen_address": "0.0.0.0",
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
			"bind_addr":      []string{"0.0.0.0"},
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
				// fails config parse ("field flush_on_shutdown not found in type
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
		"server": map[string]any{
			// bind 0.0.0.0, not 127.0.0.1 (see the matching note in
			// renderLokiConfig): a 127.0.0.1-bound http listener is refused on the
			// edges while 0.0.0.0 accepts on loopback too, so the front's
			// 127.0.0.1 proxy still reaches it. lan-reachable; the wan is firewalled.
			"http_listen_address": "0.0.0.0",
			"http_listen_port":    mimirHttpPort,
			// bind all interfaces on the unique internal port: the lb stream
			// upstream proxies to WARP_HOST_IPV4 (services_docker_network), and
			// mimir/loki's own in-process query-frontend<->scheduler grpc dials
			// loopback, so neither is reachable if we bind lanIp only. ring peers
			// reach the stable external port on the host lan and the lb forwards
			// it here; the rings still advertise lanIp:<external> (instance_addr
			// / instance_port), not this listen address.
			"grpc_listen_address": "0.0.0.0",
			"grpc_listen_port":    grpcListenPort,
		},
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
			"bind_addr":      []string{"0.0.0.0"},
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
			"tsdb": map[string]any{
				"dir": "/var/lib/mimir/tsdb",
			},
			"bucket_store": map[string]any{
				"sync_dir": "/var/lib/mimir/tsdb-sync",
			},
		},
		"ruler_storage": map[string]any{
			"storage_prefix": "ruler",
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
		"frontend": map[string]any{
			// NOTE the yaml keys are address/port even though the flags are
			// -frontend.instance-addr / -frontend.instance-port
			"address": lanIp,
			"port":    grpcPort,
		},
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

func renderGrafanaConfig(env string, domain string, lokiHttpPort int, grafanaHttpPort int, mimirHttpPort int, hostSettings *HostSettings, grafanaConfig *GrafanaConfig) string {
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

	var remoteCacheSection string
	if redis := grafanaConfig.Redis; redis != nil {
		redisHostname := redis.Hostname
		if redisHostname == "" {
			redisHostname = hostSettings.EnvVars["BRINGYOUR_REDIS_HOSTNAME"]
		}
		if redisHostname == "" {
			panic(errors.New("No redis hostname in grafana.yml or settings.yml env_vars."))
		}
		redisPort := redis.Port
		if redisPort == 0 {
			redisPort = 6379
		}
		connstrParts := []string{
			fmt.Sprintf("addr=%s:%d", redisHostname, redisPort),
			fmt.Sprintf("db=%d", redis.Database),
		}
		if redis.Password != "" {
			connstrParts = append(connstrParts, fmt.Sprintf("password=%s", redis.Password))
		}
		remoteCacheSection = strings.Join([]string{
			"[remote_cache]",
			"type = redis",
			fmt.Sprintf("connstr = %s", strings.Join(connstrParts, ",")),
		}, "\n")
	}

	grafanaHostname := fmt.Sprintf("%s-grafana.%s", env, domain)

	grafanaIni := fmt.Sprintf(`
[server]
protocol = http
; bind 0.0.0.0, not 127.0.0.1: a loopback-bound listener is refused on the edges
; (see renderLokiConfig); the front proxies to 127.0.0.1, which 0.0.0.0 serves. wan firewalled.
http_addr = 0.0.0.0
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

	datasources := map[string]any{
		"apiVersion": 1,
		"datasources": []any{
			map[string]any{
				"name":      "Loki",
				"uid":       "warp-loki",
				"type":      "loki",
				"access":    "proxy",
				"url":       fmt.Sprintf("http://127.0.0.1:%d", lokiHttpPort),
				"isDefault": false,
				"editable":  false,
			},
			map[string]any{
				"name":      "Mimir",
				"uid":       "warp-mimir",
				"type":      "prometheus",
				"access":    "proxy",
				"url":       fmt.Sprintf("http://127.0.0.1:%d/prometheus", mimirHttpPort),
				"isDefault": true,
				"editable":  false,
			},
		},
	}
	datasourcesYaml, err := yaml.Marshal(datasources)
	if err != nil {
		panic(err)
	}
	for _, provisioningDir := range []string{"datasources", "dashboards", "plugins", "alerting"} {
		if err := os.MkdirAll(filepath.Join(runDir, "provisioning", provisioningDir), 0755); err != nil {
			panic(err)
		}
	}
	writeFile(filepath.Join(runDir, "provisioning", "datasources", "loki.yml"), string(datasourcesYaml), 0644)

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

	// the grafana child runs as the grafana user
	if err := os.MkdirAll("/var/lib/grafana", 0755); err != nil {
		panic(err)
	}
	for _, chownArgs := range [][]string{
		{"chown", "-R", "grafana:grafana", "/var/lib/grafana"},
		{"chgrp", "grafana", grafanaIniPath},
	} {
		if out, err := exec.Command(chownArgs[0], chownArgs[1:]...).CombinedOutput(); err != nil {
			panic(errors.New(fmt.Sprintf("%s (%s)", string(out), err)))
		}
	}

	return grafanaIniPath
}

// alloy string literals use the same escaping as json strings
func alloyString(value string) string {
	return strconv.Quote(value)
}

func renderAlloyConfig(host string, lokiLocalPort int) string {
	// push to the stable local loki address, which the go front serves
	// with SO_REUSEPORT across redeployments.
	// the local loki replicates to the ring
	pushUrl := fmt.Sprintf("http://127.0.0.1:%d/loki/api/v1/push", lokiLocalPort)

	config := fmt.Sprintf(`
discovery.docker "warp" {
	host = "unix:///var/run/docker.sock"
	refresh_interval = "15s"
}

discovery.relabel "warp" {
	targets = []

	// only ship containers started by warp
	rule {
		source_labels = ["__meta_docker_container_label_warp_env"]
		regex = ".+"
		action = "keep"
	}

	rule {
		source_labels = ["__meta_docker_container_label_warp_env"]
		target_label = "env"
	}

	rule {
		source_labels = ["__meta_docker_container_label_warp_service"]
		target_label = "service"
	}

	rule {
		source_labels = ["__meta_docker_container_label_warp_block"]
		target_label = "block"
	}
}

loki.source.docker "warp" {
	host = "unix:///var/run/docker.sock"
	targets = discovery.docker.warp.targets
	relabel_rules = discovery.relabel.warp.rules
	labels = {
		host = %s,
	}
	forward_to = [loki.write.warp.receiver]
}

loki.write "warp" {
	endpoint {
		url = %s
	}
}
`,
		alloyString(host),
		alloyString(pushUrl),
	)

	alloyConfigPath := filepath.Join(runDir, "config.alloy")
	writeFile(alloyConfigPath, config, 0600)
	return alloyConfigPath
}

// the go http front

func serve(event *warp.Event, env string, grafanaConfig *GrafanaConfig, lokiHttpPort int, grafanaHttpPort int, mimirHttpPort int, localPort int, lokiRing ringProxyPorts, mimirRing ringProxyPorts) error {
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

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(status)
	})
	mux.Handle("/loki/api/v1/push", requireRole(grafanaConfig.Users, "push", lokiProxy))
	mux.Handle("/loki/", requireRole(grafanaConfig.Users, "query", lokiProxy))
	mux.Handle("/metrics/job/", requireRole(grafanaConfig.Users, "push", statsPushHandler))
	mux.Handle("/api/v1/push", requireRole(grafanaConfig.Users, "push", mimirProxy))
	mux.Handle("/prometheus/", requireRole(grafanaConfig.Users, "query", mimirProxy))
	mux.HandleFunc("/stats", publicStats.serveHtml)
	mux.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		serveStatsJson(w, r, publicStats, publicStatsFeed)
	})
	mux.Handle("/", grafanaProxy)

	server := &http.Server{
		Handler: mux,
		// no write timeout, to support tail
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	// the stable publish address (see `localPort`).
	// SO_REUSEPORT lets the old and new containers both serve this
	// during a redeployment overlap, each proxying to its own children.
	// bound on all interfaces (not just loopback) and unauthenticated: on-host
	// services push to 127.0.0.1:<localPort>, and hosts that don't run grafana
	// push to a grafana host's lan ip:<localPort> (see the localListenAddr note
	// below). the wan is firewalled, so lan exposure is acceptable here.
	localMux := http.NewServeMux()
	localMux.Handle("/loki/", lokiProxy)
	localMux.Handle("/metrics/job/", statsPushHandler)
	localMux.Handle("/api/v1/push", mimirProxy)
	localServer := &http.Server{
		Handler:           localMux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	// bind the main server on ALL interfaces (":<port-80 internal>"), NOT the
	// gateway ip that ServiceListenAddrs(80) returns. warpctl's readiness poll
	// hits WARP_HOST_IPV4:<port>/status, which a 0.0.0.0 listener serves -- but
	// binding the gateway ip specifically is refused during a redeploy overlap
	// (the same failure loki/mimir/grafana hit binding 127.0.0.1, now 0.0.0.0).
	// that refusal makes the new container fail its poll while the old one is
	// still up, and warpctl only drains the old container AFTER a passing poll
	// (see deploy() in warpctl/run.go), so the deploy deadlocks. the port is
	// unique per deploy so no SO_REUSEPORT is needed; dual-stack ":port" serves
	// ipv4 + ipv6.
	hostPort, err := warp.ServiceHostPort(80)
	if err != nil {
		return err
	}
	serveErrors := make(chan error, 2)
	go func() {
		listenAddr := fmt.Sprintf(":%d", hostPort)
		warp.Err.Printf("Listening on %s (all interfaces)\n", listenAddr)
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			serveErrors <- err
			return
		}
		serveErrors <- server.Serve(listener)
	}()
	go func() {
		// bind all interfaces (not just loopback) so hosts that do not run
		// grafana can push to this host's lan ip:<localPort> -- e.g. fluent-bit
		// on the db/redis/subtensor hosts reaches a grafana host via the
		// main-grafana.local /etc/hosts alias (see xops/main/ansible). the wan
		// is firewalled, and this port stays unauthenticated by design.
		localListenAddr := fmt.Sprintf(":%d", localPort)
		warp.Err.Printf("Listening on %s (reuseport, all interfaces)\n", localListenAddr)
		localListener, err := warp.ListenReusePort(localListenAddr)
		if err != nil {
			serveErrors <- err
			return
		}
		serveErrors <- localServer.Serve(localListener)
	}()

	// The loki/mimir ring ports (grpc + memberlist gossip) advertise the route
	// net address (lanIp) so peers reach them directly, like pg/redis/minio. But
	// loki/mimir cannot bind that port with SO_REUSEPORT, so the old and new
	// containers would collide on a redeploy. The front owns each ring port on
	// all interfaces with SO_REUSEPORT (old+new coexist; the kernel load-
	// balances) and proxies to the backend's unique-per-deploy internal port.
	// grpc is raw tcp; memberlist needs tcp (join/state sync) and udp (gossip).
	for _, r := range []ringProxyPorts{lokiRing, mimirRing} {
		startRingReusePortProxy(event, r.grpcExternal, r.grpcInternal, false)
		startRingReusePortProxy(event, r.gossipExternal, r.gossipInternal, true)
	}

	select {
	case <-event.Ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		localServer.Shutdown(shutdownCtx)
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
				if !slices.Contains(user.Roles, role) {
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
