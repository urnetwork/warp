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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp"
)

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

const defaultGossipPort = 23946
const defaultGrpcPort = 23095
const defaultMimirGossipPort = 23947
const defaultMimirGrpcPort = 23096
const defaultMinioPort = 23900
const defaultReplicationFactor = 3
const defaultRetention = "744h"
const defaultMimirRetention = "2160h"

// outside the warp external and internal port ranges
const alloyHttpPort = 23012

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
	GossipPort int    `yaml:"gossip_port,omitempty"`
	GrpcPort   int    `yaml:"grpc_port,omitempty"`
}

type MimirConfig struct {
	ReplicationFactor int    `yaml:"replication_factor,omitempty"`
	Retention         string `yaml:"retention,omitempty"`
	// see LokiConfig.MaxStorage
	MaxStorage string `yaml:"max_storage,omitempty"`
	GossipPort int    `yaml:"gossip_port,omitempty"`
	GrpcPort   int    `yaml:"grpc_port,omitempty"`
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
	dataHome := requireEnv("WARP_DATA")

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
	loadYaml(filepath.Join(vaultHome, env, "grafana.yml"), &grafanaConfig)

	lokiHttpPort := servicePortToHostPort(lokiServicePort)
	grafanaHttpPort := servicePortToHostPort(grafanaServicePort)
	mimirHttpPort := servicePortToHostPort(mimirServicePort)

	localPort := defaultLocalPort
	if grafanaConfig.LocalPort != 0 {
		localPort = grafanaConfig.LocalPort
	}

	lokiConfigPath := renderLokiConfig(host, lanIp, lokiHttpPort, hostSettings, &grafanaConfig)
	mimirConfigPath := renderMimirConfig(host, lanIp, mimirHttpPort, hostSettings, &grafanaConfig)
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

	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		warp.Child(
			event,
			"alloy",
			warp.DefaultChildSettings(),
			"/usr/bin/alloy",
			"run",
			fmt.Sprintf("--server.http.listen-addr=127.0.0.1:%d", alloyHttpPort),
			fmt.Sprintf("--storage.path=%s", alloyStoragePath),
			"--disable-reporting",
			alloyConfigPath,
		)
	}()

	err := serve(event, &grafanaConfig, lokiHttpPort, grafanaHttpPort, mimirHttpPort, localPort)

	// stop the children and wait for the loki flush
	event.Set()
	childWaitGroup.Wait()

	if err != nil {
		panic(err)
	}
}

func resolveMinioEndpoint(hostSettings *HostSettings, grafanaConfig *GrafanaConfig) (string, int) {
	minio := grafanaConfig.Minio
	if minio == nil {
		panic(errors.New("grafana.yml must have a minio section."))
	}
	// route the minio hostname over the host lan
	minioIp := minio.Hostname
	if routeIp, ok := hostSettings.Routes[minio.Hostname]; ok {
		minioIp = routeIp
	}
	minioPort := minio.Port
	if minioPort == 0 {
		minioPort = defaultMinioPort
	}
	return minioIp, minioPort
}

// every routed host is a potential ring peer.
// hosts that do not run the grafana service never register in the ring,
// and unreachable join members are skipped
func ringJoinMembers(hostSettings *HostSettings, gossipPort int) []string {
	joinMembers := []string{}
	for _, peerIp := range hostSettings.Routes {
		joinMembers = append(joinMembers, fmt.Sprintf("%s:%d", peerIp, gossipPort))
	}
	slices.Sort(joinMembers)
	return joinMembers
}

func renderLokiConfig(host string, lanIp string, lokiHttpPort int, hostSettings *HostSettings, grafanaConfig *GrafanaConfig) string {
	lokiSettings := grafanaConfig.Loki
	if lokiSettings == nil {
		lokiSettings = &LokiConfig{}
	}
	gossipPort := lokiSettings.GossipPort
	if gossipPort == 0 {
		gossipPort = defaultGossipPort
	}
	grpcPort := lokiSettings.GrpcPort
	if grpcPort == 0 {
		grpcPort = defaultGrpcPort
	}
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

	joinMembers := ringJoinMembers(hostSettings, gossipPort)

	lokiConfig := map[string]any{
		"auth_enabled": false,
		"server": map[string]any{
			// the loki api is exposed via the go http front only
			"http_listen_address": "127.0.0.1",
			"http_listen_port":    lokiHttpPort,
			// ring peers connect over the host lan
			"grpc_listen_address": lanIp,
			"grpc_listen_port":    grpcPort,
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
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
		"memberlist": map[string]any{
			"node_name":      host,
			"bind_addr":      []string{lanIp},
			"bind_port":      gossipPort,
			"advertise_addr": lanIp,
			"advertise_port": gossipPort,
			"join_members":   joinMembers,
			// the first instance to boot forms the cluster alone,
			// and periodic rejoin merges any startup race
			"abort_if_cluster_join_fails": false,
			"rejoin_interval":             "1m",
		},
		"ingester": map[string]any{
			// the wal does not survive redeploys.
			// flush all chunks to minio on stop, and rely on the
			// replication factor for unclean stops
			"flush_on_shutdown":    true,
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
			"reject_old_samples":          true,
			"reject_old_samples_max_age":  "168h",
			"query_timeout":               "2m",
		},
		"analytics": map[string]any{
			"reporting_enabled": false,
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

	return lokiConfigPath
}

func renderMimirConfig(host string, lanIp string, mimirHttpPort int, hostSettings *HostSettings, grafanaConfig *GrafanaConfig) string {
	mimirSettings := grafanaConfig.Mimir
	if mimirSettings == nil {
		mimirSettings = &MimirConfig{}
	}
	gossipPort := mimirSettings.GossipPort
	if gossipPort == 0 {
		gossipPort = defaultMimirGossipPort
	}
	grpcPort := mimirSettings.GrpcPort
	if grpcPort == 0 {
		grpcPort = defaultMimirGrpcPort
	}
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

	joinMembers := ringJoinMembers(hostSettings, gossipPort)

	mimirConfig := map[string]any{
		"target":               "all",
		"multitenancy_enabled": false,
		"usage_stats": map[string]any{
			"enabled": false,
		},
		"server": map[string]any{
			// the mimir api is exposed via the go http front only
			"http_listen_address": "127.0.0.1",
			"http_listen_port":    mimirHttpPort,
			// ring peers connect over the host lan
			"grpc_listen_address": lanIp,
			"grpc_listen_port":    grpcPort,
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
			"bind_addr":      []string{lanIp},
			"bind_port":      gossipPort,
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
				"kvstore": map[string]any{
					"store": "memberlist",
				},
			},
		},
		"distributor": map[string]any{
			"ring": map[string]any{
				"instance_addr": lanIp,
			},
		},
		"store_gateway": map[string]any{
			"sharding_ring": map[string]any{
				"replication_factor": replicationFactor,
				"instance_addr":      lanIp,
			},
		},
		"compactor": map[string]any{
			"data_dir": "/var/lib/mimir/compactor",
			"sharding_ring": map[string]any{
				"instance_addr": lanIp,
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

	return mimirConfigPath
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

func serve(event *warp.Event, grafanaConfig *GrafanaConfig, lokiHttpPort int, grafanaHttpPort int, mimirHttpPort int, localPort int) error {
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

	// the warp allocated ports are unique per deploy, so no SO_REUSEPORT
	listenAddrs, err := warp.ServiceListenAddrs(80)
	if err != nil {
		return err
	}

	serveErrors := make(chan error, 1+len(listenAddrs))
	for _, listenAddr := range listenAddrs {
		go func(listenAddr string) {
			warp.Err.Printf("Listening on %s\n", listenAddr)
			listener, err := net.Listen("tcp", listenAddr)
			if err != nil {
				serveErrors <- err
				return
			}
			serveErrors <- server.Serve(listener)
		}(listenAddr)
	}
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
