package main

// The lb process: one interface's nginx, and beside it lbmap (§13.4, W1,
// TLS-M6-01), which loads the custom-host map into the SNI split. lbmap runs
// only when the config renders the split, which carries lbmap's marker, and
// a credential is mounted. Without either nginx runs as it always has, and no
// custom host routes through this interface, which then counts as current
// for no version: the closed direction.
//
// The order at start: the run directory, the config nginx runs (converted
// under host networking), lbmap's load of the newest version, bounded so the
// dns API being down cannot hold nginx back, then nginx, then lbmap's loop.
// A stop signal ends lbmap before nginx drains, so no reload lands on a
// draining master.
//
// A block runs with the paths and windows below unset. A test that runs the
// process against a real nginx (server's TLS-M6-07 T3) points it elsewhere:
// WARP_LB_CONFIG_DIR for /srv/warp/nginx.conf, WARP_LB_RUN_DIR for
// /run/warp-lb, whose socket and includes the config names, and
// WARP_LBMAP_LOAD_DELAY, WARP_LBMAP_RELOAD_MIN_INTERVAL,
// WARP_LBMAP_START_TIMEOUT, WARP_LBMAP_POLL_TIMEOUT and
// WARP_LBMAP_POLL_MIN_INTERVAL, Go durations, for LbMapSettings' §13.4
// windows, so its windows are short values in LbMapSettings rather than the
// 5 s and 15 min a block keeps. A value that does not parse stops the
// process, as a block's own misconfiguration would.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/urnetwork/warp"
)

// Where a block's nginx configs are, one <block>.conf each.
const lbConfigDir = "/srv/warp/nginx.conf"

// The environment's paths and lbmap windows, with a block's defaults.
type lbEnvironment struct {
	configDir   string
	runDir      string
	lbMapConfig *warp.LbMapSettings
}

// The environment as getenv reads it: unset keys keep a block's defaults, and
// a duration that does not parse, or one LbMapSettings refuses, is an error.
func readLbEnvironment(getenv func(string) string) (*lbEnvironment, error) {
	environment := &lbEnvironment{
		configDir:   lbConfigDir,
		runDir:      warp.LbRunDir,
		lbMapConfig: warp.DefaultLbMapSettings(),
	}
	if configDir := getenv("WARP_LB_CONFIG_DIR"); configDir != "" {
		environment.configDir = configDir
	}
	if runDir := getenv("WARP_LB_RUN_DIR"); runDir != "" {
		environment.runDir = runDir
	}
	for key, target := range map[string]*time.Duration{
		"WARP_LBMAP_LOAD_DELAY":          &environment.lbMapConfig.LoadDelay,
		"WARP_LBMAP_RELOAD_MIN_INTERVAL": &environment.lbMapConfig.ReloadMinInterval,
		"WARP_LBMAP_START_TIMEOUT":       &environment.lbMapConfig.StartTimeout,
		"WARP_LBMAP_POLL_TIMEOUT":        &environment.lbMapConfig.PollTimeout,
		"WARP_LBMAP_POLL_MIN_INTERVAL":   &environment.lbMapConfig.PollMinInterval,
	} {
		value := getenv(key)
		if value == "" {
			continue
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		*target = duration
	}
	if err := environment.lbMapConfig.Validate(); err != nil {
		return nil, err
	}
	return environment, nil
}

// One of the split's run files, under the run directory.
func (self *lbEnvironment) runPath(path string) string {
	return filepath.Join(self.runDir, filepath.Base(path))
}

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

func main() {
	block := os.Getenv("WARP_BLOCK")
	if block == "" {
		panic(errors.New("WARP_BLOCK must be set."))
	}

	environment, err := readLbEnvironment(os.Getenv)
	if err != nil {
		panic(err)
	}
	configPath := filepath.Join(environment.configDir, fmt.Sprintf("%s.conf", block))
	convertedConfigPath := filepath.Join(environment.configDir, fmt.Sprintf("%s_host.conf", block))

	// §13.4's split (W1) names a socket and two includes under the run
	// directory, which must be there, and the socket gone, before nginx starts.
	// An lb without the split never reads them.
	if err := warp.PrepareLbRunDir(environment.runDir); err != nil {
		panic(err)
	}

	stop := warp.NewEvent()
	closeSignals := stop.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)

	runConfigPath, err := warp.NginxRunConfigPath(configPath, convertedConfigPath)
	if err != nil {
		panic(err)
	}
	nginx := warp.NewNginxProcess(runConfigPath, warp.DefaultNginxSettings())

	// lbmap's context ends at the stop signal, before nginx's drain starts
	lbMap := newLbMap(stop.Ctx, block, runConfigPath, nginx, environment)
	if lbMap != nil {
		// nginx starts whatever the load says; it logs its own failure
		lbMap.LoadBeforeStart()
	}
	if err := nginx.Start(stop.Ctx); err != nil {
		panic(err)
	}
	if lbMap != nil {
		go lbMap.Run()
	}
	err, exitCode := nginx.Wait()
	stop.Set()
	closeSignals()
	if err != nil {
		panic(err)
	}
	os.Exit(exitCode)
}

// The lbmap beside this interface's nginx, or nil when it has nothing to do,
// the config rendering no split, or cannot run: no credential
// (plan-TLS-internal-credentials: a client refuses to start without one), no
// domain to find the dns API under, or a config it cannot read. Each nil but
// the first is logged.
//
// The dns API is https://dns.<WARP_DOMAIN> (§12.6's dns API blocks), and the
// credential internal-lbmap.yml in the lb's secret_files. WARP_LBMAP_API_URL
// and WARP_LBMAP_CREDENTIAL point a test run elsewhere.
func newLbMap(ctx context.Context, block string, runConfigPath string, nginx warp.NginxControl, environment *lbEnvironment) *warp.LbMap {
	off := func(format string, arguments ...any) *warp.LbMap {
		warp.Err.Printf("[lbmap] off, so no custom host routes through this interface's split and it is current for no version: "+format, arguments...)
		return nil
	}
	config, err := os.ReadFile(runConfigPath)
	if err != nil {
		return off("read the config: %s", err)
	}
	renderConfig, err := warp.FindLbMapRenderConfig(config)
	if err != nil {
		return off("the config's marker: %s", err)
	}
	if renderConfig == nil {
		// no split, so nothing to load
		return nil
	}
	credentialPath := os.Getenv("WARP_LBMAP_CREDENTIAL")
	if credentialPath == "" {
		credentialPath = warp.LbMapCredentialPath
	}
	credentialData, err := os.ReadFile(credentialPath)
	if err != nil {
		return off("no credential at %s", credentialPath)
	}
	credential, err := warp.LoadLbMapCredential(credentialData)
	if err != nil {
		return off("%s", err)
	}
	domain := os.Getenv("WARP_DOMAIN")
	apiUrl := os.Getenv("WARP_LBMAP_API_URL")
	if apiUrl == "" {
		if domain == "" {
			return off("no WARP_DOMAIN to find the dns api under")
		}
		apiUrl = "https://dns." + domain
	}
	settings := environment.lbMapConfig
	// no client timeout: each call's context bounds it, on lbmap's clock
	api, err := warp.NewLbMapHttpApi(apiUrl, credential, &http.Client{}, settings)
	if err != nil {
		return off("%s", err)
	}
	lbMap, err := warp.NewLbMap(ctx, &warp.LbMapConfig{
		Interface:  warp.LbMapInterfaceName(block, domain),
		MapPath:    environment.runPath(warp.LbTlsCustomHostsMapPath),
		Http80Path: environment.runPath(warp.LbTlsCustomHosts80Path),
		Render:     renderConfig,
	}, settings, api, nginx)
	if err != nil {
		return off("%s", err)
	}
	return lbMap
}
