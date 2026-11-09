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

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"syscall"

	"github.com/urnetwork/warp"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

func main() {
	block := os.Getenv("WARP_BLOCK")
	if block == "" {
		panic(errors.New("WARP_BLOCK must be set."))
	}

	configPath := fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", block)
	convertedConfigPath := fmt.Sprintf("/srv/warp/nginx.conf/%s_host.conf", block)

	// §13.4's split (W1) names a socket and two includes under the run
	// directory, which must be there, and the socket gone, before nginx starts.
	// An lb without the split never reads them.
	if err := warp.PrepareLbRunDir(warp.LbRunDir); err != nil {
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
	lbMap := newLbMap(stop.Ctx, block, runConfigPath, nginx)
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
func newLbMap(ctx context.Context, block string, runConfigPath string, nginx warp.NginxControl) *warp.LbMap {
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
	settings := warp.DefaultLbMapSettings()
	// no client timeout: each call's context bounds it, on lbmap's clock
	api, err := warp.NewLbMapHttpApi(apiUrl, credential, &http.Client{}, settings)
	if err != nil {
		return off("%s", err)
	}
	lbMap, err := warp.NewLbMap(ctx, &warp.LbMapConfig{
		Interface:  warp.LbMapInterfaceName(block, domain),
		MapPath:    warp.LbTlsCustomHostsMapPath,
		Http80Path: warp.LbTlsCustomHosts80Path,
		Render:     renderConfig,
	}, settings, api, nginx)
	if err != nil {
		return off("%s", err)
	}
	return lbMap
}
