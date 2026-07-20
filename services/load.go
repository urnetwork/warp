package services

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultWarpHome mirrors server/env.go DefaultWarpHome.
var DefaultWarpHome = "/srv/warp"

// warpHome replicates server/env.go WarpHome (this package deliberately does not
// import github.com/urnetwork/server, which is a different module).
func warpHome() string {
	if warpHome := os.Getenv("WARP_HOME"); warpHome != "" {
		return warpHome
	}
	return DefaultWarpHome
}

// vaultHomeRoot replicates server/env.go VaultHomeRoot.
func vaultHomeRoot() string {
	if warpVaultHome := os.Getenv("WARP_VAULT_HOME"); warpVaultHome != "" {
		return warpVaultHome
	}
	return filepath.Join(warpHome(), "vault")
}

// resolveVaultPath returns <vaultDir>/<env>/<name> when that env-specific file
// exists (local dev layout), else <vaultDir>/<name> (a warp container mounts the
// env-specific vault directly at the root).
func resolveVaultPath(vaultDir string, env string, name string) string {
	envPath := filepath.Join(vaultDir, env, name)
	if _, err := os.Stat(envPath); err == nil {
		return envPath
	}
	return filepath.Join(vaultDir, name)
}

// LoadServicesConfigFrom reads and parses the services config for env out of vaultDir.
func LoadServicesConfigFrom(vaultDir string, env string) (*ServicesConfig, error) {
	servicesConfigPath := resolveVaultPath(vaultDir, env, "services.yml")
	data, err := os.ReadFile(servicesConfigPath)
	if err != nil {
		return nil, err
	}

	var servicesConfig ServicesConfig
	if err := yaml.Unmarshal(data, &servicesConfig); err != nil {
		return nil, err
	}

	if len(servicesConfig.Versions) == 0 {
		return nil, fmt.Errorf("services config %s has no versions", servicesConfigPath)
	}

	// add a default config-updater if not defined
	if servicesConfig.Versions[0].Services == nil {
		servicesConfig.Versions[0].Services = map[string]*ServiceConfig{}
	}
	if _, ok := servicesConfig.Versions[0].Services["config-updater"]; !ok {
		exposed := false
		lbExposed := false
		servicesConfig.Versions[0].Services["config-updater"] = &ServiceConfig{
			Exposed:   &exposed,
			LbExposed: &lbExposed,
			Blocks: []map[string]int{
				map[string]int{"main": 1},
			},
		}
	}

	return &servicesConfig, nil
}

// LoadServicesConfig reads and parses the services config for env, resolving the
// vault dir from the environment (WARP_VAULT_HOME, else WARP_HOME/vault, else
// /srv/warp/vault).
func LoadServicesConfig(env string) (*ServicesConfig, error) {
	return LoadServicesConfigFrom(vaultHomeRoot(), env)
}

// LoadGrafanaConfigFrom reads and parses the grafana config for env out of vaultDir.
func LoadGrafanaConfigFrom(vaultDir string, env string) (*GrafanaConfig, error) {
	grafanaConfigPath := resolveVaultPath(vaultDir, env, "grafana.yml")
	data, err := os.ReadFile(grafanaConfigPath)
	if err != nil {
		return nil, err
	}

	var grafanaConfig GrafanaConfig
	if err := yaml.Unmarshal(data, &grafanaConfig); err != nil {
		return nil, err
	}

	return &grafanaConfig, nil
}

// LoadGrafanaConfig reads and parses the grafana config for env, resolving the
// vault dir from the environment (see LoadServicesConfig).
func LoadGrafanaConfig(env string) (*GrafanaConfig, error) {
	return LoadGrafanaConfigFrom(vaultHomeRoot(), env)
}
