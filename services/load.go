package services

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/coreos/go-semver/semver"
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

// Mirrors the warpctl config-root convention without importing that child
// package into its parent service/config package.
func configHomeRoot() string {
	if warpConfigHome := os.Getenv("WARP_CONFIG_HOME"); warpConfigHome != "" {
		return warpConfigHome
	}
	return filepath.Join(warpHome(), "config")
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

// Supports source-tree, container-root, and host version-directory layouts,
// choosing the newest semantic config version in the latter case.
func resolveConfigPath(configDir string, env string, name string) (string, error) {
	for _, configPath := range []string{
		filepath.Join(configDir, env, name),
		filepath.Join(configDir, name),
	} {
		if configInfo, err := os.Stat(configPath); err == nil && configInfo.Mode().IsRegular() {
			return configPath, nil
		}
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		return "", err
	}
	versionNames := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			if _, err := semver.NewVersion(entry.Name()); err == nil {
				versionNames = append(versionNames, entry.Name())
			}
		}
	}
	slices.SortFunc(versionNames, func(a string, b string) int {
		aVersion, _ := semver.NewVersion(a)
		bVersion, _ := semver.NewVersion(b)
		if aVersion.LessThan(*bVersion) {
			return -1
		}
		if bVersion.LessThan(*aVersion) {
			return 1
		}
		return strings.Compare(a, b)
	})
	for versionIndex := len(versionNames) - 1; 0 <= versionIndex; versionIndex -= 1 {
		configPath := filepath.Join(configDir, versionNames[versionIndex], name)
		if configInfo, err := os.Stat(configPath); err == nil && configInfo.Mode().IsRegular() {
			return configPath, nil
		}
	}
	return "", fmt.Errorf("config file %q not found beneath %s", name, configDir)
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

	for versionIndex, version := range servicesConfig.Versions {
		for service, serviceConfig := range version.Services {
			if _, err := version.ResolveCorsOrigins(service); err != nil {
				return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
			}
			if serviceConfig.CapNetAdmin && service != "proxy" {
				return nil, fmt.Errorf("services config %s version %d: service %q grants cap_net_admin; only proxy may request it", servicesConfigPath, versionIndex, service)
			}
			if serviceConfig.Mount["docker"] == "yes" {
				return nil, fmt.Errorf("services config %s version %d: service %q requests the forbidden Docker API mount", servicesConfigPath, versionIndex, service)
			}
			seenSecretFiles := map[string]bool{}
			for _, secretFile := range serviceConfig.SecretFiles {
				if secretFile == "" || filepath.Base(secretFile) != secretFile || !filepath.IsLocal(secretFile) {
					return nil, fmt.Errorf("services config %s version %d: service %q has unsafe secret file %q", servicesConfigPath, versionIndex, service, secretFile)
				}
				if seenSecretFiles[secretFile] {
					return nil, fmt.Errorf("services config %s version %d: service %q repeats secret file %q", servicesConfigPath, versionIndex, service, secretFile)
				}
				seenSecretFiles[secretFile] = true
			}
			if !slices.IsSorted(serviceConfig.SecretFiles) {
				return nil, fmt.Errorf("services config %s version %d: service %q secret_files must be sorted", servicesConfigPath, versionIndex, service)
			}
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

// Loads names/roles from ordinary config and overlays only matching passwords
// from the scoped vault file.
func LoadGrafanaConfigFrom(configDir string, vaultDir string, env string) (*GrafanaConfig, error) {
	grafanaConfigPath, err := resolveConfigPath(configDir, env, "grafana.yml")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(grafanaConfigPath)
	if err != nil {
		return nil, err
	}

	var grafanaConfig GrafanaConfig
	if err := yaml.Unmarshal(data, &grafanaConfig); err != nil {
		return nil, err
	}
	secretPath := resolveVaultPath(vaultDir, env, "grafana.yml")
	secretData, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, err
	}
	var secretConfig GrafanaConfig
	if err := yaml.Unmarshal(secretData, &secretConfig); err != nil {
		return nil, err
	}

	configUsers := map[string]*GrafanaServiceUser{}
	for _, configUser := range grafanaConfig.Users {
		if configUser == nil || configUser.Name == "" {
			return nil, fmt.Errorf("Grafana config %s has an unnamed service user", grafanaConfigPath)
		}
		if configUser.Password != "" {
			return nil, fmt.Errorf("Grafana config %s contains password for %q", grafanaConfigPath, configUser.Name)
		}
		if configUsers[configUser.Name] != nil {
			return nil, fmt.Errorf("Grafana config %s repeats service user %q", grafanaConfigPath, configUser.Name)
		}
		configUsers[configUser.Name] = configUser
	}
	secretUsers := map[string]bool{}
	for _, secretUser := range secretConfig.Users {
		if secretUser == nil || secretUser.Name == "" {
			return nil, fmt.Errorf("Grafana secret %s has an unnamed service user", secretPath)
		}
		if 0 < len(secretUser.Roles) {
			return nil, fmt.Errorf("Grafana secret %s contains roles for %q", secretPath, secretUser.Name)
		}
		if secretUsers[secretUser.Name] {
			return nil, fmt.Errorf("Grafana secret %s repeats service user %q", secretPath, secretUser.Name)
		}
		secretUsers[secretUser.Name] = true
		configUser := configUsers[secretUser.Name]
		if configUser == nil {
			return nil, fmt.Errorf("Grafana secret user %q is absent from ordinary config", secretUser.Name)
		}
		configUser.Password = secretUser.Password
	}

	return &grafanaConfig, nil
}

// Resolves both ordinary config and vault roots from the environment.
func LoadGrafanaConfig(env string) (*GrafanaConfig, error) {
	return LoadGrafanaConfigFrom(configHomeRoot(), vaultHomeRoot(), env)
}
