package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	// "encoding/json"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	// "syscall"
	// "os/signal"
	"errors"
	"log"
	"regexp"
	"slices"

	"github.com/urnetwork/warp/warpctl/dynamo"
	"golang.org/x/exp/maps"

	"github.com/coreos/go-semver/semver"
	"github.com/docopt/docopt-go"
)

const WarpVersion = "0.0.1"

var Out *log.Logger
var Err *log.Logger

func init() {
	Out = log.New(os.Stdout, "", 0)
	Err = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lshortfile)
}

// TODO dns tools
func main() {
	usage := `Warp control. Fluid iteration and zero downtime continuous release.

Usage:
    warpctl init
        [--docker_namespace=<docker_namespace>]
        [--dockerhub_username=<dockerhub_username>]
        [--dockerhub_token=<dockerhub_token>]
        [--vault_home=<vault_home>]
        [--config_home=<config_home>]
        [--site_home=<site_home>]
    warpctl stage version (local | sync | next (beta | release) --message=<message>)
    warpctl build <env> <Makefile>
    warpctl import <env> <image> [--service_name=<service_name>]
    warpctl deploy <env> <service>
        (latest-local | latest-beta | latest | <version>)
        (<blocks>... | --percent=<percent>)
        [--only-older] [--timeout=<timeout>]
    warpctl deploy-local <env> <service> [--percent=<percent>]
    warpctl deploy-beta <env> <service> [--percent=<percent>]
    warpctl deploy-release <env> <service> [--percent=<percent>]
    warpctl watch <env> <service>
        (latest-local | latest-beta | latest | <version>)
        (<blocks>... | --percent=<percent>)
    warpctl ls version [-b] [-d]
    warpctl ls version-code
    warpctl ls services [<env>]
    warpctl ls service-blocks [<env> [<service>]]
    warpctl ls versions <env> [<service> [<blocks>...]] [--sample | --repo]
    warpctl lb blocks <env>
    warpctl lb hosts <env>
        [--envalias=<envalias>]
    warpctl lb create-config <env> [<block>]
        [--envalias=<envalias>]
        [--out=<outdir>]
    warpctl run-local <Makefile> [--envalias=<envalias>]
    warpctl service docker-networks <env>
    warpctl service routing-tables <env>
    warpctl service run <env> <service> <block>
        [--rttable=<rttable> --dockernet=<dockernet>]
        [--portblocks=<portblocks>]
        --services_dockernet=<services_dockernet>
        [--mount_vault=<mount_vault_mode>]
        [--mount_config=<mount_config_mode>]
        [--mount_site=<mount_site_mode>]
        [--status=<status_mode>]
        [--status-prefix=<status_prefix>]
        --domain=<domain>
        [--envvar=<envvar>...]
        [--arg=<arg>...]
    warpctl service drain <env> <service> <block>
        [--portblocks=<portblocks>]
    warpctl service create-units <env> [<service> [<block>]]
        [--target_warp_home=<target_warp_home>]
        [--target_warpctl=<target_warpctl>]
        [--out=<outdir>]
    warpctl service [down | up] <env> [<service> [<block>]]
    warpctl logs <env> [<service> [<blocks>...]]
    warpctl certs renew <env>

Options:
    -h --help                  Show this screen.
    --version                  Show version.
    --docker_namespace=<docker_namespace>      Your docker namespace. Docker repos are namespace/env-service.
    --dockerhub_username=<dockerhub_username>  Your dockerhub username.
    --dockerhub_token=<dockerhub_token>        Your dockerhub token.
    --vault_home=<vault_home>  Secure vault home. On your dev host, the services.yml will live at <vault_home>/<env>/services.yml
    --config_home=<config_home>    Config home.
    --site_home=<site_home>        Site home. These are files that exist only on this host
    --message=<message>        Version stage message.
    --percent=<percent>        Deploy to a percent of blocks, ordered lexicographically with beta first.
                               The block count is rounded up to the nearest int. 
    -b                         Include the build timestamp in the version. Use this for builds.
    -d                         Docker safe version (converts + to -).
    --portblocks=<portblocks>
    --rttable=<rttable>
    --dockernet=<dockernet>
    --services_dockernet=<services_dockernet>  
    --mount_vault=<mount_vault_mode>           One of: no, yes 
    --mount_config=<mount_config_mode>         One of: no, yes, root. Root mode allows the config to be written, e.g. the config-updater
    --mount_site=<mount_site_mode>             One of: no, yes
    --status=<status_mode>                     One of: no, standard
    --target_warp_home=<target_warp_home>      WARP_HOME for the unit.
    --outdir=<outdir>          Output dir.
    --arg=<arg>                Arg to pass to the service binary.
    --only-older               Only update blocks with entirely older versions.
    --repo                     List versions from the docker repo.
    --sample                   List versions from sampling deployed status (the method used by deploy).
    --timeout=<timeout>        Timeout in seconds.`

	opts, err := docopt.ParseArgs(usage, os.Args[1:], WarpVersion)
	if err != nil {
		panic(err)
	}

	if init_, _ := opts.Bool("init"); init_ {
		initWarp(opts)
	} else if stage, _ := opts.Bool("stage"); stage {
		if version, _ := opts.Bool("version"); version {
			stageVersion(opts)
		}
	} else if build_, _ := opts.Bool("build"); build_ {
		build(opts)
	} else if import_, _ := opts.Bool("import"); import_ {
		importImage(opts)
	} else if deploy_, _ := opts.Bool("deploy"); deploy_ {
		deploy(opts)
	} else if deployLocal_, _ := opts.Bool("deploy-local"); deployLocal_ {
		deployLocal(opts)
	} else if deployBeta_, _ := opts.Bool("deploy-beta"); deployBeta_ {
		deployBeta(opts)
	} else if deployRelease_, _ := opts.Bool("deploy-release"); deployRelease_ {
		deployRelease(opts)
	} else if ls, _ := opts.Bool("ls"); ls {
		if version, _ := opts.Bool("version"); version {
			lsVersion(opts)
		} else if versionCode, _ := opts.Bool("version-code"); versionCode {
			lsVersionCode(opts)
		} else if services, _ := opts.Bool("services"); services {
			lsServices(opts)
		} else if serviceBlocks, _ := opts.Bool("serviceBlocks"); serviceBlocks {
			lsServiceBlocks(opts)
		} else if versions, _ := opts.Bool("versions"); versions {
			lsVersions(opts)
		}
	} else if lb, _ := opts.Bool("lb"); lb {
		if blocks, _ := opts.Bool("blocks"); blocks {
			lbLsBlocks(opts)
		} else if hosts, _ := opts.Bool("hosts"); hosts {
			lbLsHosts(opts)
		} else if createConfig, _ := opts.Bool("create-config"); createConfig {
			lbCreateConfig(opts)
		}
	} else if service, _ := opts.Bool("service"); service {
		if run, _ := opts.Bool("run"); run {
			serviceRun(opts)
		} else if dockerNetworks_, _ := opts.Bool("docker-networks"); dockerNetworks_ {
			dockerNetworks(opts)
		} else if routingTables_, _ := opts.Bool("routing-tables"); routingTables_ {
			routingTables(opts)
		} else if createUnits_, _ := opts.Bool("create-units"); createUnits_ {
			createUnits(opts)
		}
	}
}

func initWarp(opts docopt.Opts) {
	state := getWarpState()

	if dockerNamespace, err := opts.String("--docker_namespace"); err == nil {
		if dockerNamespace == "" {
			state.warpSettings.DockerNamespace = nil
		} else {
			state.warpSettings.DockerNamespace = &dockerNamespace
		}
	}
	if dockerHubUsername, err := opts.String("--dockerhub_username"); err == nil {
		if dockerHubUsername == "" {
			state.warpSettings.DockerHubUsername = nil
		} else {
			state.warpSettings.DockerHubUsername = &dockerHubUsername
		}
	}
	if dockerHubToken, err := opts.String("--dockerhub_token"); err == nil {
		if dockerHubToken == "" {
			state.warpSettings.DockerHubToken = nil
		} else {
			state.warpSettings.DockerHubToken = &dockerHubToken
		}
	}
	if vaultHome, err := opts.String("--vault_home"); err == nil {
		if vaultHome == "" {
			state.warpSettings.VaultHome = nil
		} else {
			state.warpSettings.VaultHome = &vaultHome
		}
	}
	if configHome, err := opts.String("--config_home"); err == nil {
		if configHome == "" {
			state.warpSettings.ConfigHome = nil
		} else {
			state.warpSettings.ConfigHome = &configHome
		}
	}
	if siteHome, err := opts.String("--site_home"); err == nil {
		if siteHome == "" {
			state.warpSettings.SiteHome = nil
		} else {
			state.warpSettings.SiteHome = &siteHome
		}
	}

	setWarpState(state)
}

func stageVersion(opts docopt.Opts) {
	state := getWarpState()

	if local, _ := opts.Bool("local"); local {
		version := "local"
		state.versionSettings.StagedVersion = &version
		setWarpState(state)

		Out.Printf("%s (local)\n", state.getVersion(false, false))
	} else {
		sync, _ := opts.Bool("sync")
		next, _ := opts.Bool("next")

		if sync || next {
			var err error

			gitStashCommand := exec.Command("git", "stash", "-u")
			gitStashCommand.Dir = state.warpVersionHome
			err = runAndLog(gitStashCommand)
			if err != nil {
				panic(err)
			}

			gitPullCommand := exec.Command("git", "pull")
			gitPullCommand.Dir = state.warpVersionHome
			err = runAndLog(gitPullCommand)
			if err != nil {
				panic(err)
			}
		}

		if next {
			state = getWarpState()

			var version string
			var versionCode int

			beta, _ := opts.Bool("beta")
			release, _ := opts.Bool("release")

			if state.versionSettings.StagedVersion == nil {
				now := time.Now()
				year, month, day := now.Date()
				version = fmt.Sprintf("%d.%d.%d", year, month, day)
				versionCode = newVersionCode()
			} else if *state.versionSettings.StagedVersion == "local" {
				panic("Local version detected after sync. Manually revert the version to the previously staged beta or release version.")
			} else {
				now := time.Now()
				year, month, day := now.Date()
				stagedSemver := semver.New(*state.versionSettings.StagedVersion)
				if fmt.Sprintf("%d.%d", stagedSemver.Major, stagedSemver.Minor) == fmt.Sprintf("%d.%d", year, month) {
					if stagedSemver.PreRelease == "beta" && release {
						// moving from beta to release keeps the same patch
						version = fmt.Sprintf("%d.%d.%d", year, month, stagedSemver.Patch)
						if state.versionSettings.StagedVersionCode == nil {
							versionCode = newVersionCode()
						} else {
							versionCode = *state.versionSettings.StagedVersionCode
						}
					} else {
						version = fmt.Sprintf("%d.%d.%d", year, month, day)
						if state.versionSettings.StagedVersionCode == nil {
							versionCode = newVersionCode()
						} else {
							versionCode = max(
								newVersionCode(),
								*state.versionSettings.StagedVersionCode + 1,
							)
						}
					}
				} else {
					version = fmt.Sprintf("%d.%d.%d", year, month, day)
					if state.versionSettings.StagedVersionCode == nil {
						versionCode = newVersionCode()
					} else {
						versionCode = max(
							newVersionCode(),
							*state.versionSettings.StagedVersionCode + 1,
						)
					}
				}
			}

			if beta {
				version = fmt.Sprintf("%s-beta", version)
			}

			state.versionSettings.StagedVersion = &version
			state.versionSettings.StagedVersionCode = &versionCode
			setWarpState(state)

			var err error

			gitAddCommand := exec.Command("git", "add", "version.json")
			gitAddCommand.Dir = state.warpVersionHome
			err = runAndLog(gitAddCommand)
			if err != nil {
				panic(err)
			}

			message, _ := opts.String("--message")
			gitCommitCommand := exec.Command("git", "commit", "-m", message)
			gitCommitCommand.Dir = state.warpVersionHome
			err = runAndLog(gitCommitCommand)
			if err != nil {
				panic(err)
			}

			gitPushCommand := exec.Command("git", "push")
			gitPushCommand.Dir = state.warpVersionHome
			err = runAndLog(gitPushCommand)
			if err != nil {
				panic(err)
			}
		}

		Out.Printf("%s\n", state.getVersion(false, false))
	}
}

func build(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	makefile, _ := opts.String("<Makefile>")
	absMakefile, _ := filepath.Abs(makefile)

	if info, err := os.Stat(absMakefile); errors.Is(err, os.ErrNotExist) || !info.Mode().IsRegular() {
		panic(fmt.Sprintf("Makefile does not exist (%s)", absMakefile))
	}

	makefileName := filepath.Base(absMakefile)
	makfileDirPath := filepath.Dir(absMakefile)
	// the dir name is the service name
	service := filepath.Base(makfileDirPath)

	if makefileName != "Makefile" {
		panic("Makefile must point to file named Makefile")
	}

	state := getWarpState()
	version := state.getVersion(true, false)
	dockerVersion := convertVersionToDocker(version)

	envVars := map[string]string{
		"WARP_VAULT_HOME":       state.warpSettings.RequireVaultHome(),
		"WARP_CONFIG_HOME":      state.warpSettings.RequireConfigHome(),
		"WARP_SITE_HOME":        state.warpSettings.RequireSiteHome(),
		"WARP_VERSION":          version,
		"WARP_ENV":              env,
		"WARP_SERVICE":          service,
		"WARP_DOCKER_NAMESPACE": state.warpSettings.RequireDockerNamespace(),
		"WARP_DOCKER_IMAGE":     fmt.Sprintf("%s-%s", env, service),
		"WARP_DOCKER_VERSION":   dockerVersion,
	}

	makeCommand := exec.Command("make", "warp_build")
	makeCommand.Dir = makfileDirPath
	for _, envPair := range os.Environ() {
		makeCommand.Env = append(makeCommand.Env, envPair)
	}
	for key, value := range envVars {
		makeCommand.Env = append(makeCommand.Env, fmt.Sprintf("%s=%s", key, value))
	}
	makeCommand.Stdin = os.Stdin
	makeCommand.Stdout = os.Stdout
	makeCommand.Stderr = os.Stderr

	err := runAndLog(makeCommand)
	if err != nil {
		panic(err)
	}

	announceBuild(env, service, version)
}

func importImage(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	sourceImageName, _ := opts.String("<image>")

	var serviceName string
	if name, err := opts.String("--service_name"); err == nil {
		serviceName = name
	} else {
		serviceNameRegex := regexp.MustCompile("^(.*)/([^:]+):(.*)$")
		if groups := serviceNameRegex.FindStringSubmatch(sourceImageName); groups != nil {
			serviceName = groups[2]
		}
	}

	state := getWarpState()
	dockerVersion := state.getVersion(true, true)

	targetImageName := fmt.Sprintf(
		"%s/%s-%s:%s",
		state.warpSettings.RequireDockerNamespace(),
		env,
		serviceName,
		dockerVersion,
	)

	Out.Printf("Importing %s to %s\n", sourceImageName, targetImageName)

	cmd := docker("buildx", "imagetools", "create", "-t", targetImageName, sourceImageName)
	if err := runAndLog(cmd); err != nil {
		panic(err)
	}
}

func deploy(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	service, _ := opts.String("<service>")

	state := getWarpState()
	dockerHubClient := NewDockerHubClient(state)

	dc, err := dynamo.NewClient()
	if err != nil {
		panic(err)
	}

	var deployVersion string

	if version, err := opts.String("<version>"); err == nil {
		deployVersion = convertVersionFromDocker(version)
	} else {
		versionMeta, err := dockerHubClient.getVersionMeta(env, service)
		if err != nil {
			panic(err)
		}
		versions := versionMeta.versions
		semverSortWithBuild(versions)

		versionStrs := []string{}
		for _, version := range versions {
			versionStrs = append(versionStrs, version.String())
		}
		Err.Printf("All versions: %s\n", strings.Join(versionStrs, ", "))

		filteredVersions := []semver.Version{}

		if latestLocal, _ := opts.Bool("latest-local"); latestLocal {
			// keep only versions with pre release of this hostname
			hostname, err := os.Hostname()
			if err != nil {
				panic(err)
			}
			for _, version := range versions {
				if string(version.PreRelease) == hostname {
					filteredVersions = append(filteredVersions, version)
				}
			}
		} else if latestBeta, _ := opts.Bool("latest-beta"); latestBeta {
			// keep only versions with pre release of beta
			for _, version := range versions {
				if version.PreRelease == "beta" {
					filteredVersions = append(filteredVersions, version)
				}
			}
		} else if latest, _ := opts.Bool("latest"); latest {
			// keep only versions with no pre release
			for _, version := range versions {
				if version.PreRelease == "" {
					filteredVersions = append(filteredVersions, version)
				}
			}
		} else {
			panic("Unknown filter.")
		}

		if len(filteredVersions) == 0 {
			panic("No matching versions.")
		}

		filteredVersionStrs := []string{}
		for _, version := range filteredVersions {
			filteredVersionStrs = append(filteredVersionStrs, version.String())
		}
		Err.Printf("Filtered versions: %s\n", strings.Join(filteredVersionStrs, ", "))

		deployVersion = filteredVersions[len(filteredVersions)-1].String()
	}


	timeout := 120 * time.Second
	if timeoutStr, err := opts.String("--timeout"); err == nil {
		timeout, err = time.ParseDuration(timeoutStr)
		if err != nil {
			panic("Bad timeout.")
		}
	}

	Err.Printf("Selected version %s\n", deployVersion)

	orderedBlocks := getBlocks(env, service)
	slices.Sort(orderedBlocks)

	deployBlocks := []string{}

	if blocklist := opts["<blocks>"].([]string); 0 < len(blocklist) {
		blockmap := map[string]bool{}
		for _, block := range blocklist {
			blockmap[block] = true
		}
		for _, block := range orderedBlocks {
			if _, ok := blockmap[block]; ok {
				deployBlocks = append(deployBlocks, block)
			}
		}
	} else if percent, err := opts.Int("--percent"); err == nil {
		blockCount := int(math.Round(float64(len(orderedBlocks)) * float64(percent) / 100.0))
		deployBlocks = append(deployBlocks, orderedBlocks[:blockCount]...)
	}

	if len(deployBlocks) == 0 {
		panic("No matching blocks.")
	}

	if onlyOlder, _ := opts.Bool("--only-older"); onlyOlder {
		// poll the current block versions
		blockCurrentVersions := sampleBlockCurrentVersions(env, service, deployBlocks...)
		filteredDeployBlocks := []string{}
		for _, deployBlock := range deployBlocks {
			currentVersions, ok := blockCurrentVersions[deployBlock]
			if ok {
				// deploy version must be greater than all current versions
				all := true
				for currentVersion, _ := range currentVersions {
					if semverCmpWithBuild(*semver.New(deployVersion), currentVersion) <= 0 {
						all = false
						Err.Printf("[%s]Current version newer than deploy target %s <> %s. Will ignore this block.", deployBlock, currentVersion, deployVersion)
					}
				}
				if all {
					filteredDeployBlocks = append(filteredDeployBlocks, deployBlock)
				}
			} else {
				filteredDeployBlocks = append(filteredDeployBlocks, deployBlock)
			}
		}
		if len(filteredDeployBlocks) == 0 {
			Err.Printf("--only-older detected no older blocks than %s. Nothing to do.", deployVersion)
			return
		}
		deployBlocks = filteredDeployBlocks
	}

	announceDeployStarted(env, service, deployBlocks, deployVersion)

	for _, block := range deployBlocks {
		// remove tag <block>-latest from current image
		// tag target image with <block>-latest

		imageName := fmt.Sprintf(
			"%s/%s-%s",
			state.warpSettings.RequireDockerNamespace(),
			env,
			service,
		)

		sourceImageName := fmt.Sprintf(
			"%s:%s",
			imageName,
			convertVersionToDocker(deployVersion),
		)
		deployImageName := fmt.Sprintf(
			"%s:%s-latest",
			imageName,
			block,
		)

		cmd := docker("buildx", "imagetools", "create", "-t", deployImageName, sourceImageName)
		cmd.Dir = state.warpVersionHome
		if err := runAndLog(cmd); err != nil {
			panic(err)
		}

		err = dc.UpdateVersion(context.Background(), env, service, block, deployVersion)
		if err != nil {
			panic(err)
		}

		Err.Printf("Deployed %s -> %s\n", sourceImageName, deployImageName)
	}

	// the /status routes are only exposed via the load balancer internal routes
	// it's not possible to reach the status routes via the external hostname

	// poll the load balancer for the specific blocks until the versions stabilize
	Out.Printf("Block status:")
	pollLbBlockStatusUntil(env, service, deployBlocks, deployVersion, timeout)

	if reflect.DeepEqual(orderedBlocks, deployBlocks) {
		// poll the load balancer for all blocks until the version stabilizes
		Out.Printf("Service status:")
		pollLbServiceStatusUntil(env, service, deployVersion, timeout)
	}

	announceDeployEnded(env, service, deployBlocks, deployVersion)
}

func deployLocal(opts docopt.Opts) {
	opts["latest-local"] = true
	deploy(opts)
}

func deployBeta(opts docopt.Opts) {
	opts["latest-beta"] = true
	deploy(opts)
}

func deployRelease(opts docopt.Opts) {
	opts["latest"] = true
	deploy(opts)
}

func lsVersion(opts docopt.Opts) {
	build, _ := opts.Bool("-b")
	docker, _ := opts.Bool("-d")
	state := getWarpState()
	version := state.getVersion(build, docker)
	Out.Printf("%s\n", version)
}

func lsVersionCode(opts docopt.Opts) {
	state := getWarpState()
	versionCode := state.getVersionCode()
	Out.Printf("%d\n", versionCode)
}

func lsServices(opts docopt.Opts) {
	filterEnv, filterEnvErr := opts.String("<env>")
	includeEnv := func(env string) bool {
		return filterEnvErr != nil || filterEnv == env
	}

	state := getWarpState()
	dockerHubClient := NewDockerHubClient(state)

	serviceMeta, err := dockerHubClient.getServiceMeta()
	if err != nil {
		panic(err)
	}

	sort.Strings(serviceMeta.envs)
	sort.Strings(serviceMeta.services)

	for _, env := range serviceMeta.envs {
		if !includeEnv(env) {
			continue
		}
		for _, service := range serviceMeta.services {
			blocks := getBlocks(env, service)

			if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {
				var versionsSummary string
				if len(versionMeta.latestBlocks) == 0 {
					versionsSummary = "no deployed blocks"
				} else {
					count := 0
					versionCounts := map[semver.Version]int{}
					for _, version := range versionMeta.latestBlocks {
						count += 1
						versionCounts[version] += 1
					}
					versions := maps.Keys(versionCounts)
					semverSortWithBuild(versions)
					histoParts := []string{}
					for _, version := range versions {
						versionCount := versionCounts[version]
						histoPart := fmt.Sprintf("%.1f %s", 100.0*versionCount/count, version.String())
						histoParts = append(histoParts, histoPart)
					}

					blockParts := []string{}
					for _, block := range blocks {
						if version, ok := versionMeta.latestBlocks[block]; ok {
							blockPart := fmt.Sprintf("%s=%s", block, version.String())
							blockParts = append(blockParts, blockPart)
						}
					}

					versionsSummary = fmt.Sprintf(
						"%s: %s",
						strings.Join(histoParts, " "),
						strings.Join(blockParts, " "),
					)
				}

				Out.Printf("%s-%s (%s)\n", env, service, versionsSummary)
			}
		}
	}
}

func lsServiceBlocks(opts docopt.Opts) {
	filterEnv, filterEnvErr := opts.String("<env>")
	includeEnv := func(env string) bool {
		return filterEnvErr != nil || filterEnv == env
	}

	filterService, filterServiceErr := opts.String("<service>")
	includeService := func(service string) bool {
		return filterServiceErr != nil || filterService == service
	}

	state := getWarpState()
	dockerHubClient := NewDockerHubClient(state)

	serviceMeta, err := dockerHubClient.getServiceMeta()
	if err != nil {
		panic(err)
	}

	sort.Strings(serviceMeta.envs)
	sort.Strings(serviceMeta.services)
	sort.Strings(serviceMeta.blocks)

	for _, env := range serviceMeta.envs {
		if !includeEnv(env) {
			continue
		}
		for _, service := range serviceMeta.services {
			if !includeService(service) {
				continue
			}
			if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {
				for _, block := range serviceMeta.blocks {
					if blockVersion, ok := versionMeta.latestBlocks[block]; ok {
						Out.Printf("%s-%s %s %s\n", env, service, block, blockVersion.String())
					}
				}
			}
		}
	}
}

func lsVersions(opts docopt.Opts) {
	ctx := context.Background()

	env, _ := opts.String("<env>")

	filterService, filterServiceErr := opts.String("<service>")
	includeService := func(service string) bool {
		return filterServiceErr != nil || filterService == service
	}

	state := getWarpState()

	if repo, _ := opts.Bool("--repo"); repo {
		dockerHubClient := NewDockerHubClient(state)

		serviceMeta, err := dockerHubClient.getServiceMeta()
		if err != nil {
			panic(err)
		}

		sort.Strings(serviceMeta.envs)
		sort.Strings(serviceMeta.services)


		for _, service := range serviceMeta.services {
			if !includeService(service) {
				continue
			}
			if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {
				// summarize per base (MAJOR, MINOR, R) in MAJOR.MINOR.[p-P,p,p-P]-R+COUNT range format

				semverSortWithBuild(versionMeta.versions)

				baseVersionsMap := map[semver.Version][]semver.Version{}
				for _, version := range versionMeta.versions {
					baseVersion := semver.New(fmt.Sprintf("%d.%d.0-%s", version.Major, version.Minor, version.PreRelease))
					baseVersionsMap[*baseVersion] = append(baseVersionsMap[*baseVersion], version)
				}
				baseVersions := maps.Keys(baseVersionsMap)
				semverSortWithBuild(baseVersions)
				for _, baseVersion := range baseVersions {
					versions := baseVersionsMap[baseVersion]
					semverSortWithBuild(versions)
					patchParts := []string{}
					for i := 0; i < len(versions); {
						j := i + 1
						for ; j < len(versions) && (
						// multiple builds with the same patch
						versions[j-1].Patch == versions[j].Patch ||
							versions[j-1].Patch+1 == versions[j].Patch); j += 1 {
						}
						var patchPart string
						if versions[i].Patch == versions[j-1].Patch {
							// single
							patchPart = fmt.Sprintf("%d", versions[i].Patch)
						} else {
							// range
							patchPart = fmt.Sprintf("%d-%d", versions[i].Patch, versions[j-1].Patch)
						}
						patchParts = append(patchParts, patchPart)
						i = j
					}

					if baseVersion.PreRelease == "" {
						Out.Printf(
							"%s-%s %d.%d.[%s]+%d\n",
							env,
							service,
							baseVersion.Major,
							baseVersion.Minor,
							strings.Join(patchParts, ","),
							len(versions),
						)
					} else {
						Out.Printf(
							"%s-%s %d.%d.[%s]-%s+%d\n",
							env,
							service,
							baseVersion.Major,
							baseVersion.Minor,
							strings.Join(patchParts, ","),
							baseVersion.PreRelease,
							len(versions),
						)
					}
				}
			}
		}
	
	} else if sample, _ := opts.Bool("--sample"); sample {
		blocklist, _ := opts["<blocks>"].([]string)

		includeBlock := func(block string) bool {
			return len(blocklist) == 0 || slices.Contains(blocklist, block)
		}

		blockInfos := getBlockInfos(env)
		orderedServices := maps.Keys(blockInfos)
		slices.Sort(orderedServices)
		for _, service := range orderedServices {
			if includeService(service) {
				Out.Printf("[%s]\n", service)
				if service == "lb" {
					pollLbServiceStatusUntil(env, "lb", "", 0)
				} else {
					orderedBlocks := maps.Keys(blockInfos[service])
					slices.Sort(orderedBlocks)
					for _, block := range orderedBlocks {
						if includeBlock(block) {
							Out.Printf("[%s][%s]\n", service, block)
							pollLbBlockStatusUntil(env, service, []string{block}, "", 0)
						}
					}
				}
			}
		}
	} else {
		dynamoClient, err := dynamo.NewClient()
		if err != nil {
			panic(err)
		}

		blocklist, _ := opts["<blocks>"].([]string)

		includeBlock := func(block string) bool {
			return len(blocklist) == 0 || slices.Contains(blocklist, block)
		}

		blockInfos := getBlockInfos(env)
		orderedServices := maps.Keys(blockInfos)
		slices.Sort(orderedServices)
		for _, service := range orderedServices {
			if includeService(service) {
				Out.Printf("[%s]\n", service)
				orderedBlocks := maps.Keys(blockInfos[service])
				slices.Sort(orderedBlocks)
				for _, block := range orderedBlocks {
					if includeBlock(block) {
						latestVersion, err := dynamoClient.GetLatestVersion(ctx, env, service, block)
						if err != nil {
							panic(err)
						}
						Out.Printf("[%s][%s] %s\n", service, block, latestVersion)
					}
				}
			}
		}
	}
}

func lbLsBlocks(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	blockInfos := getBlockInfos(env)

	blocks := maps.Keys(blockInfos["lb"])
	sort.Strings(blocks)
	for _, block := range blocks {
		Out.Printf("%s\n", block)
	}
}

func lbLsHosts(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	envAliases := []string{}
	if envAlias, err := opts.String("--envalias"); err == nil {
		envAliases = append(envAliases, envAlias)
	}

	servicesConfig := getServicesConfig(env)

	services := maps.Keys(servicesConfig.Versions[0].Services)
	sort.Strings(services)
	for _, service := range services {
		Out.Printf("%s-%s.%s\n", env, service, servicesConfig.Domain)
		for _, envAlias := range envAliases {
			Out.Printf("%s-%s.%s\n", envAlias, service, servicesConfig.Domain)
		}
	}
}

func lbCreateConfig(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	envAliases := []string{}
	if envAlias, err := opts.String("--envalias"); err == nil {
		envAliases = append(envAliases, envAlias)
	}

	var includeBlocks []string
	if block, err := opts.String("<block>"); err == nil {
		includeBlocks = append(includeBlocks, block)
	} else {
		includeBlocks = []string{}
	}

	var outDir string
	if path, err := opts.String("--out"); err == nil {
		outDir = path
	} else {
		outDir = ""
	}

	nginxConfig, err := NewNginxConfig(env, envAliases)
	if err != nil {
		panic(err)
	}
	blockConfigs := nginxConfig.Generate()

	out := func(block string, config string) {
		if outDir == "" {
			Out.Println(templateString(`
            # block: {{.block}}

            {{.config}}

            `, map[string]any{
				"block":  block,
				"config": config,
			}))
		} else {
			// write to file
			// <dir>/<block>.conf
			unitFileName := fmt.Sprintf("%s.conf", block)
			err := os.WriteFile(
				filepath.Join(outDir, unitFileName),
				[]byte(config),
				0644,
			)
			if err != nil {
				panic(err)
			}
		}
	}

	includesBlock := func(block string) bool {
		if len(includeBlocks) == 0 {
			return true
		}
		return slices.Contains(includeBlocks, block)
	}

	for block, config := range blockConfigs {
		if !includesBlock(block) {
			continue
		}
		out(block, config)
	}
}

func serviceRun(opts docopt.Opts) {
	// note the options are usually generated by `serviceCreateUnit` which parses the service spec

	env, _ := opts.String("<env>")
	service, _ := opts.String("<service>")
	block, _ := opts.String("<block>")

	Err.Printf("Got %s, %s, %s\n", env, service, block)

	var portBlocks *PortBlocks
	if portBlocksStr, err := opts.String("--portblocks"); err == nil {
		portBlocks = parsePortBlocks(portBlocksStr)
	} else {
		// no service ports
		portBlocks = &PortBlocks{
			externalsToInternals: map[int][]int{},
			externalsToService:   map[int]int{},
		}
	}

	servicesDockerNetStr, _ := opts.String("--services_dockernet")
	servicesDockerNetwork := parseDockerNetwork(servicesDockerNetStr)

	var routingTable *RoutingTable
	var dockerNetwork *DockerNetwork

	if routingTableStr, err := opts.String("--rttable"); err == nil {
		routingTable = parseRoutingTable(routingTableStr)

		dockerNetStr, err := opts.String("--dockernet")
		if err != nil {
			panic(err)
		}
		dockerNetwork = parseDockerNetwork(dockerNetStr)
	}

	domain, _ := opts.String("--domain")

	var vaultMountMode string
	var configMountMode string
	var siteMountMode string

	if mode, err := opts.String("--mount_vault"); err == nil {
		switch mode {
		case MOUNT_MODE_YES, MOUNT_MODE_NO:
			vaultMountMode = mode
		default:
			panic(errors.New(fmt.Sprintf("Vault mount mode must be one of: %s, %s", MOUNT_MODE_YES, MOUNT_MODE_NO)))
		}
	} else {
		vaultMountMode = MOUNT_MODE_YES
	}

	if mode, err := opts.String("--mount_config"); err == nil {
		switch mode {
		case MOUNT_MODE_YES, MOUNT_MODE_NO, MOUNT_MODE_ROOT:
			configMountMode = mode
		default:
			panic(errors.New(fmt.Sprintf("Config mount mode must be one of: %s, %s, %s", MOUNT_MODE_YES, MOUNT_MODE_NO, MOUNT_MODE_ROOT)))
		}
	} else {
		configMountMode = MOUNT_MODE_YES
	}

	if mode, err := opts.String("--mount_site"); err == nil {
		switch mode {
		case MOUNT_MODE_YES, MOUNT_MODE_NO:
			siteMountMode = mode
		default:
			panic(errors.New(fmt.Sprintf("Site mount mode must be one of: %s, %s, %s", MOUNT_MODE_YES, MOUNT_MODE_NO, MOUNT_MODE_ROOT)))
		}
	} else {
		siteMountMode = MOUNT_MODE_YES
	}

	var statusMode string

	if mode, err := opts.String("--status"); err == nil {
		switch mode {
		case STATUS_MODE_STANDARD, STATUS_MODE_NO:
			statusMode = mode
		default:
			panic(errors.New(fmt.Sprintf("Status mode must be one of: %s, %s", STATUS_MODE_STANDARD, STATUS_MODE_NO)))
		}
	} else {
		statusMode = STATUS_MODE_STANDARD
	}

	var statusPrefix string
	if prefix, err := opts.String("--status-prefix"); err == nil {
		statusPrefix = prefix
	} else {
		statusPrefix = ""
	}

	envVars := map[string]string{}
	if pairs, ok := opts["--envvar"]; ok {
		for _, pair := range pairs.([]string) {
			parts := strings.SplitN(pair, ":", 2)
			if 2 != len(parts) {
				panic(fmt.Sprintf("Invalid envvar format. Must be key:value. (%s)", pair))
			}
			envVars[parts[0]] = parts[1]
		}
	}

	runArgs := []string{}
	if args, ok := opts["--arg"]; ok {
		runArgs = args.([]string)
	}

	state := getWarpState()
	dockerHubClient := NewDockerHubClient(state)

	// set home to the vault
	os.Setenv("HOME", state.warpSettings.RequireVaultHome())

	dc, err := dynamo.NewClient()
	if err != nil {
		panic(err)
	}

	runWorker := &RunWorker{
		warpState:             state,
		dockerHubClient:       dockerHubClient,
		dynamoClient:          dc,
		env:                   env,
		service:               service,
		block:                 block,
		portBlocks:            portBlocks,
		servicesDockerNetwork: servicesDockerNetwork,
		routingTable:          routingTable,
		dockerNetwork:         dockerNetwork,
		domain:                domain,
		runArgs:               runArgs,
		vaultMountMode:        vaultMountMode,
		configMountMode:       configMountMode,
		siteMountMode:         siteMountMode,
		statusMode:            statusMode,
		statusPrefix:          statusPrefix,
		envVars:               envVars,
	}
	runWorker.Run()
}

func dockerNetworks(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	hostNetworkCommands := getDockerNetworkCommands(env)

	for host, networkCommands := range hostNetworkCommands {
		Out.Printf("%s\n", host)
		for _, networkCommand := range networkCommands {
			Out.Printf("    %s\n", strings.Join(networkCommand, " "))
		}
	}
}

func routingTables(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	servicesConfig := getServicesConfig(env)

	Out.Printf("# /etc/iproute2/rt_tables\n")
	tableNumbers, err := expandAnyPorts(servicesConfig.Versions[0].RoutingTables)
	if err != nil {
		panic(err)
	}
	for _, tableNumber := range tableNumbers {
		Out.Printf("%d    warp%d\n", tableNumber, tableNumber)
	}
}

func createUnits(opts docopt.Opts) {
	env, _ := opts.String("<env>")

	var includeServices []string
	if service, err := opts.String("<service>"); err == nil {
		includeServices = []string{service}
	} else {
		includeServices = []string{}
	}

	var includeBlocks []string
	if block, err := opts.String("<block>"); err == nil {
		includeBlocks = []string{block}
	} else {
		includeBlocks = []string{}
	}

	var targetWarpHome string
	if path, err := opts.String("--target_warp_home"); err == nil {
		targetWarpHome = path
	} else {
		targetWarpHome = fmt.Sprintf("/srv/warp/%s", env)
	}

	var targetWarpctl string
	if path, err := opts.String("--target_warpctl"); err == nil {
		targetWarpctl = path
	} else {
		targetWarpctl = "/usr/local/sbin/warpctl"
	}

	var outDir string
	if path, err := opts.String("--out"); err == nil {
		outDir = path
	} else {
		outDir = ""
	}

	systemdUnits := NewSystemdUnits(
		env,
		targetWarpHome,
		targetWarpctl,
	)
	hostsServicesUnits := systemdUnits.Generate()

	out := func(host string, service string, block string, units *Units) {
		if outDir == "" {
			Out.Println(templateString(`
            # host: {{.host}}
            # service: {{.service}}
            # block: {{.block}}

            {{.unit}}

            `, map[string]any{
				"host":    host,
				"service": service,
				"block":   block,
				"unit":    units.serviceUnit,
			}))
		} else {
			// write to file
			// <dir>/<host>/warp-<env>-<service>-<shortBlock>.service
			hostDir := filepath.Join(outDir, host)
			os.MkdirAll(hostDir, 0755)
			unitFileName := fmt.Sprintf("warp-%s-%s-%s.service", env, service, units.shortBlock)
			err := os.WriteFile(
				filepath.Join(hostDir, unitFileName),
				[]byte(units.serviceUnit),
				0644,
			)
			if err != nil {
				panic(err)
			}
		}

		// FIXME drain unit
	}

	includesService := func(service string) bool {
		if len(includeServices) == 0 {
			return true
		}
		return slices.Contains(includeServices, service)
	}

	includesBlock := func(block string) bool {
		if len(includeBlocks) == 0 {
			return true
		}
		return slices.Contains(includeBlocks, block)
	}

	for host, servicesUnits := range hostsServicesUnits {
		for service, serviceUnits := range servicesUnits {
			if !includesService(service) {
				continue
			}
			for block, units := range serviceUnits {
				if !includesBlock(block) {
					continue
				}
				out(host, service, block, units)
			}
		}
	}
}
