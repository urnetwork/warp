package main

import (
	"fmt"
	"io"
	"os"
	// "os/exec"
	"encoding/json"
	"path/filepath"
	"time"
	// "strings"
	// "math"
	"net"
	"net/http"
	"regexp"
	// "context"
	"bytes"
	"strings"
	"sync"

	"golang.org/x/exp/maps"
	// "golang.org/x/sync/semaphore"

	"github.com/coreos/go-semver/semver"

	"github.com/urnetwork/warp"
)

// see https://docs.docker.com/docker-hub/api/deprecated/

func newLocalVersion() string {
	host, err := os.Hostname()
	if err != nil {
		host = "nohost"
	}
	now := time.Now()
	year, month, day := now.Date()
	return fmt.Sprintf("%d.%d.%d-%s", year, month, day, host)
}

func newVersionCode() int {
	// seconds since company founding
	companyFoundedTime, err := time.Parse(time.DateOnly, "2023-05-23")
	if err != nil {
		panic(err)
	}
	secondsSince := time.Now().Sub(companyFoundedTime) / time.Second
	// leave a 0 at the end of the base version code so that we can add in various flavors if needed
	return int(secondsSince * 10)
}

type WarpState struct {
	warpHome        string
	warpVersionHome string
	warpSettings    *WarpSettings
	versionSettings *VersionSettings
}

func (self *WarpState) getVersion(build bool, docker bool) string {
	stagedVersion := self.versionSettings.StagedVersion

	var version string
	if stagedVersion == nil || *stagedVersion == "local" {
		version = newLocalVersion()
	} else {
		version = *stagedVersion
	}

	if build {
		stagedVersionCode := self.versionSettings.StagedVersionCode
		if stagedVersion == nil || *stagedVersion == "local" {
			version = fmt.Sprintf("%s+%d", version, newVersionCode())
		} else {
			version = fmt.Sprintf("%s+%d", version, *stagedVersionCode)
		}
	}

	if docker {
		version = convertVersionToDocker(version)
	}

	return version
}

func (self *WarpState) getVersionCode() int {
	stagedVersionCode := self.versionSettings.StagedVersionCode
	if stagedVersionCode != nil {
		return *stagedVersionCode
	} else {
		return newVersionCode()
	}
}

type WarpSettings struct {
	DockerNamespace   *string `json:"dockerNamespace,omitempty"`
	DockerHubUsername *string `json:"dockerHubUsername,omitempty"`
	DockerHubToken    *string `json:"dockerHubToken,omitempty"`
	VaultHome         *string `json:"vaultHome,omitempty"`
	ConfigHome        *string `json:"configHome,omitempty"`
	SiteHome          *string `json:"siteHome,omitempty"`
}

func (self *WarpSettings) RequireDockerNamespace() string {
	if self.DockerNamespace == nil {
		panic("WARP_DOCKER_NAMESPACE is not set. Use warpctl init.")
	}
	return *self.DockerNamespace
}

func (self *WarpSettings) RequireDockerHubUsername() string {
	if self.DockerHubUsername == nil {
		panic("WARP_DOCKER_HUB_USERNAME is not set. Use warpctl init.")
	}
	return *self.DockerHubUsername
}

func (self *WarpSettings) RequireDockerHubToken() string {
	if self.DockerHubToken == nil {
		panic("WARP_DOCKER_HUB_TOKEN is not set. Use warpctl init.")
	}
	return *self.DockerHubToken
}

func (self *WarpSettings) RequireWarpHome() string {
	warpHome := os.Getenv("WARP_HOME")
	if warpHome != "" {
		return warpHome
	}
	panic("WARP_HOME is not set. Use warpctl init.")
}

func (self *WarpSettings) RequireVaultHome() string {
	if self.VaultHome != nil {
		return *self.VaultHome
	}
	warpVaultHome := os.Getenv("WARP_VAULT_HOME")
	if warpVaultHome != "" {
		return warpVaultHome
	}
	return filepath.Join(self.RequireWarpHome(), "vault")
}

func (self *WarpSettings) RequireConfigHome() string {
	if self.ConfigHome != nil {
		return *self.ConfigHome
	}
	warpConfigHome := os.Getenv("WARP_CONFIG_HOME")
	if warpConfigHome != "" {
		return warpConfigHome
	}
	return filepath.Join(self.RequireWarpHome(), "config")
}

func (self *WarpSettings) RequireSiteHome() string {
	if self.SiteHome != nil {
		return *self.SiteHome
	}
	warpSiteHome := os.Getenv("WARP_SITE_HOME")
	if warpSiteHome != "" {
		return warpSiteHome
	}
	return filepath.Join(self.RequireWarpHome(), "site")
}

type VersionSettings struct {
	StagedVersion *string `json:"stagedVersion,omitempty"`
	StagedVersionCode *int `json:"stagedVersionCode,omitempty"`
}

func getWarpState() *WarpState {
	warpHome := os.Getenv("WARP_HOME")
	if warpHome == "" {
		panic("WARP_HOME must be set.")
	}
	warpVersionHome := os.Getenv("WARP_VERSION_HOME")
	if warpVersionHome == "" {
		warpVersionHome = warpHome
	}

	var err error

	var warpSettings WarpSettings
	warpJson, err := os.ReadFile(filepath.Join(warpHome, "warp.json"))
	if err == nil {
		err = json.Unmarshal(warpJson, &warpSettings)
		if err != nil {
			panic(err)
		}
	}

	var versionSettings VersionSettings
	versionJson, err := os.ReadFile(filepath.Join(warpVersionHome, "version.json"))
	if err == nil {
		err = json.Unmarshal(versionJson, &versionSettings)
		if err != nil {
			panic(err)
		}
	}

	return &WarpState{
		warpHome:        warpHome,
		warpVersionHome: warpVersionHome,
		warpSettings:    &warpSettings,
		versionSettings: &versionSettings,
	}
}

func setWarpState(state *WarpState) {
	warpHome := os.Getenv("WARP_HOME")
	if warpHome == "" {
		panic("WARP_HOME must be set.")
	}
	warpVersionHome := os.Getenv("WARP_VERSION_HOME")
	if warpVersionHome == "" {
		warpVersionHome = warpHome
	}

	var err error

	warpJson, err := json.Marshal(state.warpSettings)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filepath.Join(warpHome, "warp.json"), warpJson, os.FileMode(0770))
	if err != nil {
		panic(err)
	}

	versionJson, err := json.Marshal(state.versionSettings)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filepath.Join(warpVersionHome, "version.json"), versionJson, os.FileMode(0770))
	if err != nil {
		panic(err)
	}
}

type DockerHubLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerHubLoginResponse struct {
	Token string `json:"token"`
}

type DockerHubReposResponse struct {
	NextUrl *string                         `json:"next"`
	Results []*DockerHubReposResponseResult `json:"results"`
}

type DockerHubReposResponseResult struct {
	Name              string `json:"name"`
	RepositoryType    string `json:"repository_type"`
	StatusDescription string `json:"status_description"`
}

type DockerHubTagsResponse struct {
	NextUrl *string                        `json:"next"`
	Results []*DockerHubTagsResponseResult `json:"results"`
}

type DockerHubTagsResponseResult struct {
	// Tags []DockerHubTagsResponseResultTag `json:"tags"`
	Name        string `json:"name"`
	Status      string `json:"tag_status"`
	ContentType string `json:"content_type"`
	Digest      string `json:"digest"`
}

// type DockerHubImagesResponseResultTag struct {
//     Tag string `json:"tag"`
//     IsCurrent bool `json:"is_current"`
// }

type DockerHubClient struct {
	warpState       *WarpState
	httpClient      *http.Client
	tokenCreateTime time.Time
	token           string
}

func NewDockerHubClient(warpState *WarpState) *DockerHubClient {
	dockerHubClient := &DockerHubClient{
		warpState:  warpState,
		httpClient: warp.DefaultHttpClient(),
	}
	dockerHubClient.Login()

	return dockerHubClient
}

func (self *DockerHubClient) Login() {
	dockerHubLoginRequest := DockerHubLoginRequest{
		Username: self.warpState.warpSettings.RequireDockerHubUsername(),
		Password: self.warpState.warpSettings.RequireDockerHubToken(),
	}
	loginRequestJson, err := json.Marshal(dockerHubLoginRequest)
	if err != nil {
		panic(err)
	}
	loginRequest, err := http.NewRequest(
		"POST",
		"https://hub.docker.com/v2/users/login",
		bytes.NewReader(loginRequestJson),
	)
	if err != nil {
		panic(err)
	}
	loginRequest.Header.Add("Content-Type", "application/json")
	loginResponse, err := self.httpClient.Do(loginRequest)
	if err != nil {
		panic(err)
	}

	var dockerHubLoginResponse DockerHubLoginResponse
	body, err := io.ReadAll(loginResponse.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(body, &dockerHubLoginResponse)
	if err != nil {
		panic(err)
	}

	self.token = dockerHubLoginResponse.Token
}

func (self *DockerHubClient) AddAuthorizationHeader(request *http.Request) {
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", self.token))
}

func (self *DockerHubClient) NamespaceUrl(path string) string {
	return fmt.Sprintf(
		"https://hub.docker.com/v2/namespaces/%s%s",
		self.warpState.warpSettings.RequireDockerNamespace(),
		path,
	)
}

type ServiceMeta struct {
	envs            []string
	services        []string
	blocks          []string
	envVersionMetas map[string]map[string]*VersionMeta
}

func (self *DockerHubClient) getServiceMeta() (*ServiceMeta, error) {
	repoNames := []string{}

	url := self.NamespaceUrl("/repositories")
	for {
		reposRequest, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		self.AddAuthorizationHeader(reposRequest)

		reposResponse, err := self.httpClient.Do(reposRequest)
		if err != nil {
			return nil, err
		}

		var dockerHubReposResponse DockerHubReposResponse
		body, err := io.ReadAll(reposResponse.Body)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(body, &dockerHubReposResponse)
		if err != nil {
			return nil, err
		}

		for _, result := range dockerHubReposResponse.Results {
			if result.StatusDescription == "active" {
				repoNames = append(repoNames, result.Name)
			}
		}

		if dockerHubReposResponse.NextUrl == nil {
			break
		}
		url = *dockerHubReposResponse.NextUrl
	}

	Err.Printf("Found repo names %s\n", strings.Join(repoNames, ", "))

	envVersionMetas := map[string]map[string]*VersionMeta{}

	envsMap := map[string]bool{}
	servicesMap := map[string]bool{}
	blocksMap := map[string]bool{}

	// a service repo is named <env>-<service>
	repoRegex := regexp.MustCompile("^([^-]+)-(.+)$")
	for _, repoName := range repoNames {
		groups := repoRegex.FindStringSubmatch(repoName)
		if groups == nil {
			continue
		}

		env := groups[1]
		service := groups[2]

		versionMeta, err := self.getVersionMeta(env, service)
		if err != nil {
			return nil, err
		}

		if envVersionMetas[env] == nil {
			envVersionMetas[env] = map[string]*VersionMeta{}
		}
		envVersionMetas[env][service] = versionMeta

		envsMap[env] = true
		servicesMap[service] = true
		for block, _ := range versionMeta.latestBlocks {
			blocksMap[block] = true
		}
	}

	envs := maps.Keys(envsMap)
	services := maps.Keys(servicesMap)
	blocks := maps.Keys(blocksMap)

	return &ServiceMeta{
		envs:            envs,
		services:        services,
		blocks:          blocks,
		envVersionMetas: envVersionMetas,
	}, nil
}

type VersionMeta struct {
	env          string
	service      string
	versions     []semver.Version
	latestBlocks map[string]semver.Version
}

func (self *DockerHubClient) getVersionMeta(env string, service string) (*VersionMeta, error) {
	versionsMap := map[semver.Version]bool{}
	latestBlocks := map[string]semver.Version{}

	// digest -> versions
	digestImageVersions := map[string][]semver.Version{}
	// block -> digest
	blockLatestDigests := map[string]string{}

	latestRegex := regexp.MustCompile("^(.*)-latest$")

	url := self.NamespaceUrl(fmt.Sprintf("/repositories/%s-%s/tags", env, service))
	for {
		imagesRequest, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		self.AddAuthorizationHeader(imagesRequest)

		imagesResponse, err := self.httpClient.Do(imagesRequest)
		if err != nil {
			return nil, err
		}
		var dockerHubTagsResponse DockerHubTagsResponse
		body, err := io.ReadAll(imagesResponse.Body)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(body, &dockerHubTagsResponse)
		if err != nil {
			return nil, err
		}

		for _, result := range dockerHubTagsResponse.Results {
			if result.Status == "active" {
				versionStr := convertVersionFromDocker(result.Name)
				if version, err := semver.NewVersion(versionStr); err == nil {
					imageVersions := append(digestImageVersions[result.Digest], *version)
					digestImageVersions[result.Digest] = imageVersions
					versionsMap[*version] = true
				} else if groups := latestRegex.FindStringSubmatch(result.Name); groups != nil {
					block := groups[1]
					blockLatestDigests[block] = result.Digest
				}
			}
		}

		if dockerHubTagsResponse.NextUrl == nil {
			break
		}
		url = *dockerHubTagsResponse.NextUrl
	}

	// resolve the latest tag against the other version tags on the image
	for block, latestDigest := range blockLatestDigests {
		if imageVersions, ok := digestImageVersions[latestDigest]; ok {
			// if len(imageVersions) == 0,
			//    the latest tag does not have an associated version
			// if 1 < len(imageVersions),
			//    the latest tag has more than one associated version
			if len(imageVersions) == 1 {
				latestBlocks[block] = imageVersions[0]
			}
		}
	}

	return &VersionMeta{
		env:          env,
		service:      service,
		versions:     maps.Keys(versionsMap),
		latestBlocks: latestBlocks,
	}, nil
}

func pollStatusUntil(
	env string,
	service string,
	sampleCount int,
	statusUrls []string,
	targetVersion string,
	timeout time.Duration,
) {
	startTime := time.Now()
	for {
		statusVersions := sampleStatusVersions(sampleCount, statusUrls)

		serviceCount := 0
		serviceVersions := []semver.Version{}
		configCount := 0
		configVersions := []semver.Version{}

		for version, count := range statusVersions.versions {
			serviceVersions = append(serviceVersions, version)
			serviceCount += count
		}
		for version, count := range statusVersions.configVersions {
			configVersions = append(configVersions, version)
			configCount += count
		}

		semverSortWithBuild(serviceVersions)
		semverSortWithBuild(configVersions)

		if 0 < len(statusVersions.errors) {
			Out.Printf("** errors **:\n")
			for errorMessage, count := range statusVersions.errors {
				Out.Printf("    %s: %d\n", errorMessage, count)
			}
		}

		Out.Printf("%s versions:\n", service)
		for _, version := range serviceVersions {
			count := statusVersions.versions[version]
			percent := float32(100.0*count) / float32(serviceCount)
			Out.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
		}

		Out.Printf("config versions:\n")
		for _, version := range configVersions {
			count := statusVersions.configVersions[version]
			percent := float32(100.0*count) / float32(configCount)
			Out.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
		}

		if targetVersion == "" {
			break
		}
		if len(serviceVersions) == 1 &&
			serviceVersions[0].String() == targetVersion &&
			len(statusVersions.errors) == 0 {
			break
		}

		Out.Printf("\n")

		if timeout < 0 {
			time.Sleep(10 * time.Second)
		} else if timeout == 0 {
			return
		} else {
			remainingTimeout := timeout - time.Now().Sub(startTime)
			if remainingTimeout <= 0 {
				return
			} else {
				time.Sleep(min(remainingTimeout, 10 * time.Second))
			}
		}
	}
}

func pollStatus(
	env string,
	service string,
	sampleCount int,
	statusUrls []string,
) (
	serviceVersionPercents map[semver.Version]float32,
	configVersionPercents map[semver.Version]float32,
	errorMessageCounts map[string]int,
) {
	serviceVersionPercents = map[semver.Version]float32{}
	configVersionPercents = map[semver.Version]float32{}
	errorMessageCounts = map[string]int{}

	statusVersions := sampleStatusVersions(sampleCount, statusUrls)

	serviceCount := 0
	serviceVersions := []semver.Version{}
	configCount := 0
	configVersions := []semver.Version{}

	for version, count := range statusVersions.versions {
		serviceVersions = append(serviceVersions, version)
		serviceCount += count
	}
	for version, count := range statusVersions.configVersions {
		configVersions = append(configVersions, version)
		configCount += count
	}

	if 0 < len(statusVersions.errors) {
		for errorMessage, count := range statusVersions.errors {
			errorMessageCounts[errorMessage] = count
		}
	}

	for _, version := range serviceVersions {
		count := statusVersions.versions[version]
		percent := float32(100.0*count) / float32(serviceCount)
		serviceVersionPercents[version] = percent
	}

	for _, version := range configVersions {
		count := statusVersions.configVersions[version]
		percent := float32(100.0*count) / float32(configCount)
		configVersionPercents[version] = percent
	}

	return
}

type WarpStatusResponse struct {
	Version       string `json:"version"`
	ConfigVersion string `json:"config_version"`
	Status        string `json:"status"`
}

func (self *WarpStatusResponse) IsError() bool {
	// if status starts with error it is recorded as an error
	errorRegex := regexp.MustCompile("^(?i)error\\s")
	return errorRegex.MatchString(self.Status)
}

type StatusVersions struct {
	versions       map[semver.Version]int
	configVersions map[semver.Version]int
	errors         map[string]int
}

func sampleStatusVersions(sampleCount int, statusUrls []string) *StatusVersions {
	resultsMutex := sync.Mutex{}
	versions := map[semver.Version]int{}
	configVersions := map[semver.Version]int{}
	errors := map[string]int{}

	addResults := func(statusResponse *WarpStatusResponse) {
		resultsMutex.Lock()
		defer resultsMutex.Unlock()

		if version, err := semver.NewVersion(statusResponse.Version); err == nil {
			versions[*version] += 1
		} else {
			errors[fmt.Sprintf("error status bad version (%s)", statusResponse.Status)] += 1
		}

		if statusResponse.ConfigVersion != "" {
			if configVersion, err := semver.NewVersion(statusResponse.ConfigVersion); err == nil {
				configVersions[*configVersion] += 1
			}
			// no config version is not an error
		}

		if statusResponse.IsError() {
			errors[statusResponse.Status] += 1
		}
	}

	sample := func(statusUrl string, complete chan string) {
		// do not use connection re-use or keep alives
		// each request should be a new connection
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 5 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableKeepAlives:     true,
				MaxIdleConnsPerHost:   -1,
			},
		}

		sampleOne := func() *WarpStatusResponse {
			statusRequest, err := http.NewRequest("GET", statusUrl, nil)
			if err != nil {
				return &WarpStatusResponse{
					Status: "error could not create request",
				}
			}
			statusResponse, err := httpClient.Do(statusRequest)
			if err != nil {
				return &WarpStatusResponse{
					Status: "error status request failed",
				}
			}
			if statusResponse.StatusCode != 200 {
				return &WarpStatusResponse{
					Status: fmt.Sprintf("error http status %d", statusResponse.StatusCode),
				}
			}

			var warpStatusResponse WarpStatusResponse
			body, err := io.ReadAll(statusResponse.Body)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(body, &warpStatusResponse)
			if err != nil {
				return &WarpStatusResponse{
					Status: fmt.Sprintf("error could not parse status"),
				}
			}

			return &warpStatusResponse
		}

		for i := 0; i < sampleCount; i += 1 {
			addResults(sampleOne())
		}

		complete <- statusUrl
	}

	complete := make(chan string, len(statusUrls))
	for _, statusUrl := range statusUrls {
		go sample(statusUrl, complete)
	}
	for range statusUrls {
		<-complete
	}

	return &StatusVersions{
		versions:       versions,
		configVersions: configVersions,
		errors:         errors,
	}
}

func pollLbBlockStatusUntil(env string, service string, blocks []string, targetVersion string, timeout time.Duration) {
	// TODO for lb, if the service config mapped each interface to a public ip,
	// TODO then we could reach individual blocks via a http+ip+host header
	if !isStandardStatus(env, service) {
		return
	}

	if service == "lb" {
		return
	}

	if !isLbExposed(env, service) {
		// the service is not externally exposed
		return
	}

	domain := getDomain(env)
	hiddenPrefix := getLbHiddenPrefix(env)

	blockStatusUrls := []string{}
	for _, block := range blocks {
		var blockStatusUrl string
		if hiddenPrefix == "" {
			blockStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/by/b/%s/%s/status",
				env,
				domain,
				service,
				block,
			)
		} else {
			blockStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/%s/by/b/%s/%s/status",
				env,
				domain,
				hiddenPrefix,
				service,
				block,
			)
		}
		blockStatusUrls = append(blockStatusUrls, blockStatusUrl)
	}

	pollStatusUntil(env, service, 20, blockStatusUrls, targetVersion, timeout)
}

func pollLbServiceStatusUntil(env string, service string, targetVersion string, timeout time.Duration) {
	if !isStandardStatus(env, service) {
		return
	}

	if service == "lb" {
		domain := getDomain(env)
		hiddenPrefix := getLbHiddenPrefix(env)

		var serviceStatusUrl string
		if hiddenPrefix == "" {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/status",
				env,
				domain,
			)
		} else {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/%s/status",
				env,
				domain,
				hiddenPrefix,
			)
		}

		pollStatusUntil(env, service, 20, []string{serviceStatusUrl}, targetVersion, timeout)
	} else {
		if !isLbExposed(env, service) {
			// the service is not externally exposed
			return
		}

		domain := getDomain(env)
		hiddenPrefix := getLbHiddenPrefix(env)

		var serviceStatusUrl string
		if hiddenPrefix == "" {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/by/service/%s/status",
				env,
				domain,
				service,
			)
		} else {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/%s/by/service/%s/status",
				env,
				domain,
				hiddenPrefix,
				service,
			)
		}

		pollStatusUntil(env, service, 20, []string{serviceStatusUrl}, targetVersion, timeout)
	}
}

func convertVersionToDocker(version string) string {
	// replace last + with -
	parts := strings.Split(version, "+")
	if 2 < len(parts) {
		panic("Bad semver: expecting at most one +")
	}
	return strings.Join(parts, "-")
}

func convertVersionFromDocker(dockerVersion string) string {
	// if two tailing -, replace last with +
	parts := strings.Split(dockerVersion, "-")
	if 2 <= len(parts) {
		return fmt.Sprintf("%s+%s", strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1])
	} else {
		return strings.Join(parts, "-")
	}
}

// block -> version -> percent
func sampleBlockCurrentVersions(env string, service string, blocks ...string) (blockVersionPercents map[string]map[semver.Version]float32) {
	blockVersionPercents = map[string]map[semver.Version]float32{}

	if !isStandardStatus(env, service) {
		return
	}

	if service == "lb" {
		// TODO poll blocks of lb needs ip map
		return
	}

	if !isLbExposed(env, service) {
		// the service is not externally exposed
		return
	}

	domain := getDomain(env)
	hiddenPrefix := getLbHiddenPrefix(env)

	for _, block := range blocks {
		var serviceStatusUrl string
		if hiddenPrefix == "" {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/by/b/%s/%s/status",
				env,
				domain,
				service,
				block,
			)
		} else {
			serviceStatusUrl = fmt.Sprintf(
				"https://%s-lb.%s/%s/by/b/%s/%s/status",
				env,
				domain,
				hiddenPrefix,
				service,
				block,
			)
		}

		serviceVersionPercents, _, _ := pollStatus(env, service, 20, []string{serviceStatusUrl})
		blockVersionPercents[block] = serviceVersionPercents
	}

	return
}
