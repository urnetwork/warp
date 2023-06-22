package main


import (

	"fmt"
    "os"
    "io"
    // "os/exec"
    "path"
    "encoding/json"
    "time"
    // "strings"
    // "math"
    "net"
    "net/http"
    "regexp"
    "context"
    "sync"
    "bytes"
    "strings"

    "golang.org/x/exp/maps"
	"golang.org/x/sync/semaphore"

    "github.com/coreos/go-semver/semver"
)


type WarpState struct {
    warpHome string
    warpVersionHome string
    warpSettings *WarpSettings
    versionSettings *VersionSettings
}


type WarpSettings struct {
    DockerNamespace *string `json:"dockerNamespace,omitempty"`
    DockerHubUsername *string `json:"dockerHubUsername,omitempty"`
    DockerHubToken *string `json:"dockerHubToken,omitempty"`
    VaultHome *string `json:"vaultHome,omitempty"`
    ConfigHome *string `json:"configHome,omitempty"`
    SiteHome *string `json:"siteHome,omitempty"`
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
func (self *WarpSettings) RequireVaultHome() string {
	if self.VaultHome == nil {
		panic("WARP_VAULT_HOME is not set. Use warpctl init.")
	}
	return *self.VaultHome
}
func (self *WarpSettings) RequireConfigHome() string {
	if self.ConfigHome == nil {
		panic("WARP_CONFIG_HOME is not set. Use warpctl init.")
	}
	return *self.ConfigHome
}
func (self *WarpSettings) RequireSiteHome() string {
	if self.ConfigHome == nil {
		panic("WARP_SITE_HOME is not set. Use warpctl init.")
	}
	return *self.SiteHome
}




type VersionSettings struct {
    StagedVersion *string `json:"stagedVersion,omitempty"`
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
    warpJson, err := os.ReadFile(path.Join(warpHome, "warp.json"))
    if err == nil {
        err = json.Unmarshal(warpJson, &warpSettings)
        if err != nil {
            panic(err)
        }
    }

    var versionSettings VersionSettings
    versionJson, err := os.ReadFile(path.Join(warpVersionHome, "version.json"))
    if err == nil {
        err = json.Unmarshal(versionJson, &versionSettings)
        if err != nil {
            panic(err)
        }
    }

    return &WarpState{
        warpHome: warpHome,
        warpVersionHome: warpVersionHome,
        warpSettings: &warpSettings,
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
    err = os.WriteFile(path.Join(warpHome, "warp.json"), warpJson, os.FileMode(0770))
    if err != nil {
        panic(err)
    }

    versionJson, err := json.Marshal(state.versionSettings)
    if err != nil {
        panic(err)
    }
    err = os.WriteFile(path.Join(warpVersionHome, "version.json"), versionJson, os.FileMode(0770))
    if err != nil {
        panic(err)
    }
}


func getLocalVersion() string {
    host, err := os.Hostname()
    if err != nil {
        host = "nohost"
    }
    now := time.Now()
    year, month, day := now.Date()
    return fmt.Sprintf("%d.%d.%d-%s", year, month, day, host)
}


func getVersion(build bool, docker bool) string {
    state := getWarpState()

    stagedVersion := state.versionSettings.StagedVersion

    var version string
    if stagedVersion == nil || *stagedVersion == "local" {
        version = getLocalVersion()
    } else {
        version = *stagedVersion
    }

    if build {
        buildTimestamp := time.Now().UnixMilli()
        version = fmt.Sprintf("%s+%d", version, buildTimestamp)
    }

    if docker {
        version = convertVersionToDocker(version)
    }

    return version
}


type DockerHubLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerHubLoginResponse struct {
	Token string `json:"token"`
}

type DockerHubReposResponse struct {
	NextUrl *string `json:"next"`
	Results []DockerHubReposResponseResult `json:"results"`
}

type DockerHubReposResponseResult struct {
	Name string `json:"name"`
	RepositoryType string `json:"repository_type"`
	StatusDescription string `json:"status_description"`
}

type DockerHubImagesResponse struct {
	NextUrl *string `json:"next"`
	Results []DockerHubImagesResponseResult `json:"results"`
}

type DockerHubImagesResponseResult struct {
	Tags []DockerHubImagesResponseResultTag `json:"tags"`
	Status string `json:"status"`
}

type DockerHubImagesResponseResultTag struct {
	Tag string `json:"tag"`
	IsCurrent bool `json:"is_current"`
}

type DockerHubClient struct {
	warpState *WarpState
	httpClient *http.Client
	token string
}

func NewDockerHubClient(warpState *WarpState) *DockerHubClient {
	// state := getWarpState()

	httpClient := &http.Client{}

    dockerHubLoginRequest := DockerHubLoginRequest{
    	Username: warpState.warpSettings.RequireDockerHubUsername(),
    	Password: warpState.warpSettings.RequireDockerHubToken(),
    }
    loginRequestJson, err := json.Marshal(dockerHubLoginRequest)
    if err != nil {
    	panic(err)
    }
    fmt.Printf("LOGIN JSON %s\n", loginRequestJson)
    loginRequest, err := http.NewRequest(
    	"POST",
    	"https://hub.docker.com/v2/users/login",
    	bytes.NewReader(loginRequestJson),
    )
    if err != nil {
    	panic(err)
    }
    loginRequest.Header.Add("Content-Type", "application/json")
    loginResponse, err := httpClient.Do(loginRequest)
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

    fmt.Printf("LOGIN GOT RESPONSE %s\n", dockerHubLoginResponse.Token)

    return &DockerHubClient{
    	warpState: warpState,
    	httpClient: httpClient,
    	token: dockerHubLoginResponse.Token,
    }
}

func (self *DockerHubClient) AddAuthorizationHeader(request *http.Request) {
	// fmt.Printf("Authorization: Bearer %s\n", self.token)
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
    envs []string
    services []string
    blocks []string
    envVersionMetas map[string]map[string]*VersionMeta
}


type VersionMeta struct {
    env string
    service string
    versions []*semver.Version
    latestBlocks map[string]*semver.Version
}


func (self *DockerHubClient) getServiceMeta() *ServiceMeta {
	// state := getWarpState()
    // client := NewDockerHubClient(state)

    repoNames := []string{}

    url := self.NamespaceUrl("/repositories")
    for {
    	// fmt.Printf("%s\n", url)
	    reposRequest, err := http.NewRequest("GET", url, nil)
	    if err != nil {
	    	panic(err)
	    }
	    self.AddAuthorizationHeader(reposRequest)

	    reposResponse, err := self.httpClient.Do(reposRequest)
	    if err != nil {
	    	panic(err)
	    }

	    var dockerHubReposResponse DockerHubReposResponse
	    body, err := io.ReadAll(reposResponse.Body)
	    if err != nil {
	    	panic(err)
	    }
	    err = json.Unmarshal(body, &dockerHubReposResponse)
	    if err != nil {
	    	panic(err)
	    }

		for _, result := range dockerHubReposResponse.Results {
			fmt.Printf("SCANNING RESULT %s\n", result)
			if /*result.RepositoryType == "image" &&*/ result.StatusDescription == "active" {
				repoNames = append(repoNames, result.Name)
			}
		}

		if dockerHubReposResponse.NextUrl == nil {
			break
		}
		url = *dockerHubReposResponse.NextUrl
	}

	fmt.Printf("FOUND REPO NAMES %s\n", repoNames)

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

		versionMeta := self.getVersionMeta(env, service)

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
		envs: envs,
		services: services,
		blocks: blocks,
		envVersionMetas: envVersionMetas,
	}
}


func (self *DockerHubClient) getVersionMeta(env string, service string) *VersionMeta {
	// state := getWarpState()
    // client := NewDockerHubClient(state)

	versionsMap := map[*semver.Version]bool{}
	latestBlocks := map[string]*semver.Version{}

	latestRegex := regexp.MustCompile("^(.*)-latest$")

	url := self.NamespaceUrl(fmt.Sprintf("/repositories/%s-%s/images", env, service))
	for {
	    imagesRequest, err := http.NewRequest("GET", url, nil)
	    if err != nil {
	    	panic(err)
	    }
	    self.AddAuthorizationHeader(imagesRequest)

	    imagesResponse, err := self.httpClient.Do(imagesRequest)
	    if err != nil {
	    	panic(err)
	    }
	    var dockerHubImagesResponse DockerHubImagesResponse
	    body, err := io.ReadAll(imagesResponse.Body)
	    if err != nil {
	    	panic(err)
	    }
	    err = json.Unmarshal(body, &dockerHubImagesResponse)
	    if err != nil {
	    	panic(err)
	    }

	    
		for _, result := range dockerHubImagesResponse.Results {
			if result.Status == "active" {
				imageVersions := []*semver.Version{}

				for _, tag := range result.Tags {
					if tag.IsCurrent {
						// fmt.Printf("tag %s %t\n", tag.Tag, tag.IsCurrent)
						versionStr := convertVersionFromDocker(tag.Tag)
						if version, err := semver.NewVersion(versionStr); err == nil {
							// fmt.Printf("v %s %t\n", version, tag.IsCurrent)
							imageVersions = append(imageVersions, version)
							versionsMap[version] = true
						}
					}
				}

				// resolve the latest tag against the other version tags on the image
				for _, tag := range result.Tags {
					if tag.IsCurrent {
						if groups := latestRegex.FindStringSubmatch(tag.Tag); groups != nil {
							fmt.Printf("MATCHED LATEST VERSION AGAINST %s\n", tag.Tag)
							block := groups[1]
							if len(imageVersions) == 0 {
								panic("Latest tag does not have an associated version.")
							}
							if 1 < len(imageVersions) {
								panic("Latest tag has more than one associated version.")
							}
							latestBlocks[block] = imageVersions[0]
						}
					}
				}
			}
		}

		if dockerHubImagesResponse.NextUrl == nil {
			break
		}
		url = *dockerHubImagesResponse.NextUrl
	}

	return &VersionMeta{
		env: env,
		service: service,
		versions: maps.Keys(versionsMap),
		latestBlocks: latestBlocks,
	}
}


func pollStatusUntil(env string, service string, sampleCount int, statusUrls []string, targetVersion string) {
	for {
        statusVersions := sampleStatusVersions(20, statusUrls)

        serviceCount := 0
        serviceVersions := []*semver.Version{}
        configCount := 0
        configVersions := []*semver.Version{}

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
            fmt.Printf("** errors **:\n")
            for errorMessage, count := range statusVersions.errors {
                fmt.Printf("    %s: %d\n", errorMessage, count)
            }
        }

        fmt.Printf("%s versions:\n", service)
        for _, version := range serviceVersions {
            count := statusVersions.versions[version]
            percent := 100.0 * count / serviceCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        fmt.Printf("config versions:\n")
        for _, version := range configVersions {
            count := statusVersions.configVersions[version]
            percent := 100.0 * count / configCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        if targetVersion == "" {
            break
        }
        if len(serviceVersions) == 1 && 
        		serviceVersions[0].String() == targetVersion && 
        		len(statusVersions.errors) == 0 {
            break
        }

        fmt.Printf("\n")

        time.Sleep(10 * time.Second)
    }
}


type StatusVersions struct {
	versions map[*semver.Version]int
	configVersions map[*semver.Version]int
	errors map[string]int
}


type WarpStatusResponse struct {
	Version string `json:"version"`
	ConfigVersion string `json:"configVersion"`
	Status string `json:"status"`
}

func (self *WarpStatusResponse) IsError() bool {
	// if status starts with error it is recorded as an error
	errorRegex := regexp.MustCompile("^(?i)error\\s")
	return errorRegex.MatchString(self.Status)
}


func sampleStatusVersions(sampleCount int, statusUrls []string) *StatusVersions {
	

	resultsMutex := sync.Mutex{}
	versions := map[*semver.Version]int{}
	configVersions := map[*semver.Version]int{}
	errors := map[string]int{}

	addResults := func(statusResponse *WarpStatusResponse) {
		resultsMutex.Lock()
		defer resultsMutex.Unlock()

		version, err := semver.NewVersion(statusResponse.Version)
		if err == nil {
			versions[version] += 1
		} else {
			errors["error status bad version"] += 1
		}

		configVersion, err := semver.NewVersion(statusResponse.ConfigVersion)
		if err == nil {
			configVersions[configVersion] += 1
		} else {
			errors["error status bad config version"] += 1
		}

		if statusResponse.IsError() {
			errors[statusResponse.Status] += 1
		}
	}

	sample := func(sem *semaphore.Weighted, statusUrl string) {
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
	            DisableKeepAlives: true,
	            MaxIdleConnsPerHost: -1,
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
		sem.Release(1)
	}


	sem := semaphore.NewWeighted(0)
	for _, statusUrl := range statusUrls {
		go sample(sem, statusUrl)
	}

	sem.Acquire(context.Background(), int64(len(statusUrls)))

	return &StatusVersions{
		versions: versions,
		configVersions: configVersions,
		errors: errors,
	}
}


func pollLbBlockStatusUntil(env string, service string, blocks []string, targetVersion string) {
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
	        	"%s-lb.%s/by/b/%s/%s/status",
	        	env,
	        	domain,
	        	service,
	        	block,
	        )
	    } else {
	    	blockStatusUrl = fmt.Sprintf(
	        	"%s-lb.%s/%s/by/b/%s/%s/status",
	        	env,
	        	domain,
	        	hiddenPrefix,
	        	service,
	        	block,
	        )
	    }
        blockStatusUrls = append(blockStatusUrls, blockStatusUrl)
    }

    pollStatusUntil(env, service, 20, blockStatusUrls, targetVersion)
}


func pollLbServiceStatusUntil(env string, service string, targetVersion string) {
	if !isLbExposed(env, service) {
		// the service is not externally exposed
		return
	}

	domain := getDomain(env)
	hiddenPrefix := getLbHiddenPrefix(env)

	var serviceStatusUrl string
	if hiddenPrefix == "" {
		serviceStatusUrl = fmt.Sprintf(
			"%s-lb.%s/by/service/%s/status",
			env,
			domain,
			service,
		)
	} else {
		serviceStatusUrl = fmt.Sprintf(
			"%s-lb.%s/%s/by/service/%s/status",
			env,
			domain,
			hiddenPrefix,
			service,
		)
	}

    pollStatusUntil(env, service, 20, []string{serviceStatusUrl}, targetVersion)
}


func pollServiceStatusUntil(env string, service string, targetVersion string) {
	if !isExposed(env, service) {
		// the service is not externally exposed
		return
	}

	domain := getDomain(env)
	hiddenPrefix := getHiddenPrefix(env)

	var serviceStatusUrl string
	if hiddenPrefix == "" {
		serviceStatusUrl = fmt.Sprintf(
			"%s-%s.%s/status",
			env,
			service,
			domain,
		)
	} else {
		serviceStatusUrl = fmt.Sprintf(
			"%s-%s.%s/%s/status",
			env,
			service,
			domain,
			hiddenPrefix,
		)
	}

    pollStatusUntil(env, service, 20, []string{serviceStatusUrl}, targetVersion)
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
		return fmt.Sprintf("%s+%s", strings.Join(parts[:len(parts) - 1], "-"), parts[len(parts) - 1])
	} else {
		return strings.Join(parts, "-")
	}
}
