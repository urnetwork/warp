package services

// The sidecar's service blocks in sidecar-blocks/ (DESIGN §19.4; OPS-M2-03), each loaded through warp's
// own loader on the synthetic base fragment_test.go keeps, since nobody here reads the vault's file. Every
// fragment in the directory is applied, so one added later is held to the same rules. A registrar the
// owner fills in is filled in first, with a synthetic choice, as the owner would before applying.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The names W10 and QD-012 give mmm: recurd.dev's two, which forward to ur.io/recurd, and the page
// Worker's key origin.
var sidecarBlockMmmAliases = []string{"recurd.dev", "www.recurd.dev", "sidecar.ur.io"}

// The origin the page Worker's requests carry (sidecar DESIGN §18.8).
const sidecarBlockKeyOrigin = "https://sidecar.ur.io"

// The registrar these tests fill each placeholder with, for the owner, who gives the real one.
const sidecarBlockFilledRegistrar = "route53"

// The fragments in sidecar-blocks/, by file name.
func sidecarBlockFragments(t *testing.T) map[string]*ServicesFragment {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("sidecar-blocks", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("sidecar-blocks/ holds no fragment")
	}
	sort.Strings(paths)
	fragments := map[string]*ServicesFragment{}
	for _, path := range paths {
		fragment, err := LoadServicesFragment(path)
		if err != nil {
			t.Fatal(err)
		}
		fragments[filepath.Base(path)] = fragment
	}
	return fragments
}

// The base with every fragment applied, each placeholder registrar filled in, as the loader reads it, and
// which services the fragments added.
func applySidecarBlockFragments(t *testing.T) (*ServicesConfig, []string) {
	t.Helper()
	fragments := sidecarBlockFragments(t)
	names := []string{}
	for name := range fragments {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := []*ServicesFragment{}
	for _, name := range names {
		for index, domain := range fragments[name].domains {
			if !slices.Contains(servicesFragmentRegistrars, domain.registrar) {
				fragments[name].domains[index].registrar = sidecarBlockFilledRegistrar
			}
		}
		ordered = append(ordered, fragments[name])
	}
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", ordered...)
	if err != nil {
		t.Fatal(err)
	}
	servicesConfig, err := ParseServicesConfig(result.Text, "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseServicesConfig([]byte(fragmentBaseYaml), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	added := []string{}
	for service := range servicesConfig.Versions[0].Services {
		if _, ok := base.Versions[0].Services[service]; !ok {
			added = append(added, service)
		}
	}
	sort.Strings(added)
	return servicesConfig, added
}

// Vault files no block but the issuer may mount: the oauth issuer's signing keys, the session jwt keys,
// grafana.yml, whose push-only replacement every new block mounts (QD-249), and anything named a key.
var sidecarBlockForbiddenSecretRegex = regexp.MustCompile(`^(auth\.yml|jwt\.yml|grafana\.yml)$|signing|private|\.key$|\.pem$`)

// Each block §19.4 adds: beta 1 and g1 99, only config mounted, user 65532, the scoped vault home,
// sorted secrets naming no signing key, its own metrics push credential, and path-only logs.
func TestSidecarBlocksFollowTheNewBlockRules(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	if !slices.Equal(added, []string{"evs", "gkm"}) {
		t.Errorf("the fragments add %q, want evs and gkm", added)
	}
	for _, service := range added {
		serviceConfig := servicesConfig.Versions[0].Services[service]
		if want := map[string]string{"vault": "no", "config": "yes", "site": "no"}; !mapsEqualStrings(serviceConfig.Mount, want) {
			t.Errorf("%s mounts %v, want %v", service, serviceConfig.Mount, want)
		}
		if serviceConfig.User != "65532:65532" {
			t.Errorf("%s runs as %q", service, serviceConfig.User)
		}
		if serviceConfig.EnvVars["WARP_VAULT_HOME"] != "/srv/warp/secrets" || len(serviceConfig.EnvVars) != 1 {
			t.Errorf("%s's env_vars are %v", service, serviceConfig.EnvVars)
		}
		if !slices.IsSorted(serviceConfig.SecretFiles) || len(serviceConfig.SecretFiles) == 0 {
			t.Errorf("%s's secret_files are %q", service, serviceConfig.SecretFiles)
		}
		for _, required := range []string{"grafana-push-" + service + ".yml", "oauth-jwks-svc.json", "redis.yml", "file-clusters-" + service + ".yml"} {
			if !slices.Contains(serviceConfig.SecretFiles, required) {
				t.Errorf("%s does not mount %s", service, required)
			}
		}
		if !serviceConfig.LogUri {
			t.Errorf("%s logs query strings (W8)", service)
		}
		if len(serviceConfig.Blocks) != 2 || serviceConfig.Blocks[0]["beta"] != 1 || serviceConfig.Blocks[1]["g1"] != 99 {
			t.Errorf("%s's blocks are %v", service, serviceConfig.Blocks)
		}
		if !serviceConfig.IsExposed() || !serviceConfig.IsLbExposed() || !serviceConfig.IsStandardStatus() || !slices.Equal(serviceConfig.HttpTcpPorts(), []int{80}) {
			t.Errorf("%s is not an lb service with GET /status on port 80", service)
		}
		if serviceConfig.CapNetAdmin || len(serviceConfig.Hosts) != 0 {
			t.Errorf("%s asks for cap_net_admin or pins hosts", service)
		}
		if want := []string{service + ".bringyour.com"}; !slices.Equal(serviceConfig.ExposeAliases, want) {
			t.Errorf("%s is named %q, want %q (§19.4)", service, serviceConfig.ExposeAliases, want)
		}
	}
}

// No fragment mounts a signing key or grafana.yml on any block (D-OPS-1), new or extended.
func TestNoSidecarBlockFragmentNamesASigningKey(t *testing.T) {
	for name, fragment := range sidecarBlockFragments(t) {
		text, err := encodeServicesFragmentNode(fragment.version)
		if err != nil {
			t.Fatal(err)
		}
		var version ServicesConfigVersion
		if err := fragment.version.Decode(&version); err != nil {
			t.Fatal(err)
		}
		for service, serviceConfig := range version.Services {
			for _, secretFile := range serviceConfig.SecretFiles {
				if sidecarBlockForbiddenSecretRegex.MatchString(secretFile) {
					t.Errorf("%s gives %s the secret %s", name, service, secretFile)
				}
			}
		}
		if strings.Contains(string(text), "vault: yes") {
			t.Errorf("%s mounts a whole vault", name)
		}
	}
}

// evs's rows: its segment PUT streams through the lb and nothing else does (§11.6), and the whole service
// shares W2's per-address limit; gkm's limit names no burst.
func TestEvsAndGkmBlocksCarryTheirRows(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	evs := servicesConfig.Versions[0].Services["evs"]
	if len(evs.StreamablePaths) != 1 {
		t.Fatalf("evs's streamable_paths are %q", evs.StreamablePaths)
	}
	streamable := regexp.MustCompile("^(?:" + evs.StreamablePaths[0] + ")$")
	for path, want := range map[string]bool{
		"/evs/v1/repos/r1/segments/s1":    true,
		"/evs/v1/repos/r1/segments/s1/x":  false,
		"/evs/v1/repos/r1":                false,
		"/evs/v1/repos/r1/push":           false,
		"/evs/v1/repos/r1/segments/":      false,
		"/x/evs/v1/repos/r1/segments/s1":  false,
		"/evs/v1/repos/r1/r2/segments/s1": false,
	} {
		if streamable.MatchString(path) != want {
			t.Errorf("evs streams %s: %v, want %v", path, !want, want)
		}
	}
	if limit := evs.ServiceRateLimit; limit == nil || limit.RequestsPerMinute != 3000 || limit.Burst != 1000 {
		t.Errorf("evs's service_rate_limit is %+v", limit)
	}
	if !slices.Contains(evs.SecretFiles, "evs-receipt-keys.json") {
		t.Errorf("evs does not mount its receipt keys")
	}
	gkm := servicesConfig.Versions[0].Services["gkm"]
	if limit := gkm.ServiceRateLimit; limit == nil || limit.RequestsPerMinute != 1200 || limit.Burst != 0 {
		t.Errorf("gkm's service_rate_limit is %+v", limit)
	}
	if 0 < len(gkm.StreamablePaths) || gkm.IsStreamable() {
		t.Errorf("gkm streams a request body")
	}
}

// api and taskworker keep what they had and add their file clusters; api's log keeps paths only (W8).
func TestApiAndTaskworkerBlocksAddTheirClusters(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base, err := ParseServicesConfig([]byte(fragmentBaseYaml), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := servicesConfig.Versions[0].Services["api"]
	if !slices.Equal(api.SecretFiles, []string{"api-extra.yml", "file-clusters-api.yml"}) || !api.LogUri {
		t.Errorf("api = %+v", api)
	}
	taskworker := servicesConfig.Versions[0].Services["taskworker"]
	if !slices.Equal(taskworker.SecretFiles, []string{"file-clusters-taskworker.yml"}) || taskworker.LogUri {
		t.Errorf("taskworker = %+v", taskworker)
	}
	for _, service := range []string{"api", "taskworker"} {
		before := base.Versions[0].Services[service]
		after := servicesConfig.Versions[0].Services[service]
		if !mapsEqualStrings(before.Mount, after.Mount) || before.User != after.User || !slices.Equal(before.PortSpecs, after.PortSpecs) {
			t.Errorf("%s's mounts, user or ports changed", service)
		}
	}
}

// Every secret file a new block mounts is one xops makes readable to uid 65532, or the block cannot
// read it (plan-OPS-small-readings #4): playbook-edges.yml's task lists exactly the new blocks' files.
func TestEdgesPlaybookRestrictsEveryNewBlockSecret(t *testing.T) {
	playbook, err := os.ReadFile(filepath.Join("..", "..", "xops", "main", "ansible", "playbook-edges.yml"))
	if err != nil {
		t.Skipf("xops is not beside this checkout: %v", err)
	}
	servicesConfig, added := applySidecarBlockFragments(t)
	want := []string{}
	for _, service := range added {
		for _, secretFile := range servicesConfig.Versions[0].Services[service].SecretFiles {
			if !slices.Contains(want, secretFile) {
				want = append(want, secretFile)
			}
		}
	}
	sort.Strings(want)
	task := regexp.MustCompile(`(?s)- name: Find the sidecar blocks' scoped secrets\n.*?loop:\n((?:\s+- [^\n]+\n)+)`).FindSubmatch(playbook)
	if task == nil {
		t.Fatal("playbook-edges.yml has no task finding the sidecar blocks' secrets")
	}
	got := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(task[1])), "\n") {
		got = append(got, strings.TrimPrefix(strings.TrimSpace(line), "- "))
	}
	if !slices.Equal(got, want) {
		t.Errorf("playbook-edges.yml restricts %q, the new blocks mount %q", got, want)
	}
}

// mmm.yml (W10, QD-012): mmm gains recurd.dev's two names and the key origin and nothing else changes in
// its block; recurd.dev joins domains under the registrar the owner gives, ur.io stays cloudflare's, and
// the key origin alone is listed unproxied. Each name is under a registrar domain, so warpctl certs issue
// covers it and warpctl dns can publish it.
func TestMmmBlockServesRecurdDevAndTheKeyOrigin(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base := mustParseServicesConfig(t, fragmentBaseYaml)
	before := base.Versions[0].Services["mmm"]
	mmm := servicesConfig.Versions[0].Services["mmm"]
	if want := append(slices.Clone(before.ExposeAliases), sidecarBlockMmmAliases...); !slices.Equal(mmm.ExposeAliases, want) {
		t.Errorf("mmm is named %q, want %q", mmm.ExposeAliases, want)
	}
	unchanged := *mmm
	unchanged.ExposeAliases = before.ExposeAliases
	if !reflect.DeepEqual(unchanged, *before) {
		t.Errorf("mmm's block changed beyond its names: %+v, was %+v", unchanged, *before)
	}
	if want := map[string]string{"example.com": "route53", "recurd.dev": sidecarBlockFilledRegistrar, "ur.io": "cloudflare"}; !reflect.DeepEqual(servicesConfig.DomainRegistrars(), want) {
		t.Errorf("domains = %v, want %v", servicesConfig.DomainRegistrars(), want)
	}
	if got := servicesConfig.DnsUnproxiedHosts(); !slices.Equal(got, []string{"sidecar.ur.io"}) {
		t.Errorf("unproxied = %q", got)
	}
	for _, alias := range sidecarBlockMmmAliases {
		covered := slices.ContainsFunc(servicesConfig.DomainNames(), func(domain string) bool {
			return alias == domain || strings.HasSuffix(alias, "."+domain)
		})
		if !covered {
			t.Errorf("%s is under no registrar domain", alias)
		}
	}
}

// mmm.yml leaves recurd.dev's registrar for the owner, and applied without it, the merge is refused and
// names the domain to fill in.
func TestMmmFragmentWaitsForItsRegistrar(t *testing.T) {
	fragment, err := LoadServicesFragment(filepath.Join("sidecar-blocks", "mmm.yml"))
	if err != nil {
		t.Fatal(err)
	}
	placeholders := []string{}
	for _, domain := range fragment.domains {
		if !slices.Contains(servicesFragmentRegistrars, domain.registrar) {
			placeholders = append(placeholders, domain.name)
		}
	}
	if !slices.Equal(placeholders, []string{"recurd.dev"}) {
		t.Errorf("mmm.yml leaves %q for the owner, want recurd.dev alone", placeholders)
	}
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", fragment)
	if err == nil || !strings.Contains(err.Error(), "domains.recurd.dev's registrar") || result != nil {
		t.Errorf("an unfilled registrar: %v", err)
	}
}

// The page Worker calls api, whose names include auth's token exchange, evs and gkm across origins (§18.8,
// §18.9), so each allows the key origin beside what it allowed; no fragment allows any other origin; and
// the key origin is a name mmm serves and the dns block keeps unproxied.
func TestKeyOriginIsAllowedByWhatThePageWorkerCalls(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base := mustParseServicesConfig(t, fragmentBaseYaml)
	for _, service := range []string{"api", "evs", "gkm"} {
		origins, err := servicesConfig.Versions[0].ResolveCorsOrigins(service)
		if err != nil {
			t.Fatal(err)
		}
		before := []string{}
		if _, ok := base.Versions[0].Services[service]; ok {
			if before, err = base.Versions[0].ResolveCorsOrigins(service); err != nil {
				t.Fatal(err)
			}
		}
		if want := append(before, sidecarBlockKeyOrigin); !slices.Equal(origins, want) {
			t.Errorf("%s allows %q, want %q", service, origins, want)
		}
	}
	for name, fragment := range sidecarBlockFragments(t) {
		var version ServicesConfigVersion
		if err := fragment.version.Decode(&version); err != nil {
			t.Fatal(err)
		}
		for service, serviceConfig := range version.Services {
			for _, origin := range serviceConfig.CorsOrigins {
				if origin != sidecarBlockKeyOrigin {
					t.Errorf("%s gives %s the origin %s", name, service, origin)
				}
			}
			if serviceConfig.CorsOriginsFrom != "" {
				t.Errorf("%s has %s take another service's origins", name, service)
			}
		}
	}
	keyOriginHost := strings.TrimPrefix(sidecarBlockKeyOrigin, "https://")
	if !slices.Contains(servicesConfig.Versions[0].Services["mmm"].ExposeAliases, keyOriginHost) || !slices.Contains(servicesConfig.DnsUnproxiedHosts(), keyOriginHost) {
		t.Errorf("the key origin %s is not an unproxied name of mmm", keyOriginHost)
	}
}

// Each name mmm.yml gives mmm is a server_name of mmm's own nginx, so the lb never sends mmm a name it
// would answer only with its default server.
func TestMmmNginxServesEveryNameTheFragmentAdds(t *testing.T) {
	nginxConf, err := os.ReadFile(filepath.Join("..", "..", "mmm", "mmm", "nginx", "nginx.conf.j2"))
	if err != nil {
		t.Skipf("mmm is not beside this checkout: %v", err)
	}
	serverNames := []string{}
	for _, match := range regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`).FindAllStringSubmatch(string(nginxConf), -1) {
		serverNames = append(serverNames, strings.Fields(match[1])...)
	}
	for _, alias := range sidecarBlockMmmAliases {
		if !slices.Contains(serverNames, alias) {
			t.Errorf("mmm's nginx serves no %s", alias)
		}
	}
}

// Whether two string maps hold the same entries; nil and empty are equal.
func mapsEqualStrings(a map[string]string, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}
