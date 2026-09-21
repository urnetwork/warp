package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp/services"
	"github.com/urnetwork/warp/vyos"
)

// file names in the create-config out dir, the create-migration in dir and
// the create-migration out dir
func vyosConfigFileName(router string) string {
	return fmt.Sprintf("%s-config.boot", router)
}

func vyosLiveFileName(router string) string {
	return fmt.Sprintf("%s-live.config", router)
}

func vyosMigrationFileName(router string) string {
	return fmt.Sprintf("%s-migration.sh", router)
}

// vyosSelectedRouters returns the routers named by <router>, or all of them.
func vyosSelectedRouters(generator *VyosGenerator, opts docopt.Opts) []string {
	routers := generator.Routers()
	if router, err := opts.String("<router>"); err == nil && router != "" {
		if !slices.Contains(routers, router) {
			panic(fmt.Errorf("unknown router %q; routers are %v", router, routers))
		}
		return []string{router}
	}
	return routers
}

// warpctl vyos hosts <env>
// prints one `<router> <management ipv4> <class>` line per router that is
// rolled out; a planned router (not on the vpn yet) is left out
func vyosHosts(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	// only the routers section is needed; skip the port allocation and its log
	servicesConfig := getServicesConfig(env)
	if len(servicesConfig.Routers) == 0 {
		panic(fmt.Errorf("services config for %s has no routers", env))
	}
	for _, router := range servicesConfig.RouterNames() {
		routerConfig := servicesConfig.Routers[router]
		if routerConfig.Planned {
			Err.Printf("%s: planned, not rolled out\n", router)
			continue
		}
		Out.Printf("%s %s %s\n", router, routerConfig.ManagementIpv4, routerConfig.GetClass())
	}
}

// warpctl vyos update-settings <env> [<router>] --in=<indir>
// merges the hosts the live lan routers know (their dhcp static mappings,
// read from <indir>/<router>-live.config) into the lan_hosts block of
// config/<env>/settings.yml: hosts missing from the block are added, a
// host whose live address or mac differs is reported and left alone,
// nothing is removed. Prints what changed; changes no router.
func vyosUpdateSettings(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	inDir, err := opts.String("--in")
	if err != nil || inDir == "" {
		panic(errors.New("--in=<indir> is required"))
	}
	generator, err := NewVyosGenerator(env)
	if err != nil {
		panic(err)
	}
	if generator.settingsPath == "" {
		panic(fmt.Errorf("services config for %s has no lan router", env))
	}
	discovered := map[string]*services.LanHost{}
	discoveredBy := map[string]string{}
	lanRouters := 0
	for _, router := range vyosSelectedRouters(generator, opts) {
		class, err := generator.Class(router)
		if err != nil {
			panic(err)
		}
		if class != services.RouterClassLan {
			continue
		}
		lanRouters++
		hosts, err := vyosLiveLanHosts(generator, router, inDir)
		if err != nil {
			panic(err)
		}
		names := maps.Keys(hosts)
		sort.Strings(names)
		for _, name := range names {
			if other, ok := discoveredBy[name]; ok && *discovered[name] != *hosts[name] {
				panic(fmt.Errorf("%s and %s both map %s, differently", other, router, name))
			}
			discovered[name] = hosts[name]
			discoveredBy[name] = router
		}
	}
	if lanRouters == 0 {
		panic(fmt.Errorf("no lan router selected"))
	}
	document, err := os.ReadFile(generator.settingsPath)
	if err != nil {
		panic(err)
	}
	merge, err := services.MergeLanHosts(document, discovered)
	if err != nil {
		panic(err)
	}
	if string(merge.Document) != string(document) {
		if err := os.WriteFile(generator.settingsPath, merge.Document, 0644); err != nil {
			panic(err)
		}
	}
	for _, name := range merge.Added {
		Out.Printf("added %s %s %s\n", name, merge.Hosts[name].Ip, merge.Hosts[name].Mac)
	}
	for _, conflict := range merge.Conflicts {
		Out.Printf("conflict %s\n", conflict)
	}
	Out.Printf("%s: %d lan hosts, %d added, %d conflicts\n", generator.settingsPath, len(merge.Hosts), len(merge.Added), len(merge.Conflicts))
}

// vyosLiveLanHosts reads a lan router's live capture and returns the dhcp
// static mappings inside its lan.
func vyosLiveLanHosts(generator *VyosGenerator, router string, inDir string) (map[string]*services.LanHost, error) {
	routerConfig := generator.servicesConfig.Routers[router]
	lanIpv4, err := services.RouterLanIpv4(router, routerConfig)
	if err != nil {
		return nil, err
	}
	lan := lanIpv4.Masked()
	livePath := filepath.Join(inDir, vyosLiveFileName(router))
	liveText, err := os.ReadFile(livePath)
	if err != nil {
		return nil, err
	}
	live, err := vyos.Parse(string(liveText))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", livePath, err)
	}
	if hostNames := live.Root.LeafValues("system", "host-name"); len(hostNames) != 1 || hostNames[0] != router {
		return nil, fmt.Errorf("%s: host-name %v is not %s", livePath, hostNames, router)
	}
	hosts := map[string]*services.LanHost{}
	dhcp := live.Root.Lookup("service", "dhcp-server")
	if dhcp == nil {
		return hosts, nil
	}
	for _, networkKey := range dhcp.ContainerKeys() {
		if networkKey.Name != "shared-network-name" {
			continue
		}
		network := dhcp.Container(networkKey)
		for _, subnetKey := range network.ContainerKeys() {
			if subnetKey.Name != "subnet" {
				continue
			}
			subnet := network.Container(subnetKey)
			for _, mappingKey := range subnet.ContainerKeys() {
				if mappingKey.Name != "static-mapping" {
					continue
				}
				mapping := subnet.Container(mappingKey)
				ips := mapping.LeafValues("ip-address")
				macs := mapping.LeafValues("mac-address")
				if len(ips) != 1 || len(macs) != 1 {
					return nil, fmt.Errorf("%s: static-mapping %s has no ip-address and mac-address", livePath, mappingKey.Tag)
				}
				ip, err := netip.ParseAddr(ips[0])
				if err != nil || !lan.Contains(ip) {
					continue
				}
				hosts[mappingKey.Tag] = &services.LanHost{Ip: ips[0], Mac: strings.ToLower(macs[0])}
			}
		}
	}
	if err := services.ValidateLanHosts(hosts); err != nil {
		return nil, fmt.Errorf("%s: %w", livePath, err)
	}
	return hosts, nil
}

// warpctl vyos list-gateway-routes <env> [<router>]
// prints what the upstream gateway of each WAN block must route to the
// routers: the IPv6 /56 of every router to its WAN address, the note that
// IPv4 needs no route, and the pre-convention /64 routes to retire
func vyosListGatewayRoutes(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	generator, err := NewVyosGenerator(env)
	if err != nil {
		panic(err)
	}
	blocks, err := generator.GatewayRoutes(vyosSelectedRouters(generator, opts))
	if err != nil {
		panic(err)
	}
	Out.Print(vyosGatewayRoutesText(blocks))
}

// warpctl vyos create-config <env> [<router>] [--out=<outdir>]
// writes <outdir>/<router>-config.boot, or prints each config
func vyosCreateConfig(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	outDir, _ := opts.String("--out")

	generator, err := NewVyosGenerator(env)
	if err != nil {
		panic(err)
	}
	for _, router := range vyosSelectedRouters(generator, opts) {
		config, err := generator.Generate(router)
		if err != nil {
			panic(err)
		}
		if outDir == "" {
			Out.Printf("# router: %s\n\n%s\n", router, config.String())
			continue
		}
		if err := os.MkdirAll(outDir, 0755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, vyosConfigFileName(router)), []byte(config.String()), 0644); err != nil {
			panic(err)
		}
		Err.Printf("%s: wrote %s\n", router, filepath.Join(outDir, vyosConfigFileName(router)))
	}
}

// warpctl vyos create-migration <env> [<router>] --in=<indir> [--out=<outdir>] [--commit-confirm=<minutes>]
// reads <indir>/<router>-live.config (the router's `show configuration`) and
// writes <outdir>/<router>-migration.sh, or prints each script
func vyosCreateMigration(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	inDir, err := opts.String("--in")
	if err != nil || inDir == "" {
		panic(errors.New("--in=<indir> is required"))
	}
	outDir, _ := opts.String("--out")
	commitConfirmMinutes := 0
	if commitConfirm, err := opts.String("--commit-confirm"); err == nil && commitConfirm != "" {
		commitConfirmMinutes, err = strconv.Atoi(commitConfirm)
		if err != nil || commitConfirmMinutes < 1 {
			panic(fmt.Errorf("--commit-confirm must be a positive number of minutes: %q", commitConfirm))
		}
	}

	generator, err := NewVyosGenerator(env)
	if err != nil {
		panic(err)
	}
	for _, router := range vyosSelectedRouters(generator, opts) {
		script, migration, err := vyosMigrationScript(generator, env, router, inDir, commitConfirmMinutes)
		if err != nil {
			panic(err)
		}
		if outDir == "" {
			Out.Print(script)
		} else {
			if err := os.MkdirAll(outDir, 0755); err != nil {
				panic(err)
			}
			if err := os.WriteFile(filepath.Join(outDir, vyosMigrationFileName(router)), []byte(script), 0755); err != nil {
				panic(err)
			}
		}
		Err.Printf("%s: changes=%d deletes=%d sets=%d\n", router, len(migration.Deletes)+len(migration.Sets), len(migration.Deletes), len(migration.Sets))
	}
}

// vyosMigrationScript renders the migration for one router from its live
// capture. The capture must be the router's own: its host-name is checked
// against the router name so a capture from one router is never applied to
// another.
func vyosMigrationScript(generator *VyosGenerator, env string, router string, inDir string, commitConfirmMinutes int) (string, *vyos.Migration, error) {
	livePath := filepath.Join(inDir, vyosLiveFileName(router))
	liveText, err := os.ReadFile(livePath)
	if err != nil {
		return "", nil, err
	}
	live, err := vyos.Parse(string(liveText))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", livePath, err)
	}
	if hostNames := live.Root.LeafValues("system", "host-name"); len(hostNames) != 1 || hostNames[0] != router {
		return "", nil, fmt.Errorf("%s: host-name %v is not %s", livePath, hostNames, router)
	}
	desired, err := generator.Generate(router)
	if err != nil {
		return "", nil, err
	}
	protected, err := generator.ProtectedPaths(router)
	if err != nil {
		return "", nil, err
	}
	migration, err := vyos.Migrate(live.Root, desired.Root, vyos.MigrateOptions{Protected: protected})
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", router, err)
	}
	script := migration.Script(vyos.ScriptOptions{
		Router:               router,
		Env:                  env,
		CommitConfirmMinutes: commitConfirmMinutes,
	})
	return script, migration, nil
}
