package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/docopt/docopt-go"

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
// prints one `<router> <management ipv4>` line per router
func vyosHosts(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	// only the routers section is needed; skip the port allocation and its log
	servicesConfig := getServicesConfig(env)
	if len(servicesConfig.Routers) == 0 {
		panic(fmt.Errorf("services config for %s has no routers", env))
	}
	for _, router := range servicesConfig.RouterNames() {
		Out.Printf("%s %s\n", router, servicesConfig.Routers[router].ManagementIpv4)
	}
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
