package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/docopt/docopt-go"
)

// warpctl dns plan <env> [--envalias=<envalias>] [--domain=<domain>] [--cloudflare-token-file=<path>]
// warpctl dns sync <env> [--envalias=<envalias>] [--domain=<domain>] [--cloudflare-token-file=<path>]
//
// plan prints the records each registrar would change; sync applies them.
func dnsPlan(opts docopt.Opts) {
	if err := dnsRun(opts, false); err != nil {
		panic(err)
	}
}

func dnsSync(opts docopt.Opts) {
	if err := dnsRun(opts, true); err != nil {
		panic(err)
	}
}

// defaultCloudflareTokenFile is where the controller keeps the token when
// no path is given: <WARP_HOME>/root/servers/cloudflare.
func defaultCloudflareTokenFile() string {
	warpHome := os.Getenv("WARP_HOME")
	if warpHome == "" {
		return ""
	}
	path := filepath.Join(warpHome, "root", "servers", "cloudflare")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func dnsRun(opts docopt.Opts, apply bool) error {
	env, _ := opts.String("<env>")
	envAliases := []string{}
	if envAlias, err := opts.String("--envalias"); err == nil && envAlias != "" {
		envAliases = append(envAliases, envAlias)
	}
	onlyDomain, _ := opts.String("--domain")
	tokenFile, _ := opts.String("--cloudflare-token-file")
	if tokenFile == "" {
		tokenFile = defaultCloudflareTokenFile()
	}

	servicesConfig := getServicesConfig(env)
	input := dnsPlanInput{Env: env, EnvAliases: envAliases, ServicesConfig: servicesConfig}
	domains, err := dnsDerive(input)
	if err != nil {
		return err
	}
	if onlyDomain != "" {
		selected := []*dnsDomain{}
		for _, domain := range domains {
			if domain.Domain == onlyDomain {
				selected = append(selected, domain)
			}
		}
		if len(selected) == 0 {
			return fmt.Errorf("%s is not a registrar domain of %s", onlyDomain, env)
		}
		domains = selected
	}

	ctx := context.Background()
	providers := map[string]dnsProvider{}
	provider := func(registrar string) (dnsProvider, error) {
		if existing, ok := providers[registrar]; ok {
			return existing, nil
		}
		var created dnsProvider
		switch registrar {
		case "route53":
			route53Provider, err := newRoute53Provider(ctx)
			if err != nil {
				return nil, err
			}
			created = route53Provider
		case "cloudflare":
			token, err := cloudflareToken(tokenFile)
			if err != nil {
				return nil, err
			}
			created = newCloudflareProvider(ctx, token)
		default:
			return nil, fmt.Errorf("unknown registrar %q", registrar)
		}
		providers[registrar] = created
		return created, nil
	}

	verb := "plan"
	if apply {
		verb = "sync"
	}
	failures := []string{}
	for _, domain := range domains {
		Out.Printf("== %s (%s) %s\n", domain.Domain, domain.Registrar, verb)
		registrar, err := provider(domain.Registrar)
		if err != nil {
			Out.Printf("!! %s\n", err)
			failures = append(failures, domain.Domain)
			continue
		}
		var changes []dnsChange
		if apply {
			changes, err = registrar.Apply(domain, input)
		} else {
			changes, err = registrar.Plan(domain, input)
		}
		if err != nil {
			Out.Printf("!! %s\n", err)
			failures = append(failures, domain.Domain)
			continue
		}
		for _, name := range domain.Names {
			Out.Printf("   %s\n", dnsNameSummary(name))
		}
		if len(changes) == 0 {
			Out.Printf("   no changes\n")
		}
		for _, change := range changes {
			Out.Printf("%s\n", change)
		}
		notes := append([]string{}, domain.Notes...)
		sort.Strings(notes)
		for _, note := range notes {
			Out.Printf("   note: %s\n", note)
		}
		if apply {
			Out.Printf("   applied %d changes\n", len(changes))
		} else {
			Out.Printf("   %d changes\n", len(changes))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("dns %s failed for %s", verb, strings.Join(failures, ", "))
	}
	return nil
}

// dnsNameSummary is one line per derived name for the plan.
func dnsNameSummary(name *dnsName) string {
	families := []string{}
	if name.HasIpv4 {
		families = append(families, "A")
	}
	if name.HasIpv6 {
		families = append(families, "AAAA")
	}
	switch name.Kind {
	case dnsLbSet:
		members := []string{}
		for _, member := range name.Members {
			members = append(members, fmt.Sprintf("%s=%d", member.Id, member.Weight))
		}
		return fmt.Sprintf("%s: lb set %s [%s]", name.Name, strings.Join(families, "+"), strings.Join(members, " "))
	case dnsAliasTo:
		return fmt.Sprintf("%s: alias %s -> %s", name.Name, strings.Join(families, "+"), name.Target)
	default:
		addresses := append(append([]string{}, name.Ipv4...), name.Ipv6...)
		return fmt.Sprintf("%s: %s %s", name.Name, strings.Join(families, "+"), strings.Join(addresses, " "))
	}
}
