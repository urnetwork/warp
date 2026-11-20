package main

// The nginx config and a host_services list that names a service the services
// config does not define.

import (
	"strings"
	"testing"
)

// The test services with host_services listing hostServices for
// edge-0.example.com in the latest version, which the lb is generated from.
func nginxHostServicesYaml(t *testing.T, hostServices ...string) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)
	// the first services block is the latest version's
	servicesBlock := "    services:\n        svc-a:\n"
	if !strings.Contains(servicesYaml, servicesBlock) {
		t.Fatal("test services fixture lacks the latest version's services")
	}
	hostServicesBlock := "    host_services:\n        edge-0.example.com:\n"
	for _, service := range hostServices {
		hostServicesBlock += "            - " + service + "\n"
	}
	return []byte(strings.Replace(servicesYaml, servicesBlock, hostServicesBlock+servicesBlock, 1))
}

// A host_services name the latest version does not define, which a service
// removed from services but not from host_services leaves, is refused when the
// nginx config is made, as the lb_alt route render refuses it. Generate
// renders every service the lb fronts on a host from the service's config, so
// it dereferenced the missing config of an accepted name. The same list
// without the name renders.
func TestNginxConfigRefusesAFrontedServiceTheConfigDoesNotDefine(t *testing.T) {
	definedServices := []string{"svc-a", "svc-b", "svc-c", "svc-d", "taskworker"}
	env, _ := setupTestVaultWithTLS(t, nginxHostServicesYaml(t, definedServices...))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blockConfigs := nginxConfig.Generate(); len(blockConfigs) == 0 {
		t.Fatal("no lb block config was generated")
	}

	env, _ = setupTestVaultWithTLS(t, nginxHostServicesYaml(t, append(definedServices, "ghost")...))
	nginxConfig, err = NewNginxConfig(env, nil)
	if err == nil {
		// what Generate makes of the accepted name
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewNginxConfig accepted host_services naming ghost, and Generate panicked: %v", r)
			}
		}()
		nginxConfig.Generate()
		t.Fatal("NewNginxConfig accepted host_services naming ghost")
	}
	if want := `edge-0.example.com fronts service "ghost", which the services config does not define`; !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}
