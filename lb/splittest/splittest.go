//go:build linux || darwin

// Package splittest runs §13.4's SNI split through a real nginx on loopback,
// with fake backends on both branches: a stand-in for tlsedge that records
// the PROXY header and ClientHello it is sent, and an http upstream that
// records each request and echoes upgraded connections. lb's tests, splitbench
// (TLS-M5-03), lbmap's reload test (TLS-M6-01) and later the custom-host tests
// (TLS-M6-07) run it; Lb.NginxControl hands its nginx to lbmap.
//
// The nginx config it writes carries the split's directives as warpctl's
// render writes them (warpctl/config_tls_split.go), on high loopback ports in
// place of 443 and 80 and with a fake upstream in place of the services; lb's
// tests hold the two to the same directives through the render's golden file.
// Its port 80 stand-in has the render's redirect server for the roots' names,
// lbmap's include inside it, but proxies where the render answers 301, since
// nginx_local has no rewrite module. It never listens on 443 or 80.
//
// The binary comes from NGINX_SPLIT_BINARY, which must then run and carry the
// split's modules, else the first capable candidate; a caller that finds none
// skips, but a set and wrong NGINX_SPLIT_BINARY is an error, never a skip.
//
// Nothing here imports testing, so a command can run it too. An Lb is safe for
// concurrent use; its backends record from their own goroutines.
package splittest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The environment variable naming the nginx binary the split's tests run.
const BinaryEnv = "NGINX_SPLIT_BINARY"

// The configure options the split needs of a binary: http with ssl and realip,
// and stream with ssl_preread.
var RequiredBuildOptions = []string{
	"--with-http_ssl_module",
	"--with-http_realip_module",
	"--with-stream",
	"--with-stream_ssl_preread_module",
}

// No binary was named and no candidate can run the split.
var ErrNoBinary = errors.New("no nginx that can run the split")

// Whether binary runs and its build carries every RequiredBuildOptions.
func CheckBinary(binary string) error {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return err
	}
	versionOutput, err := exec.Command(resolved, "-V").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -V: %w: %s", resolved, err, strings.TrimSpace(string(versionOutput)))
	}
	buildOptions := map[string]bool{}
	for _, field := range strings.Fields(string(versionOutput)) {
		buildOptions[field] = true
	}
	missing := []string{}
	for _, option := range RequiredBuildOptions {
		if !buildOptions[option] {
			missing = append(missing, option)
		}
	}
	if 0 < len(missing) {
		return fmt.Errorf("%s lacks %v", resolved, missing)
	}
	return nil
}

// Whether binary's map matches regular expressions, which it does with PCRE:
// the render's `"~:"` entry brackets an IPv6 X-UR-Forwarded-For only then.
// nginx_local leaves the rewrite module and PCRE out; the image builds both.
func BinaryHasRegex(binary string) (bool, error) {
	versionOutput, err := exec.Command(binary, "-V").CombinedOutput()
	if err != nil {
		return false, err
	}
	output := string(versionOutput)
	if strings.Contains(output, "--with-pcre") {
		return true, nil
	}
	return !strings.Contains(output, "--without-http_rewrite_module") && !strings.Contains(output, "--without-pcre"), nil
}

// The binary to run: NGINX_SPLIT_BINARY when set, an error if it cannot run
// the split; else the first of candidates that can, or ErrNoBinary with each
// candidate's reason.
func FindBinary(candidates []string) (string, error) {
	if configured := os.Getenv(BinaryEnv); configured != "" {
		if err := CheckBinary(configured); err != nil {
			return "", fmt.Errorf("%s=%q cannot run the split: %w", BinaryEnv, configured, err)
		}
		return exec.LookPath(configured)
	}
	rejections := []string{}
	for _, candidate := range candidates {
		if err := CheckBinary(candidate); err != nil {
			rejections = append(rejections, err.Error())
			continue
		}
		return exec.LookPath(candidate)
	}
	return "", fmt.Errorf("%w (%s); build one with make nginx_local in warp/lb, or set %s", ErrNoBinary, strings.Join(rejections, "; "), BinaryEnv)
}
