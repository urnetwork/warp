package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/urnetwork/warp"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

func main() {
	block := os.Getenv("WARP_BLOCK")
	if block == "" {
		panic(errors.New("WARP_BLOCK must be set."))
	}

	configPath := fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", block)
	convertedConfigPath := fmt.Sprintf("/srv/warp/nginx.conf/%s_host.conf", block)

	err, exitCode := warp.NginxWithDefaults(configPath, convertedConfigPath)
	if err != nil {
		panic(err)
	}
	os.Exit(exitCode)
}
