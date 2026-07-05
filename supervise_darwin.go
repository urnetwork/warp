//go:build darwin

package warp

import "syscall"

const soReusePort = syscall.SO_REUSEPORT
