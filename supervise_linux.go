//go:build linux

package warp

// the linux syscall package does not export SO_REUSEPORT
const soReusePort = 0xf
