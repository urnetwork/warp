//go:build linux || darwin

// This file owns the load-balancer regressions for NGINX UDP upstream PPv2.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This is the first upstream revision with UDP upstream PPv2 support.
const nginxUdpProxyV2Commit = "11d11b5f0d3d8ace5215e1a77918e9dc219ce7db"

// This pins the exact codeload archive bytes for the revision above.
const nginxUdpProxyV2SourceSha256 = "dbc96585a7ddc6f3c3a8faae9487ecdf5ad4e1e2eeb77a8b26e69d935434c9de"

// nginxUdpProxyV2TestBinary locates the explicitly selected binary first and
// then the repository-local build. The temporary candidate keeps existing
// developer builds usable while they migrate to `make nginx_local`.
func nginxUdpProxyV2TestBinary(t *testing.T) string {
	t.Helper()
	if configuredBinary := os.Getenv("NGINX_UDP_PROXY_V2_BINARY"); configuredBinary != "" {
		resolvedBinary, err := exec.LookPath(configuredBinary)
		if err != nil {
			t.Fatalf("NGINX_UDP_PROXY_V2_BINARY=%q is not executable: %v", configuredBinary, err)
		}
		return resolvedBinary
	}

	candidates := []string{
		filepath.Join("build", "nginx-local", "sbin", "nginx"),
		"/tmp/urnetwork-nginx-udp-v2-full/sbin/nginx",
	}
	for _, candidate := range candidates {
		resolvedBinary, err := exec.LookPath(candidate)
		if err == nil {
			return resolvedBinary
		}
	}

	t.Skip("pinned NGINX 1.31.4 build not found; run `make nginx_local` in warp/lb")
	return ""
}

// The image must build the known-capable source with the stream module rather
// than silently returning to a distribution package or floating source.
func TestDockerfilePinsNginxUdpProxyProtocolV2Support(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	requiredParts := []string{
		"ARG NGINX_COMMIT=" + nginxUdpProxyV2Commit,
		"ARG NGINX_SOURCE_SHA256=" + nginxUdpProxyV2SourceSha256,
		"${NGINX_SOURCE_SHA256}  nginx.tar.gz",
		"sha256sum --check --strict",
		"--with-stream",
		"org.opencontainers.image.nginx.commit=\"${NGINX_COMMIT}\"",
		"nginx -V",
	}
	for _, requiredPart := range requiredParts {
		if !strings.Contains(dockerfile, requiredPart) {
			t.Errorf("Dockerfile omits NGINX UDP PPv2 requirement %q", requiredPart)
		}
	}
	if strings.Count(dockerfile, "ARG NGINX_COMMIT="+nginxUdpProxyV2Commit) != 2 {
		t.Errorf("Dockerfile must pin the NGINX commit in both build and runtime stages")
	}
	if strings.Contains(dockerfile, "install -y nginx") {
		t.Error("Dockerfile installs a distribution NGINX over the pinned source build")
	}
}

// A capable NGINX must emit a valid PPv2 datagram with each client's original
// address and preserve bidirectional UDP pseudo-sessions.
func TestNginxUdpProxyProtocolV2EndToEnd(t *testing.T) {
	nginxBinary := nginxUdpProxyV2TestBinary(t)
	versionOutput, err := exec.Command(nginxBinary, "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("read NGINX build configuration: %v: %s", err, versionOutput)
	}
	if !bytes.Contains(versionOutput, []byte("--with-stream")) {
		t.Fatalf("NGINX binary omits the stream module: %s", versionOutput)
	}

	backendConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = backendConn.Close()
	})
	backendPort := backendConn.LocalAddr().(*net.UDPAddr).Port

	frontReservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	frontPort := frontReservation.LocalAddr().(*net.UDPAddr).Port
	if err := frontReservation.Close(); err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nginx.conf")
	config := fmt.Sprintf(`
worker_processes 2;
pid nginx.pid;
error_log stderr info;
daemon off;

events {
    worker_connections 128;
}

stream {
    upstream backend {
        server 127.0.0.1:%d;
    }

    server {
        listen 127.0.0.1:%d udp reuseport;
        proxy_protocol v2;
        proxy_timeout 1s;
        proxy_requests 0;
        proxy_pass backend;
    }
}
`, backendPort, frontPort)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(tempDir, "nginx-output.log")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	nginxCmd := exec.Command(nginxBinary, "-p", tempDir+string(os.PathSeparator), "-c", configPath)
	nginxCmd.Stdout = outputFile
	nginxCmd.Stderr = outputFile
	nginxCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := nginxCmd.Start(); err != nil {
		_ = outputFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-nginxCmd.Process.Pid, syscall.SIGQUIT)
		waitDone := make(chan error, 1)
		go func() {
			waitDone <- nginxCmd.Wait()
		}()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-nginxCmd.Process.Pid, syscall.SIGKILL)
			<-waitDone
		}
		_ = outputFile.Close()
		if t.Failed() {
			output, _ := os.ReadFile(outputPath)
			t.Logf("NGINX output:\n%s", output)
		}
	})

	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(tempDir, "nginx.pid")); err == nil {
			break
		}
		if readyDeadline.Before(time.Now()) {
			output, _ := os.ReadFile(outputPath)
			t.Fatalf("NGINX did not become ready:\n%s", output)
		}
		select {
		case <-time.After(5 * time.Millisecond):
		}
	}

	parseDatagram := func(packet []byte) (netip.AddrPort, []byte, error) {
		signature := []byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}
		if len(packet) < 28 || !bytes.Equal(packet[:len(signature)], signature) {
			return netip.AddrPort{}, nil, fmt.Errorf("PPv2 signature missing")
		}
		if packet[12] != 0x21 {
			return netip.AddrPort{}, nil, fmt.Errorf("version/command=%#x want=0x21", packet[12])
		}
		if packet[13] != 0x12 {
			return netip.AddrPort{}, nil, fmt.Errorf("family/protocol=%#x want IPv4 datagram 0x12", packet[13])
		}
		addressLength := int(binary.BigEndian.Uint16(packet[14:16]))
		payloadOffset := 16 + addressLength
		if addressLength < 12 || len(packet) < payloadOffset {
			return netip.AddrPort{}, nil, fmt.Errorf("invalid address length=%d packet length=%d", addressLength, len(packet))
		}
		var sourceOctets [4]byte
		copy(sourceOctets[:], packet[16:20])
		source := netip.AddrPortFrom(
			netip.AddrFrom4(sourceOctets),
			binary.BigEndian.Uint16(packet[24:26]),
		)
		return source, packet[payloadOffset:], nil
	}

	frontAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: frontPort}
	clients := make([]*net.UDPConn, 2)
	for clientIndex := range clients {
		client, err := net.DialUDP("udp4", nil, frontAddr)
		if err != nil {
			t.Fatal(err)
		}
		clients[clientIndex] = client
		t.Cleanup(func() {
			_ = client.Close()
		})
	}

	backendBuffer := make([]byte, 1600)
	clientBuffer := make([]byte, 1600)
	for clientIndex, client := range clients {
		request := bytes.Repeat([]byte{byte(clientIndex + 1)}, 1400)
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		if err := backendConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, proxyAddr, err := backendConn.ReadFrom(backendBuffer)
		if err != nil {
			t.Fatalf("read client %d datagram from NGINX: %v", clientIndex, err)
		}
		source, payload, err := parseDatagram(backendBuffer[:n])
		if err != nil {
			t.Fatalf("parse client %d PPv2 datagram: %v", clientIndex, err)
		}
		wantSource := client.LocalAddr().(*net.UDPAddr).AddrPort()
		wantSource = netip.AddrPortFrom(wantSource.Addr().Unmap(), wantSource.Port())
		if source != wantSource {
			t.Fatalf("client %d PPv2 source=%s want=%s", clientIndex, source, wantSource)
		}
		if !bytes.Equal(payload, request) {
			t.Fatalf("client %d payload changed after PPv2 header", clientIndex)
		}

		reply := []byte(fmt.Sprintf("reply-client-%d", clientIndex))
		if _, err := backendConn.WriteTo(reply, proxyAddr); err != nil {
			t.Fatalf("write client %d reply through NGINX: %v", clientIndex, err)
		}
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(clientBuffer)
		if err != nil {
			t.Fatalf("read client %d reply through NGINX: %v", clientIndex, err)
		}
		if !bytes.Equal(clientBuffer[:n], reply) {
			t.Fatalf("client %d reply changed in transit", clientIndex)
		}
	}
}
