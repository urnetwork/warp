package warp

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

func DefaultChildSettings() *ChildSettings {
	return &ChildSettings{
		StopSignal:   syscall.SIGTERM,
		StopTimeout:  30 * time.Second,
		RestartDelay: 1 * time.Second,
	}
}

type ChildSettings struct {
	StopSignal  syscall.Signal
	StopTimeout time.Duration
	// delay before restarting an exited child
	RestartDelay time.Duration
	// optional user to run the child as
	Username string
}

// Child runs a command in a restart loop until the event is set.
// When the event is set, the child is sent the stop signal,
// and killed after the stop timeout.
func Child(event *Event, name string, settings *ChildSettings, path string, args ...string) {
	var credential *syscall.Credential
	if settings.Username != "" {
		childUser, err := user.Lookup(settings.Username)
		if err != nil {
			panic(err)
		}
		uid, err := strconv.Atoi(childUser.Uid)
		if err != nil {
			panic(err)
		}
		gid, err := strconv.Atoi(childUser.Gid)
		if err != nil {
			panic(err)
		}
		credential = &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		}
	}

	for !event.IsSet() {
		cmd := exec.Command(path, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if credential != nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: credential,
			}
		}

		Err.Printf("[%s]start %s\n", name, path)
		if err := cmd.Start(); err != nil {
			Err.Printf("[%s]start error (%s)\n", name, err)
			event.WaitForSet(settings.RestartDelay)
			continue
		}

		done := make(chan struct{})
		go func() {
			select {
			case <-done:
				return
			case <-event.Ctx.Done():
			}

			cmd.Process.Signal(settings.StopSignal)

			select {
			case <-done:
			case <-time.After(settings.StopTimeout):
				cmd.Process.Kill()
			}
		}()

		err := cmd.Wait()
		close(done)

		if event.IsSet() {
			return
		}
		Err.Printf("[%s]exited (%v). Restarting.\n", name, err)
		event.WaitForSet(settings.RestartDelay)
	}
}

func reusePortControl(network string, address string, conn syscall.RawConn) error {
	var controlErr error
	err := conn.Control(func(fd uintptr) {
		controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	})
	if err != nil {
		return err
	}
	return controlErr
}

// ListenReusePort listens with SO_REUSEPORT,
// so that the old and new containers can both bind
// during a redeployment overlap
func ListenReusePort(addr string) (net.Listener, error) {
	listenConfig := &net.ListenConfig{Control: reusePortControl}
	return listenConfig.Listen(context.Background(), "tcp", addr)
}

// ListenReusePortPacket is the udp counterpart of ListenReusePort, for
// datagram protocols (e.g. memberlist gossip) that also need old and new
// containers to bind the same port during a redeployment overlap.
func ListenReusePortPacket(addr string) (net.PacketConn, error) {
	listenConfig := &net.ListenConfig{Control: reusePortControl}
	return listenConfig.ListenPacket(context.Background(), "udp", addr)
}

// ServiceHostPort is the host (internal) port allocated by warp
// for a service port, using the warp host networking env vars
func ServiceHostPort(servicePort int) (int, error) {
	hostNetwork, err := warpHostNetwork()
	if err != nil {
		return 0, err
	}
	hostPort, ok := hostNetwork.HostPorts[servicePort]
	if !ok {
		return 0, fmt.Errorf("Missing host port for service port %d", servicePort)
	}
	return hostPort, nil
}

// ServiceListenAddrs are the addresses a service listens on
// for a service port, using the warp host networking env vars.
// Without host networking, this is just the service port.
func ServiceListenAddrs(servicePort int) ([]string, error) {
	hostNetwork, err := warpHostNetwork()
	if err != nil {
		// not host networking
		return []string{fmt.Sprintf(":%d", servicePort)}, nil
	}

	hostPort, ok := hostNetwork.HostPorts[servicePort]
	if !ok {
		return nil, fmt.Errorf("Missing host port for service port %d", servicePort)
	}

	addrs := []string{}
	if hostNetwork.Ipv4 != nil {
		addrs = append(addrs, net.JoinHostPort(hostNetwork.Ipv4.String(), strconv.Itoa(hostPort)))
	}
	if hostNetwork.Ipv6 != nil {
		addrs = append(addrs, net.JoinHostPort(hostNetwork.Ipv6.String(), strconv.Itoa(hostPort)))
	}
	if len(addrs) == 0 {
		addrs = append(addrs, fmt.Sprintf(":%d", hostPort))
	}
	return addrs, nil
}
