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
	// optional liveness probe for a child that keeps running but stops
	// working. Exit is otherwise the only signal Child has, and a process can
	// be alive and permanently useless: a loki whose query modules never
	// leave Starting answers 503 forever without ever exiting
	// (SIGNALS.md 11.13). Nil leaves exit as the only restart trigger.
	HealthCheck func(ctx context.Context) error
	// how often to run HealthCheck
	HealthCheckInterval time.Duration
	// how long a child may stay continuously unhealthy before it is
	// restarted. The clock starts when the process starts, so this must
	// exceed the child's slowest legitimate start, and it must also exceed
	// the unready window a rolling fleet deploy opens (a ring-gated /ready
	// goes 503 while peers cycle).
	UnhealthyTimeout time.Duration
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

		if settings.HealthCheck != nil {
			go superviseHealth(event, name, settings, cmd, done)
		}

		err := cmd.Wait()
		close(done)

		if event.IsSet() {
			return
		}
		Err.Printf("[%s]exited (%v). Restarting.\n", name, err)
		event.WaitForSet(settings.RestartDelay)
	}
}

// superviseHealth stops a child that is still running but has been failing its
// health check for longer than the unhealthy timeout. It only signals the
// process; Child's own exit path observes the exit and restarts it, so the
// restart delay and stop timeout keep their single definition.
func superviseHealth(event *Event, name string, settings *ChildSettings, cmd *exec.Cmd, done chan struct{}) {
	// an unhealthy child is unhealthy from the moment it starts, so a child
	// that never becomes ready is restarted on the same timeout as one that
	// stops being ready later
	healthyTime := time.Now()

	for {
		select {
		case <-done:
			return
		case <-event.Ctx.Done():
			return
		case <-time.After(settings.HealthCheckInterval):
		}

		checkCtx, checkCancel := context.WithTimeout(event.Ctx, settings.HealthCheckInterval)
		err := settings.HealthCheck(checkCtx)
		checkCancel()

		if err == nil {
			healthyTime = time.Now()
			continue
		}

		unhealthyDuration := time.Since(healthyTime)
		if unhealthyDuration < settings.UnhealthyTimeout {
			continue
		}

		Err.Printf(
			"[%s]unhealthy for %s (%s). Restarting.\n",
			name,
			unhealthyDuration.Round(time.Second),
			err,
		)
		// the stop signal first, so a child that can still flush does
		cmd.Process.Signal(settings.StopSignal)
		select {
		case <-done:
		case <-time.After(settings.StopTimeout):
			cmd.Process.Kill()
		}
		return
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
