package main

// A process's deploy slot (sidecar QD-873 and QD-1011, its DESIGN §13.6 and owner decisions 428 and 577): warp
// hands each new process a small slot, WARP_SLOT beside WARP_BLOCK, and keeps it in the container's warp.slot
// label. An edge service (tlsedge, mxedge's router, smtpedge) derives its platform clients from (environment,
// host, block, slot, index), and on every lb host its beta and g1 blocks run side by side passing the same
// environment, host and block, so each running process of an edge service on a host holds a slot of its own: the
// beta and g1 processes, and a deploy's new process beside the old one of either, then each connect their own
// clients. A service is an edge service when it mounts the edge class's internal gate bearer,
// internal-gate-edge.yml, among its secret files, the credential its clients are minted on; mxedge-platform, whose
// containers share mxedge's name prefix, mounts none.
//
// startContainer takes an edge service's slot under the service's slot lock on the host, a file under WARP_HOME
// that every run worker of the service there shares, held from the listing until docker run has answered, so the
// beta and g1 workers never take one slot between them. It lists the service's running containers on the host by
// their warp.env and warp.service labels, never by name, reads the slot each holds from its warp.slot label, and
// gives the new process the lowest of DeploySlotSettings.SlotCount (4) that none holds. A container from before
// warp set the slot holds slot 0, as an edge block reads a missing WARP_SLOT; a label that is not a slot below the
// count holds none.
//
// Four slots hold every process an edge service runs on a host in the ordinary course: beta's and g1's, and a
// deploy's new process beside the old one draining, since a block's worker starts no candidate while its old
// drain is pending. Only a run worker's restart amid a drain can leave every slot held. The new process then
// takes none: its start is refused before the candidate starts, as a full port pool refuses it, and the watcher
// tries again at its next poll, which finds a slot free once a drain has ended. A slot listing that cannot be read,
// or a slot lock not taken in time, stops the deploy the same way.
//
// Every other service ignores the value: its process takes slot 0, and nothing is listed or locked for it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The labels a container carries its environment, service and slot in, beside warp.block. The slot listing
// filters on the first two.
const (
	warpEnvLabel     = "warp.env"
	warpServiceLabel = "warp.service"
	deploySlotLabel  = "warp.slot"
)

// The secret file of the edge class's internal gate bearer (server's internal_gate.go), which every edge service
// mounts and no other service does.
const deploySlotEdgeBearerSecretFile = "internal-gate-edge.yml"

// The slot lock's file name under WARP_HOME, before its env and service.
const deploySlotLockFilePrefix = "warpctl-deploy-slot"

// Every slot of the service on this host is held: the start waits for a drain to end.
var errDeploySlotsHeld = errors.New("every deploy slot of the service on this host is held")

// The deploy slot's tunables.
type DeploySlotSettings struct {
	// The slots an edge service's processes on one host take: 4, its beta and g1 blocks' processes and a deploy's
	// new process beside either. The edge clients' api refuses a slot at or past its own count, server's
	// EdgeClientKeySettings.SlotCount, which is the same number. Below 2 no deploy could start its new process
	// beside the old one, and every start is refused.
	SlotCount int
	// How long an edge service's new process waits for the slot lock while another block's worker holds it, which
	// it does from its listing until its docker run answers: 2 minutes. Not taken by then, the start is refused and
	// the next poll tries again. Not positive: one try.
	LockTimeout time.Duration
	// How long the wait sleeps between tries of the lock: 200 ms, as the host drain lock's. Not positive refuses
	// the start, since the wait would spin.
	LockRetryInterval time.Duration
}

func DefaultDeploySlotSettings() *DeploySlotSettings {
	return &DeploySlotSettings{
		SlotCount:         4,
		LockTimeout:       2 * time.Minute,
		LockRetryInterval: 200 * time.Millisecond,
	}
}

// One running process of the service, as docker ps lists it.
type deploySlotProcess struct {
	containerId string
	name        string
	// the slot it holds, when slotValid
	slot      int
	slotValid bool
}

// Reads docker ps's lines of `<id>\t<name>\t<warp.slot label>`. A line that is not three fields is an answer warp
// cannot read, and refuses. A missing label is slot 0; a label that is not a slot below slotCount holds none.
func parseDeploySlotProcesses(out []byte, slotCount int) ([]*deploySlotProcess, error) {
	processes := []*deploySlotProcess{}
	// line by line, never trimming the whole answer: a last line whose label is empty ends in its tab
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("docker ps answered a line that is not a container's id, name and slot: %q", line)
		}
		process := &deploySlotProcess{containerId: fields[0], name: fields[1]}
		switch label := fields[2]; label {
		case "":
			// started before warp set the slot: an edge block reads its missing WARP_SLOT as 0
			process.slot, process.slotValid = 0, true
		default:
			slot, err := strconv.Atoi(label)
			if err == nil && strconv.Itoa(slot) == label && 0 <= slot && slot < slotCount {
				process.slot, process.slotValid = slot, true
			}
		}
		processes = append(processes, process)
	}
	return processes, nil
}

// The lowest slot below slotCount that none of processes holds; false when they hold every one.
func selectDeploySlot(processes []*deploySlotProcess, slotCount int) (int, bool) {
	heldSlots := map[int]bool{}
	for _, process := range processes {
		if process.slotValid {
			heldSlots[process.slot] = true
		}
	}
	for slot := range slotCount {
		if !heldSlots[slot] {
			return slot, true
		}
	}
	return 0, false
}

// Whether the service holds edge clients, and so each of its processes on a host a slot of its own: whether it
// mounts the edge class's bearer.
func (self *RunWorker) holdsEdgeClients() bool {
	return slices.Contains(self.secretFiles, deploySlotEdgeBearerSecretFile)
}

// The slot lock's file for the service on this host.
func (self *RunWorker) deploySlotLockPath() string {
	return filepath.Join(
		self.warpState.warpSettings.RequireWarpHome(),
		fmt.Sprintf(
			"%s-%s-%s.lock",
			deploySlotLockFilePrefix,
			sanitizeHostDrainLockNamePart(self.env),
			sanitizeHostDrainLockNamePart(self.service),
		),
	)
}

// Takes the service's slot lock on this host, trying again each LockRetryInterval until LockTimeout passes or the
// worker quits. Closing the file releases it.
func (self *RunWorker) lockDeploySlot(settings *DeploySlotSettings) (*os.File, error) {
	file, err := os.OpenFile(self.deploySlotLockPath(), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open the deploy slot lock: %w", err)
	}
	deadline := time.Now().Add(settings.LockTimeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if err != syscall.EWOULDBLOCK {
			file.Close()
			return nil, fmt.Errorf("take the deploy slot lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			file.Close()
			return nil, fmt.Errorf("the deploy slot lock was not taken within %s", settings.LockTimeout)
		}
		if self.quitEvent.WaitForSet(settings.LockRetryInterval) {
			file.Close()
			return nil, errors.New("quit while waiting for the deploy slot lock")
		}
	}
}

// The slot the service's next process on this host takes, and the release of the slot lock, which startContainer
// calls once its docker run has answered, so the process it started is listed with its slot before another block's
// worker lists. An edge service with every slot held is refused (errDeploySlotsHeld). A service that holds no edge
// clients takes slot 0, and nothing is listed or locked.
func (self *RunWorker) takeDeploySlot() (int, func(), error) {
	settings := self.deploySlotSettings
	if settings == nil {
		settings = DefaultDeploySlotSettings()
	}
	if !self.holdsEdgeClients() {
		return 0, func() {}, nil
	}
	if settings.SlotCount < 2 {
		return 0, nil, errors.New("a deploy slot count below 2 cannot start a deploy beside its old process")
	}
	if settings.LockRetryInterval <= 0 {
		return 0, nil, errors.New("a deploy slot lock needs a positive retry interval")
	}
	lockFile, err := self.lockDeploySlot(settings)
	if err != nil {
		return 0, nil, err
	}
	release := sync.OnceFunc(func() {
		// closing the file releases the lock
		lockFile.Close()
	})
	slot, err := func() (int, error) {
		// running containers only, a stopped one holding no clients; by labels, never by name, since a name prefix
		// of one service can be another's (mxedge's is mxedge-platform's)
		psCmd := docker(
			"ps",
			"-f", fmt.Sprintf("label=%s=%s", warpEnvLabel, self.env),
			"-f", fmt.Sprintf("label=%s=%s", warpServiceLabel, self.service),
			"--format", fmt.Sprintf("{{.ID}}\t{{.Names}}\t{{.Label %q}}", deploySlotLabel),
		)
		out, err := outAndLog(psCmd)
		if err != nil {
			return 0, fmt.Errorf("list the service's running slots: %w", err)
		}
		processes, err := parseDeploySlotProcesses(out, settings.SlotCount)
		if err != nil {
			return 0, err
		}
		slot, free := selectDeploySlot(processes, settings.SlotCount)
		if !free {
			holders := []string{}
			for _, process := range processes {
				if process.slotValid {
					holders = append(holders, fmt.Sprintf("%s in slot %d", process.name, process.slot))
				}
			}
			return 0, fmt.Errorf(
				"%w (%s): the start waits for a drain to end, and the next poll tries again",
				errDeploySlotsHeld,
				strings.Join(holders, ", "),
			)
		}
		return slot, nil
	}()
	if err != nil {
		release()
		return 0, nil, err
	}
	return slot, release, nil
}
