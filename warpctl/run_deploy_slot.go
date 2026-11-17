package main

// A block's deploy slot (sidecar QD-873, its DESIGN §13.6 and owner decision 428): warp hands each process of a
// block on a host a small slot, WARP_SLOT beside WARP_BLOCK, alternating per deploy, so a deploy's new process
// never holds the slot of the old process it replaces while the old one drains. An edge block (tlsedge, mxedge's
// router, smtpedge) derives its platform clients from (environment, host, block, slot, index), so its old and new
// process hold disjoint clients through the drain; every other service ignores the value.
//
// startContainer lists the block's running containers on this host, reads the slot each was given from its
// warp.slot label, set from the same value as its WARP_SLOT, and gives the new process the lowest slot none of
// them holds. In the steady state one process of the block runs, so the new process takes the other slot. A
// container from before warp set the slot holds slot 0, as an edge block reads a missing WARP_SLOT.
//
// Only a run worker's restart amid an earlier drain leaves more than one process of a block running when the next
// deploy starts (the worker otherwise joins the old drain first), and then every slot can be held. The new process
// then takes the lowest slot the newest running process does not hold: the newest is the one this deploy replaces,
// so the new process still never shares its slot, and it shares one with an older process that is already
// draining, whose edge clients the new one's then displace; this is said in the log. A slot listing that cannot be
// read stops the deploy before the candidate starts, as a failed pull does.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The label a container carries its slot in, beside warp.block.
const deploySlotLabel = "warp.slot"

// The deploy slot's tunables.
type DeploySlotSettings struct {
	// The slots a block's processes on one host alternate between: 2, a deploy's old process and its new one.
	// The edge clients' api refuses a slot at or past its own count, server's EdgeClientKeySettings.SlotCount,
	// which is the same number. Below 2 nothing can alternate, and a deploy refuses to start.
	SlotCount int
}

func DefaultDeploySlotSettings() *DeploySlotSettings {
	return &DeploySlotSettings{
		SlotCount: 2,
	}
}

// One running process of the block, as docker ps lists it.
type deploySlotProcess struct {
	containerId string
	// from the container's name, which ends in the millisecond warp started it at; 0 when it does not
	startMillis int64
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
		process := &deploySlotProcess{containerId: fields[0]}
		if i := strings.LastIndex(fields[1], "-"); 0 <= i {
			if startMillis, err := strconv.ParseInt(fields[1][i+1:], 10, 64); err == nil {
				process.startMillis = startMillis
			}
		}
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

// The slot a deploy's new process takes beside the block's running processes on this host: see the file header.
// shared says the slot is one an older running process already holds.
func selectDeploySlot(processes []*deploySlotProcess, slotCount int) (slot int, shared bool) {
	heldSlots := map[int]bool{}
	var newest *deploySlotProcess
	for _, process := range processes {
		if process.slotValid {
			heldSlots[process.slot] = true
		}
		if newest == nil || newest.startMillis < process.startMillis {
			newest = process
		}
	}
	for slot := range slotCount {
		if !heldSlots[slot] {
			return slot, false
		}
	}
	// every slot held: never the newest process's, the one this deploy replaces
	for slot := range slotCount {
		if !newest.slotValid || slot != newest.slot {
			return slot, true
		}
	}
	return 0, true
}

// The slot the block's next process on this host takes, from the block's running containers.
func (self *RunWorker) deploySlot() (int, error) {
	settings := self.deploySlotSettings
	if settings == nil {
		settings = DefaultDeploySlotSettings()
	}
	if settings.SlotCount < 2 {
		return 0, errors.New("a deploy slot count below 2 cannot alternate")
	}
	containerNamePrefix := fmt.Sprintf(
		"%s-%s-%s-",
		self.env,
		self.service,
		self.block,
	)
	// running containers only: a stopped one holds no clients
	psCmd := docker(
		"ps",
		"-f", containerNamePrefixFilter(containerNamePrefix),
		"--format", fmt.Sprintf("{{.ID}}\t{{.Names}}\t{{.Label %q}}", deploySlotLabel),
	)
	out, err := outAndLog(psCmd)
	if err != nil {
		return 0, fmt.Errorf("list the block's running slots: %w", err)
	}
	processes, err := parseDeploySlotProcesses(out, settings.SlotCount)
	if err != nil {
		return 0, err
	}
	slot, shared := selectDeploySlot(processes, settings.SlotCount)
	if shared {
		Err.Printf(
			"Deploy slot %d is held by an older draining process: %d running processes of the block hold every slot\n",
			slot,
			len(processes),
		)
	}
	return slot, nil
}
