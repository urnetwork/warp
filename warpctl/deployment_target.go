package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/coreos/go-semver/semver"
)

type deploymentVersionClient interface {
	GetLatestVersion(context.Context, string, string, string) (string, error)
	GetLatestVersionConsistent(context.Context, string, string, string) (string, error)
}

var errDeploymentTargetChanged = errors.New("deployment target changed before candidate start")

// A selected target is provisional until its owner reaches the start boundary.
// Each read is bounded by the existing poll interval and worker lifetime;
// a changed/unknown target returns to Run's normal polling and rollback path.
// It does not cancel a promoted deployment or shorten its predecessor drain.
func (self *RunWorker) verifyDeploymentTarget() error {
	ctx, cancel := context.WithTimeout(self.quitEvent.Ctx, WarpPollTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	version, err := self.dynamoClient.GetLatestVersionConsistent(ctx, self.env, self.service, self.block)
	if err != nil {
		return fmt.Errorf("recheck deployment selector before start: %w", err)
	}
	current, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("parse deployment selector before start: %w", err)
	}
	if self.deployedVersion == nil || *current != *self.deployedVersion {
		return errDeploymentTargetChanged
	}
	if self.needsConfigVersion() {
		entries, err := os.ReadDir(self.warpState.warpSettings.RequireConfigHome())
		if err != nil {
			return fmt.Errorf("recheck completed config before start: %w", err)
		}
		config := latestCompletedConfigVersion(entries)
		if config == nil || self.deployedConfigVersion == nil || *config != *self.deployedConfigVersion {
			return errDeploymentTargetChanged
		}
	}
	return ctx.Err()
}
