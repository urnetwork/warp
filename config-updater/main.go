package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/coreos/go-semver/semver"
	"github.com/docopt/docopt-go"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

var Out *log.Logger
var Err *log.Logger

func init() {
	Out = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	Err = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lshortfile)
}

/*
copy all dirs recursively from `/root/config/*` to `/srv/warp/config` in a safe sequence:
1. if `/srv/warp/config/<dir>` exixts, stop
2. if `/srv/warp/config/<dir>.tmp` exists, remove it
3. copy to `/srv/warp/config/<dir>.tmp`
4. mv `/srv/warp/config/<dir>.tmp` to `/srv/warp/config/<dir>`
*/
func main() {
	usage := `Warp control. Fluid iteration and zero downtime continuous release.

Usage:
    config-updater <source_dir> <dest_dir>

Options:
    -h --help                  Show this screen.
    --version                  Show version.`

	opts, err := docopt.ParseArgs(usage, os.Args[1:], CONFIG_UPDATER_VERSION)
	if err != nil {
		panic(err)
	}

	sourceDir, _ := opts.String("<source_dir>")
	destDir, _ := opts.String("<dest_dir>")

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		panic(err)
	}

	rootPaths := map[*semver.Version]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			versionStr := entry.Name()
			if version, err := semver.NewVersion(versionStr); err == nil {
				rootPaths[version] = filepath.Join(sourceDir, versionStr)
			} else {
				Err.Printf("Ignoring non-version dir (%s)\n", versionStr)
			}
		}
	}

	for version, rootPath := range rootPaths {
		targetRootPath := filepath.Join(destDir, version.String())
		if _, err := os.Stat(targetRootPath); !errors.Is(err, os.ErrNotExist) {
			Err.Printf("Target path already exists. Will not copy. (%s)\n", targetRootPath)
			continue
		}
		targetTempRootPath := filepath.Join(destDir, fmt.Sprintf("%s.tmp", version.String()))
		if _, err := os.Stat(targetTempRootPath); !errors.Is(err, os.ErrNotExist) {
			Err.Printf("Removing existing partial directory. (%s)\n", targetTempRootPath)
			os.RemoveAll(targetTempRootPath)
		}
		Err.Printf("Copy %s -> %s\n", rootPath, targetTempRootPath)
		err := copyConfig(rootPath, targetTempRootPath)
		if err != nil {
			Err.Printf("Error during copy. Version %s will not be deployed. (%s)\n", version.String(), err)
			continue
		}
		Err.Printf("Move %s -> %s\n", targetTempRootPath, targetRootPath)
		err = os.Rename(targetTempRootPath, targetRootPath)
		if err != nil {
			Err.Printf("Error during move. Version %s will not be deployed. (%s)\n", version.String(), err)
		}
	}
}

func copyConfig(sourceRootPath string, targetRootPath string) error {
	filepath.Walk(sourceRootPath, func(path string, info fs.FileInfo, err error) error {
		relPath, _ := filepath.Rel(sourceRootPath, path)
		targetPath := filepath.Join(targetRootPath, relPath)
		if info.IsDir() {
			os.Mkdir(targetPath, info.Mode())
		} else {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			os.WriteFile(targetPath, data, info.Mode())
		}
		return nil
	})
	return nil
}
