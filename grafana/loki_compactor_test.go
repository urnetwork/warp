package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The rendered compactor settings that decide whether expired chunks leave
// the bucket.
type renderedLokiDocument struct {
	Server struct {
		GrpcListenPort int `yaml:"grpc_listen_port"`
	} `yaml:"server"`
	Common struct {
		Ring struct {
			InstancePort int `yaml:"instance_port"`
		} `yaml:"ring"`
		Storage struct {
			S3 struct {
				BucketNames string `yaml:"bucketnames"`
			} `yaml:"s3"`
		} `yaml:"storage"`
	} `yaml:"common"`
	Memberlist struct {
		BindPort      int `yaml:"bind_port"`
		AdvertisePort int `yaml:"advertise_port"`
	} `yaml:"memberlist"`
	Compactor struct {
		WorkingDirectory                string `yaml:"working_directory"`
		RetentionEnabled                bool   `yaml:"retention_enabled"`
		DeleteRequestStore              string `yaml:"delete_request_store"`
		DeletionMarkerObjectStorePrefix string `yaml:"deletion_marker_object_store_prefix"`
	} `yaml:"compactor"`
	LimitsConfig struct {
		RetentionPeriod string `yaml:"retention_period"`
	} `yaml:"limits_config"`
}

// renderedLoki renders the complete child document, the same one
// renderLokiConfig writes, and reads it back.
func renderedLoki(t *testing.T) renderedLokiDocument {
	t.Helper()
	hostSettings := &HostSettings{
		Routes: map[string]string{
			"edge-a": "192.0.2.10",
			"edge-b": "192.0.2.11",
			"minio":  "192.0.2.20",
		},
	}
	grafanaConfig := &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "minio", Bucket: "loki"},
		Loki:  &LokiConfig{ReplicationFactor: 3, Retention: "168h", MaxStorage: "1.5TiB"},
	}
	rendered, err := yaml.Marshal(lokiChildConfig("edge-a", "192.0.2.10", 3101, 16490, 16492, hostSettings, []string{"edge-a", "edge-b"}, grafanaConfig))
	if err != nil {
		t.Fatal(err)
	}
	var parsed renderedLokiDocument
	if err := yaml.Unmarshal(rendered, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

// Retention drops expired chunks from the index at once and leaves a mark
// for each; the sweeper deletes the chunks two hours later. Loki 3.7.3 keeps
// the marks in the compactor's working directory unless
// deletion_marker_object_store_prefix is set, and that directory is in the
// container. Each redeploy and each move of the compactor's leadership lost
// the marks still pending. Their chunks then had no index entry and no mark,
// so nothing ever deleted them. On 2026-11-06 the loki bucket held 1.03 TiB
// under 168h retention. In a 1/16 sample, 46% of the chunk bytes ended before
// 10-28, the oldest index table, some as far back as 07-19. The marks have
// to live in the bucket, where they survive the container and the next
// leader sweeps them.
func TestLokiCompactorKeepsDeletionMarksInTheBucket(t *testing.T) {
	loki := renderedLoki(t)

	if !loki.Compactor.RetentionEnabled || loki.Compactor.DeleteRequestStore != "s3" {
		t.Fatalf("retention_enabled=%t delete_request_store=%q, want true and s3", loki.Compactor.RetentionEnabled, loki.Compactor.DeleteRequestStore)
	}
	prefix := loki.Compactor.DeletionMarkerObjectStorePrefix
	if prefix == "" {
		t.Fatal("deletion marks stay on the container's disk: compactor.deletion_marker_object_store_prefix is unset")
	}
	// Loki 3.7.3 compactor Config.Validate refuses to start without the slash
	if !strings.HasSuffix(prefix, "/") {
		t.Fatalf("deletion_marker_object_store_prefix %q must end with /", prefix)
	}
	// the marks share the bucket with the tenant's chunks and the index,
	// which the orphan cleanup and the index shipper list by prefix
	for _, taken := range []string{"fake/", "index/"} {
		if strings.HasPrefix(prefix, taken) || strings.HasPrefix(taken, prefix) {
			t.Fatalf("deletion_marker_object_store_prefix %q overlaps %q", prefix, taken)
		}
	}
	if loki.LimitsConfig.RetentionPeriod != "168h" {
		t.Fatalf("retention_period = %q, want the configured 168h", loki.LimitsConfig.RetentionPeriod)
	}
}

// The document moved into lokiChildConfig so it can be read back without
// WARP_PORTS. The ring addresses it advertises must not have moved with it.
func TestLokiChildConfigKeepsTheRingPorts(t *testing.T) {
	loki := renderedLoki(t)

	if loki.Server.GrpcListenPort != 16490 || loki.Memberlist.BindPort != 16492 {
		t.Fatalf("listen ports grpc=%d gossip=%d, want the allocated 16490/16492", loki.Server.GrpcListenPort, loki.Memberlist.BindPort)
	}
	if loki.Common.Ring.InstancePort != defaultGrpcPort || loki.Memberlist.AdvertisePort != defaultGossipPort {
		t.Fatalf("advertised ports grpc=%d gossip=%d, want the fronted %d/%d", loki.Common.Ring.InstancePort, loki.Memberlist.AdvertisePort, defaultGrpcPort, defaultGossipPort)
	}
	if loki.Common.Storage.S3.BucketNames != "loki" {
		t.Fatalf("bucketnames = %q, want loki", loki.Common.Storage.S3.BucketNames)
	}
	if loki.Compactor.WorkingDirectory != "/var/lib/loki/compactor" {
		t.Fatalf("compactor working_directory = %q", loki.Compactor.WorkingDirectory)
	}
}
