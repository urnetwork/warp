package loki

import (
	"bytes"
	"log"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// entries print as [host][service][block][cid:<id>][<level>][<utc time>][<file:line>]<message>:
// a glog header is promoted into the level and file:line brackets and
// stripped, lines stored as bare json strings (the drop_single_key on
// window) unquote, and lines stored by the pre-cid pipeline (whole journal
// record as json, no cid label) unwrap to the message plus the record's
// CONTAINER_ID
func TestPrintEntryPrefixAndJournalRecordUnwrap(t *testing.T) {
	var out bytes.Buffer
	client := NewClient(
		"http://localhost",
		"",
		"",
		time.UTC,
		log.New(&out, "", 0),
		log.New(&out, "", 0),
	)

	entries := flattenStreams([]streamResult{
		{
			Stream: map[string]string{
				"host":    "by-us-fmt-5-edge-0",
				"service": "taskworker",
				"block":   "g2",
				"cid":     "a96b5f8e9fac",
			},
			Values: [][2]string{
				{"1", "I0810 21:40:31.487172       1 subscription_model.go:2886] [sm]force close contract: both sides"},
			},
		},
		{
			Stream: map[string]string{
				"host":    "by-us-fmt-5-edge-1",
				"service": "connect",
				"block":   "g4",
			},
			Values: [][2]string{
				{"2", `{"_UID":"0","CONTAINER_ID":"eedc54b608ef","MESSAGE":"I0810 21:39:48.708161       1 transport.go:498] [t]inactive auth jwt","PRIORITY":"3"}`},
			},
		},
		{
			Stream: map[string]string{
				"host":    "by-us-fmt-5-edge-3",
				"service": "connect",
				"block":   "g1",
				"cid":     "e2349f1f2bde",
			},
			Values: [][2]string{
				{"3", `"I0810 22:04:44.138794       1 transport.go:498] quoted interim line"`},
				{"4", "plain line without a glog header"},
			},
		},
	}, true)
	for _, entry := range entries {
		client.printEntry(entry)
	}

	assert.Equal(
		t,
		"[by-us-fmt-5-edge-0][taskworker][g2][cid:a96b5f8e9fac][I][1970-01-01T00:00:00.000000Z][subscription_model.go:2886][sm]force close contract: both sides\n"+
			"[by-us-fmt-5-edge-1][connect][g4][cid:eedc54b608ef][I][1970-01-01T00:00:00.000000Z][transport.go:498][t]inactive auth jwt\n"+
			"[by-us-fmt-5-edge-3][connect][g1][cid:e2349f1f2bde][I][1970-01-01T00:00:00.000000Z][transport.go:498]quoted interim line\n"+
			"[by-us-fmt-5-edge-3][connect][g1][cid:e2349f1f2bde][1970-01-01T00:00:00.000000Z]plain line without a glog header\n",
		out.String(),
	)
}

// without --utc the timestamp prints in the client location with its offset
func TestPrintEntryTimestampInClientLocation(t *testing.T) {
	var out bytes.Buffer
	client := NewClient(
		"http://localhost",
		"",
		"",
		time.FixedZone("CDT", -5*60*60),
		log.New(&out, "", 0),
		log.New(&out, "", 0),
	)

	client.printEntry(&logEntry{
		timestamp: 0,
		line:      "plain line",
		host:      "by-us-fmt-5-edge-3",
		service:   "connect",
		block:     "g1",
		cid:       "e2349f1f2bde",
	})

	assert.Equal(
		t,
		"[by-us-fmt-5-edge-3][connect][g1][cid:e2349f1f2bde][1969-12-31T19:00:00.000000-05:00]plain line\n",
		out.String(),
	)
}
