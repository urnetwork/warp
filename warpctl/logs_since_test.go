package main

import (
	"strings"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// --since takes either a lookback duration or a start timestamp
func TestParseSinceDurationOrTimestamp(t *testing.T) {
	chicago := time.FixedZone("CDT", -5*60*60)
	tokyo := time.FixedZone("JST", 9*60*60)
	now := time.Date(2026, 8, 10, 22, 45, 0, 0, time.UTC)

	for _, testCase := range []struct {
		since    string
		location *time.Location
		expected time.Time
	}{
		// durations are relative to now, in either sign
		{"5m", time.UTC, time.Date(2026, 8, 10, 22, 40, 0, 0, time.UTC)},
		{"2h30m", time.UTC, time.Date(2026, 8, 10, 20, 15, 0, 0, time.UTC)},
		{"-5m", time.UTC, time.Date(2026, 8, 10, 22, 40, 0, 0, time.UTC)},

		// a timestamp with an offset or Z is taken at that offset, whatever
		// the display location
		{
			"2026-08-10T17:29:32.005459-05:00", time.UTC,
			time.Date(2026, 8, 10, 22, 29, 32, 5459000, time.UTC),
		},
		{
			"2026-08-10T22:29:32.005459Z", chicago,
			time.Date(2026, 8, 10, 22, 29, 32, 5459000, time.UTC),
		},
		{
			"2026-08-10T17:29:32-05:00", time.UTC,
			time.Date(2026, 8, 10, 22, 29, 32, 0, time.UTC),
		},

		// a timestamp without a zone is read in the display location
		{
			"2026-08-10T17:29:32", chicago,
			time.Date(2026, 8, 10, 22, 29, 32, 0, time.UTC),
		},
		{
			"2026-08-10 17:29:32", chicago,
			time.Date(2026, 8, 10, 22, 29, 32, 0, time.UTC),
		},
		{
			"2026-08-10 17:29", chicago,
			time.Date(2026, 8, 10, 22, 29, 0, 0, time.UTC),
		},
		{
			"2026-08-10", chicago,
			time.Date(2026, 8, 10, 5, 0, 0, 0, time.UTC),
		},
		{
			"2026-08-10T17:29:32", tokyo,
			time.Date(2026, 8, 10, 8, 29, 32, 0, time.UTC),
		},

		// a time with no date is today in the display location. now is
		// 2026-08-10T22:45Z, which is 2026-08-10 in chicago and already
		// 2026-08-11 in tokyo
		{
			"17:29:32", chicago,
			time.Date(2026, 8, 10, 22, 29, 32, 0, time.UTC),
		},
		{
			"17:29", chicago,
			time.Date(2026, 8, 10, 22, 29, 0, 0, time.UTC),
		},
		{
			"17:29", tokyo,
			time.Date(2026, 8, 11, 8, 29, 0, 0, time.UTC),
		},
	} {
		t.Run(testCase.since, func(t *testing.T) {
			start, err := parseSince(testCase.since, testCase.location, now)
			assert.Equal(t, nil, err)
			assert.Equal(t, true, start.Equal(testCase.expected))
		})
	}
}

// an unparseable --since names the accepted forms instead of failing blankly
func TestParseSinceRejectsUnknownForms(t *testing.T) {
	now := time.Date(2026, 8, 10, 22, 45, 0, 0, time.UTC)

	for _, since := range []string{"", "yesterday", "5", "5 minutes", "08/10/2026"} {
		t.Run(since, func(t *testing.T) {
			_, err := parseSince(since, time.UTC, now)
			assert.NotEqual(t, nil, err)
			assert.Equal(t, true, strings.Contains(err.Error(), "must be a duration"))
		})
	}
}
