// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"regexp"
	"testing"
	"time"
)

func TestGetAbsoluteTs(t *testing.T) {
	ts := getAbsoluteTs()
	t.Logf("absolute timestamp: %s", ts)

	// ISO 8601 date-time with milliseconds: 2006-01-02T15:04:05.000
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}$`)
	if !re.MatchString(ts) {
		t.Fatalf("timestamp %q does not match ISO 8601 format", ts)
	}

	if _, err := time.Parse(absoluteTS, ts); err != nil {
		t.Fatalf("failed to parse timestamp %q: %v", ts, err)
	}
}
