package main

import (
	"time"
)

// activityDateTime ge 2025-07-23T00:00:00Z and activityDateTime le 2025-07-29T23:59:59Z
func getStructuredDate() (date string) {
	currentTime := time.Now().UTC().Format("2006-01-02T00:00:00Z")
	aWeekAgo := time.Now().UTC().Add(-168 * time.Hour).Format("2006-01-02T00:00:00Z")

	date = "activityDisplayName eq 'Reset password (self-service)' and activity DateTime ge " + currentTime + " and activityDateTime le " + aWeekAgo
	return date
}
