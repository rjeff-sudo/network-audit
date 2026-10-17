// Package util contains small shared helpers used across the Sentry codebase.
package util

import "fmt"

// PortCountStr returns a human-readable string for a port count.
// Zero is displayed as "no" rather than "0" for friendlier UI copy.
func PortCountStr(n int) string {
	if n == 0 {
		return "no"
	}
	return fmt.Sprintf("%d", n)
}
