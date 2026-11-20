// Package run holds the options handed from the command line to the pipeline.
package run

import "time"

// Options is the parsed, validated command line.
type Options struct {
	Command            string
	Offline, Yes, JSON bool
	Since              time.Duration
}
