package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/cache"
	"github.com/cowsecurity/emudhraslop/internal/incident"
)

// RunObservation exposes a last-observed status for fleet inventory without
// turning stored evidence into a fresh scan or running discovered programs.
func RunObservation(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("observation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("cache", "", "owner-private stored report")
	maxAge := flags.Duration("max-age", 24*time.Hour, "maximum observation age")
	asJSON := flags.Bool("json", false, "emit historical status and observation time")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *maxAge <= 0 || *maxAge > 7*24*time.Hour {
		fmt.Fprintln(stderr, "emudhraslop: observation requires --cache FILE and an optional --max-age between 0 and 168h")
		return 1
	}
	in, err := incident.Load()
	if err != nil {
		fmt.Fprintln(stderr, "emudhraslop: embedded incident integrity validation failed")
		return 1
	}
	observation := cache.Observe(*path, Version, in.SHA256, *maxAge)
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(observation); err != nil {
			return 1
		}
	} else {
		value := "unknown"
		if observation.State == "fresh" && observation.LastObservedStatus != nil {
			value = "observed_" + string(*observation.LastObservedStatus)
		}
		if _, err := fmt.Fprintln(stdout, value); err != nil {
			return 1
		}
	}
	if observation.State != "fresh" {
		return 3
	}
	return 0
}
