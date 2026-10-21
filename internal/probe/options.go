package probe

import "time"

type Options struct {
	Online       bool
	ProbeTimeout time.Duration
	AllowRoot    bool
	MaxOutput    int
}
