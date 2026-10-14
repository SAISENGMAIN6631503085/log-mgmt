package normalize

import (
	"fmt"
	"time"
)

// Func is one source's normalizer: (payload, tenant, now) -> Event. `now` is the receipt time:
// syslog lines have no year, and API events without a time are stored at it.
type Func func(payload any, tenant string, now time.Time) (*Event, error)

var registry = map[string]Func{
	"firewall": Firewall, "network": Network, "api": API, "crowdstrike": CrowdStrike,
	"aws": AWS, "m365": M365, "ad": AD,
}

// Known reports whether a source name has a normalizer.
func Known(source string) bool {
	_, ok := registry[source]
	return ok
}

// Normalize runs the source's normalizer and validates the result.
func Normalize(source string, payload any, tenant string, now time.Time) (*Event, error) {
	fn, ok := registry[source]
	if !ok {
		return nil, fmt.Errorf("unknown source %q; expected one of %v", source, Sources)
	}
	e, err := fn(payload, tenant, now)
	if err != nil {
		return nil, err
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}
