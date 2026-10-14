package geoip

import "testing"

// Ported from tests/test_geoip.py: without the database file, enrichment is simply off.
func TestMissingDatabaseTurnsEnrichmentOff(t *testing.T) {
	l := Open("/nonexistent/geo.mmdb")
	if _, off := l.(Off); !off || l.Country("1.46.10.5") != "" {
		t.Errorf("want the Off lookup, got %T", l)
	}
}

func TestNotAnIPHasNoCountry(t *testing.T) {
	if (&DB{}).Country("not-an-ip") != "" {
		t.Error("an invalid address has no country")
	}
}
