// Package geoip looks up the country of an IP address, once at ingest, so search, the dashboard
// and alerts can all use it.
//
// Data: DB-IP "IP to Country Lite" (free, CC BY 4.0: the website links to db-ip.com as the
// licence asks). The file is downloaded when the image is built and read locally: no lookup
// ever leaves the server. Without the file, enrichment is simply off and nothing else changes.
package geoip

import (
	"log"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// Lookup gives a two-letter country code ("TH", "DE"), or "" for private, reserved or unknown
// addresses (10.x, 192.168.x and the documentation ranges in the assignment samples have none).
type Lookup interface {
	Country(ip string) string
}

// Off is the lookup used when there is no database: every answer is "".
type Off struct{}

func (Off) Country(string) string { return "" }

type DB struct{ reader *maxminddb.Reader }

// Open loads the database, or returns Off (with a warning) if the file isn't there.
func Open(path string) Lookup {
	if path == "" {
		return Off{}
	}
	if _, err := os.Stat(path); err != nil {
		log.Printf("geoip: database not found at %q; country enrichment is off", path)
		return Off{}
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		log.Printf("geoip: can't read %q (%v); country enrichment is off", path, err)
		return Off{}
	}
	return &DB{reader: r}
}

func (d *DB) Country(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	// A lookup is a few microseconds (a tree walk in a memory-mapped file), so unlike the
	// Python version there's no cache in front of it.
	if err := d.reader.Lookup(parsed, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}
