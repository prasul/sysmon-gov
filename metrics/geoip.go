package metrics

import (
	"net"
	"os"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPDefaults lists the most common install locations for the
// GeoLite2-Country database across popular Linux distributions.
var GeoIPDefaults = []string{
	"/usr/share/GeoIP/GeoLite2-Country.mmdb",
	"/var/lib/GeoIP/GeoLite2-Country.mmdb",
	"/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
	"/etc/GeoIP/GeoLite2-Country.mmdb",
	"./GeoLite2-Country.mmdb",
}

// NewGeoIPLookup returns a function that resolves an IP string to a
// two-letter ISO country code (e.g. "US", "DE", "IN").
//
// If dbPath is empty, common system paths are probed.  If no database
// is found at all, the returned function always returns "—" — the
// dashboard stays usable, just without country data.
//
// The underlying MaxMind reader is kept open for the lifetime of the
// process (it memory-maps the file, so lookups are very fast).
func NewGeoIPLookup(dbPath string) func(string) string {
	noopFn := func(string) string { return "—" }

	// Resolve the database path.
	if dbPath == "" {
		for _, p := range GeoIPDefaults {
			if _, err := os.Stat(p); err == nil {
				dbPath = p
				break
			}
		}
	}
	if dbPath == "" {
		return noopFn
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return noopFn
	}
	// Note: we intentionally never close db — it lives for the
	// entire process.  The mmap'd file uses minimal RSS.

	return func(ipStr string) string {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "—"
		}
		record, err := db.Country(ip)
		if err != nil || record.Country.IsoCode == "" {
			return "—"
		}
		return record.Country.IsoCode
	}
}
