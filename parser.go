package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func parseGeoSite() {
	f, err := os.Open("geosite.dat")
	if err != nil {
		log.Fatal("failed to open file:", err)
	}
	defer f.Close()

	// Read the file directly without gzip decompression
	geositeBytes, err := io.ReadAll(f)
	if err != nil {
		log.Fatal("failed to read data:", err)
	}

	// Unmarshal the protobuf data.
	var geositeList routercommon.GeoSiteList
	if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
		log.Fatal("failed to unmarshal data:", err)
	}

	i := 0
	// Iterate over the SiteGroup field in the GeoSiteList.
	for _, group := range geositeList.Entry {
		i++
		log.Printf("%d, Group: %s", i, group.CountryCode)
		for _, domain := range group.GetDomain() {
			log.Printf("  Domain: type=%v, value=%s", domain.GetType(), domain.GetValue())
			// Optionally, iterate over domain attributes if available.
			for _, attr := range domain.GetAttribute() {
				log.Printf("    Attribute: key=%s", attr.GetKey())
			}
		}
	}
}

func parseGeoIP() {
	// Open the geoip.dat file
	f, err := os.Open("geoip.dat")
	if err != nil {
		log.Fatal("failed to open file:", err)
	}
	defer f.Close()

	// Read the file directly
	geoipBytes, err := io.ReadAll(f)
	if err != nil {
		log.Fatal("failed to read data:", err)
	}

	// Unmarshal the protobuf data
	var geoipList routercommon.GeoIPList
	if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
		log.Fatal("failed to unmarshal data:", err)
	}

	i := 0
	// Iterate over the entries in the GeoIPList
	for _, entry := range geoipList.Entry {
		i++
		log.Printf("%d, Country: %s", i, entry.CountryCode)
		time.Sleep(1 * time.Second)

		// Iterate over CIDR entries
		for _, cidr := range entry.GetCidr() {
			// Extract IP and prefix from CIDR
			ip := cidr.GetIp()
			prefix := cidr.GetPrefix()

			// Convert IP bytes to string representation
			ipStr := ""
			if len(ip) == 4 {
				// IPv4
				ipStr = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
			} else if len(ip) == 16 {
				// IPv6 - simplified display
				ipStr = fmt.Sprintf("%x:%x:%x:%x:...", ip[0], ip[1], ip[2], ip[3])
			}

			log.Printf("  CIDR: %s/%d", ipStr, prefix)
		}
	}
}

func main() {
	parseGeoSite()
	parseGeoIP()

	time.Sleep(5 * time.Second)

}
