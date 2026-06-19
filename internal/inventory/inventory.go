package inventory

import (
	"sort"
	"strings"
	"time"

	"fahscan/pkg/types"
)

type Asset struct {
	Target           string    `json:"target"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ScanCount        int       `json:"scan_count"`
	OpenPorts        []int     `json:"open_ports"`
	Services         []string  `json:"services"`
	Products         []string  `json:"products"`
	FindingCount     int       `json:"finding_count"`
	HighestSeverity  string    `json:"highest_severity"`
	Exposure         string    `json:"exposure"`
	RecommendedFocus string    `json:"recommended_focus"`
}

type Snapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	Assets      []Asset   `json:"assets"`
	Totals      Totals    `json:"totals"`
}

type Totals struct {
	Targets       int `json:"targets"`
	OpenPorts     int `json:"open_ports"`
	Findings      int `json:"findings"`
	DatabasePorts int `json:"database_ports"`
	AdminPorts    int `json:"admin_ports"`
	WebPorts      int `json:"web_ports"`
}

func Build(scans []types.Scan, servicesByScan map[int64][]types.Service, findingsByScan map[int64][]types.Finding) Snapshot {
	assetsByTarget := map[string]*Asset{}
	for _, scan := range scans {
		asset := assetsByTarget[scan.Target]
		if asset == nil {
			asset = &Asset{Target: scan.Target, FirstSeen: scan.StartedAt, HighestSeverity: "info"}
			assetsByTarget[scan.Target] = asset
		}
		asset.ScanCount++
		if asset.FirstSeen.IsZero() || scan.StartedAt.Before(asset.FirstSeen) {
			asset.FirstSeen = scan.StartedAt
		}
		if scan.FinishedAt.After(asset.LastSeen) {
			asset.LastSeen = scan.FinishedAt
		}
		for _, service := range servicesByScan[scan.ID] {
			asset.OpenPorts = appendUniqueInt(asset.OpenPorts, service.Port)
			asset.Services = appendUniqueString(asset.Services, service.Service)
			asset.Products = appendUniqueString(asset.Products, service.Product)
		}
		for _, finding := range findingsByScan[scan.ID] {
			asset.FindingCount++
			asset.HighestSeverity = highest(asset.HighestSeverity, finding.Severity)
		}
		asset.Exposure = exposure(asset.OpenPorts, asset.Services)
		asset.RecommendedFocus = focus(*asset)
	}
	var snapshot Snapshot
	snapshot.GeneratedAt = time.Now()
	for _, asset := range assetsByTarget {
		sort.Ints(asset.OpenPorts)
		sort.Strings(asset.Services)
		sort.Strings(asset.Products)
		snapshot.Assets = append(snapshot.Assets, *asset)
	}
	sort.Slice(snapshot.Assets, func(i, j int) bool { return snapshot.Assets[i].Target < snapshot.Assets[j].Target })
	snapshot.Totals = summarize(snapshot.Assets)
	return snapshot
}

func summarize(assets []Asset) Totals {
	totals := Totals{Targets: len(assets)}
	for _, asset := range assets {
		totals.OpenPorts += len(asset.OpenPorts)
		totals.Findings += asset.FindingCount
		for _, service := range asset.Services {
			if isDatabase(service) {
				totals.DatabasePorts++
			}
			if isAdmin(service) {
				totals.AdminPorts++
			}
			if isWeb(service) {
				totals.WebPorts++
			}
		}
	}
	return totals
}

func exposure(ports []int, services []string) string {
	db, admin, remote, web := false, false, false, false
	for _, service := range services {
		switch {
		case isDatabase(service):
			db = true
		case isAdmin(service):
			admin = true
		case isRemoteAccess(service):
			remote = true
		case isWeb(service):
			web = true
		}
	}
	for _, port := range ports {
		switch port {
		case 21, 22, 23, 3389, 5900:
			remote = true
		case 3306, 5432, 6379, 9200, 27017, 11211:
			db = true
		case 8080, 8081, 8443, 8888, 9000, 9443:
			admin = true
		case 80, 443, 8000:
			web = true
		}
	}
	switch {
	case db && admin:
		return "database-and-admin"
	case db:
		return "database"
	case admin:
		return "admin"
	case remote:
		return "remote-access"
	case web:
		return "web"
	default:
		return "general"
	}
}

func focus(asset Asset) string {
	if asset.FindingCount == 0 && len(asset.OpenPorts) == 0 {
		return "No open services observed in the latest retained scans."
	}
	switch asset.Exposure {
	case "database-and-admin":
		return "Prioritize network restrictions for database and administrative services."
	case "database":
		return "Confirm database listener scope and owner."
	case "admin":
		return "Validate authentication and network controls for administrative surfaces."
	case "remote-access":
		return "Review remote access ownership, patching, and access policy."
	case "web":
		return "Review HTTP/TLS hardening findings and exposed metadata."
	default:
		return "Review open services and document ownership."
	}
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func highest(a, b string) string {
	weights := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	if weights[strings.ToLower(b)] > weights[strings.ToLower(a)] {
		return strings.ToLower(b)
	}
	if a == "" {
		return "info"
	}
	return strings.ToLower(a)
}

func isDatabase(service string) bool {
	service = strings.ToLower(service)
	for _, token := range []string{"mysql", "postgres", "mongodb", "redis", "mssql", "oracle", "elasticsearch", "memcached", "cassandra", "couchdb"} {
		if strings.Contains(service, token) {
			return true
		}
	}
	return false
}

func isAdmin(service string) bool {
	service = strings.ToLower(service)
	return strings.Contains(service, "admin") || strings.Contains(service, "grafana") || strings.Contains(service, "kibana")
}

func isWeb(service string) bool {
	service = strings.ToLower(service)
	return strings.Contains(service, "http") || service == "web" || strings.Contains(service, "https")
}

func isRemoteAccess(service string) bool {
	service = strings.ToLower(service)
	return strings.Contains(service, "ssh") || strings.Contains(service, "ftp") || strings.Contains(service, "telnet") || strings.Contains(service, "rdp")
}
