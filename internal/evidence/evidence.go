package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"fahscan/pkg/types"
)

type Item struct {
	Source      string            `json:"source"`
	Target      string            `json:"target"`
	Port        int               `json:"port,omitempty"`
	Kind        string            `json:"kind"`
	Summary     string            `json:"summary"`
	Value       string            `json:"value,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CollectedAt time.Time         `json:"collected_at"`
}

type Bundle struct {
	ScanID      int64     `json:"scan_id"`
	Target      string    `json:"target"`
	Items       []Item    `json:"items"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

func FromService(target string, service types.Service) []Item {
	var items []Item
	if strings.TrimSpace(service.Banner) != "" {
		items = append(items, Item{
			Source:      "tcp",
			Target:      target,
			Port:        service.Port,
			Kind:        "banner",
			Summary:     "TCP banner collected",
			Value:       service.Banner,
			CollectedAt: service.CreatedAt,
		})
	}
	keys := make([]string, 0, len(service.Metadata))
	for key := range service.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(service.Metadata[key]) == "" {
			continue
		}
		items = append(items, Item{
			Source:      service.Protocol,
			Target:      target,
			Port:        service.Port,
			Kind:        key,
			Summary:     "Passive service metadata",
			Value:       service.Metadata[key],
			CollectedAt: service.CreatedAt,
		})
	}
	return items
}

func FromFinding(target string, finding types.Finding) Item {
	return Item{
		Source:      "finding",
		Target:      target,
		Kind:        strings.ToLower(finding.Severity),
		Summary:     finding.Title,
		Value:       finding.Evidence,
		Attributes:  map[string]string{"confidence": finding.Confidence, "cve_id": finding.CVEID},
		CollectedAt: finding.CreatedAt,
	}
}

func Build(scan types.Scan, services []types.Service, findings []types.Finding) Bundle {
	bundle := Bundle{ScanID: scan.ID, Target: scan.Target, CreatedAt: time.Now()}
	for _, service := range services {
		bundle.Items = append(bundle.Items, FromService(scan.Target, service)...)
	}
	for _, finding := range findings {
		bundle.Items = append(bundle.Items, FromFinding(scan.Target, finding))
	}
	bundle.Fingerprint = Fingerprint(bundle.Items)
	return bundle
}

func Fingerprint(items []Item) string {
	cloned := append([]Item(nil), items...)
	sort.Slice(cloned, func(i, j int) bool {
		left := cloned[i].Source + cloned[i].Kind + cloned[i].Value
		right := cloned[j].Source + cloned[j].Kind + cloned[j].Value
		return left < right
	})
	data, _ := json.Marshal(cloned)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Redact(items []Item, saveRaw bool) []Item {
	out := append([]Item(nil), items...)
	if saveRaw {
		return out
	}
	for i := range out {
		if out[i].Kind == "banner" || strings.Contains(out[i].Kind, "header") {
			out[i].Value = Fingerprint([]Item{out[i]})
		}
	}
	return out
}
