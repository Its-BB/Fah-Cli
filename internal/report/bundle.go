package report

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"fahscan/pkg/types"
)

type BundlePlan struct {
	BaseName  string            `json:"base_name"`
	Target    string            `json:"target"`
	ScanID    int64             `json:"scan_id"`
	Entries   []BundleEntry     `json:"entries"`
	Checksums map[string]string `json:"checksums"`
	Manifest  Manifest          `json:"manifest"`
}

type BundleEntry struct {
	Format   string `json:"format"`
	Path     string `json:"path"`
	MimeType string `json:"mime_type"`
	SizeHint int    `json:"size_hint"`
}

func PlanBundle(data types.ReportData, directory string, formats []string) BundlePlan {
	if len(formats) == 0 {
		formats = []string{"json", "html", "markdown", "txt", "sarif"}
	}
	base := safeBase(data.Scan.Target, data.Scan.ID)
	plan := BundlePlan{
		BaseName:  base,
		Target:    data.Scan.Target,
		ScanID:    data.Scan.ID,
		Checksums: map[string]string{},
		Manifest:  BuildManifest(data, formats),
	}
	for _, format := range formats {
		artifact := ArtifactFor(format)
		path := filepath.Join(directory, base+"."+extension(artifact.Format))
		entry := BundleEntry{Format: artifact.Format, Path: path, MimeType: artifact.MimeType, SizeHint: sizeHint(data, artifact.Format)}
		plan.Entries = append(plan.Entries, entry)
		plan.Checksums[path] = checksumSeed(data, artifact.Format, path)
	}
	sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Format < plan.Entries[j].Format })
	return plan
}

func (p BundlePlan) Formats() []string {
	formats := make([]string, 0, len(p.Entries))
	for _, entry := range p.Entries {
		formats = append(formats, entry.Format)
	}
	sort.Strings(formats)
	return formats
}

func (p BundlePlan) TotalSizeHint() int {
	total := 0
	for _, entry := range p.Entries {
		total += entry.SizeHint
	}
	return total
}

func (p BundlePlan) Paths() []string {
	paths := make([]string, 0, len(p.Entries))
	for _, entry := range p.Entries {
		paths = append(paths, entry.Path)
	}
	sort.Strings(paths)
	return paths
}

func (p BundlePlan) HasFormat(format string) bool {
	format = strings.ToLower(strings.TrimSpace(format))
	for _, entry := range p.Entries {
		if entry.Format == format {
			return true
		}
	}
	return false
}

func (p BundlePlan) Entry(format string) (BundleEntry, bool) {
	format = strings.ToLower(strings.TrimSpace(format))
	for _, entry := range p.Entries {
		if entry.Format == format {
			return entry, true
		}
	}
	return BundleEntry{}, false
}

func (p BundlePlan) Empty() bool { return len(p.Entries) == 0 }

func safeBase(target string, scanID int64) string {
	target = strings.ToLower(strings.TrimSpace(target))
	replacer := strings.NewReplacer(".", "-", ":", "-", "/", "-", "\\", "-", " ", "-")
	target = strings.Trim(replacer.Replace(target), "-")
	if target == "" {
		target = "scan"
	}
	return target + "-" + int64Text(scanID)
}

func extension(format string) string {
	switch strings.ToLower(format) {
	case "markdown":
		return "md"
	case "sarif":
		return "sarif.json"
	case "text":
		return "txt"
	default:
		return strings.ToLower(format)
	}
}

func sizeHint(data types.ReportData, format string) int {
	base := 512 + len(data.Services)*160 + len(data.Findings)*320 + len(data.Remediation)*220
	switch strings.ToLower(format) {
	case "json", "sarif":
		return base * 2
	case "html":
		return base + 2048
	default:
		return base
	}
}

func checksumSeed(data types.ReportData, format, path string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{data.Scan.Target, format, path, data.EvidenceFingerprint}, "|")))
	return hex.EncodeToString(sum[:])
}

func int64Text(n int64) string {
	if n == 0 {
		return "0"
	}
	digits := "0123456789"
	var out []byte
	for n > 0 {
		out = append([]byte{digits[n%10]}, out...)
		n /= 10
	}
	return string(out)
}
