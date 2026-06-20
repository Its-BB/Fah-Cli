package health

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fahscan/internal/config"
	"fahscan/internal/database"
	"fahscan/pkg/types"
)

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Check struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Status      Status        `json:"status"`
	Message     string        `json:"message"`
	Duration    time.Duration `json:"duration_ms"`
	Remediation string        `json:"remediation,omitempty"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Overall     Status    `json:"overall"`
	Checks      []Check   `json:"checks"`
}

type Runner struct {
	Config types.Config
}

func NewRunner(cfg types.Config) Runner {
	return Runner{Config: cfg}
}

func Run() Report {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}
	return NewRunner(cfg).Run()
}

func (r Runner) Run() Report {
	checks := []func() Check{
		r.configPath,
		r.configValues,
		r.databasePath,
		r.databaseOpen,
		r.dataDirectory,
		r.permissions,
		r.releaseFiles,
	}
	report := Report{GeneratedAt: time.Now(), Overall: Pass}
	for _, fn := range checks {
		check := timed(fn)
		report.Checks = append(report.Checks, check)
		report.Overall = worse(report.Overall, check.Status)
	}
	sort.SliceStable(report.Checks, func(i, j int) bool {
		if weight(report.Checks[i].Status) == weight(report.Checks[j].Status) {
			return report.Checks[i].ID < report.Checks[j].ID
		}
		return weight(report.Checks[i].Status) > weight(report.Checks[j].Status)
	})
	return report
}

func (r Runner) configPath() Check {
	path := r.Config.ConfigPath
	if strings.TrimSpace(path) == "" {
		return fail("health.config_path", "Config path", "config path is empty", "Run fahscan init to create a default config.")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return warn("health.config_path", "Config path", "config file does not exist yet", "Run fahscan init before long-term use.")
		}
		return fail("health.config_path", "Config path", err.Error(), "Check file permissions and parent directories.")
	}
	return pass("health.config_path", "Config path", path)
}

func (r Runner) configValues() Check {
	if err := config.Validate(r.Config); err != nil {
		return fail("health.config_values", "Config values", err.Error(), "Adjust the invalid config value with fahscan config set.")
	}
	if r.Config.MaxConcurrency > 100 {
		return warn("health.config_values", "Config values", "high concurrency may be noisy on fragile systems", "Prefer conservative concurrency unless the target owner approved it.")
	}
	return pass("health.config_values", "Config values", "configuration validates")
}

func (r Runner) databasePath() Check {
	path := r.Config.DBPath
	if strings.TrimSpace(path) == "" {
		return fail("health.database_path", "Database path", "database path is empty", "Run fahscan init to create default paths.")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail("health.database_path", "Database path", err.Error(), "Create or grant access to the database directory.")
	}
	return pass("health.database_path", "Database path", path)
}

func (r Runner) databaseOpen() Check {
	db, err := database.Open(r.Config.DBPath)
	if err != nil {
		return fail("health.database_open", "Database open", err.Error(), "Check SQLite file permissions and available disk space.")
	}
	defer db.Close()
	stats, err := db.Stats()
	if err != nil {
		return fail("health.database_open", "Database stats", err.Error(), "Run fahscan db vacuum or restore a known-good backup.")
	}
	return pass("health.database_open", "Database open", fmt.Sprintf("targets=%d scans=%d findings=%d", stats["targets"], stats["scans"], stats["findings"]))
}

func (r Runner) dataDirectory() Check {
	dir := filepath.Join(filepath.Dir(r.Config.ConfigPath))
	info, err := os.Stat(dir)
	if err != nil {
		return fail("health.data_directory", "Data directory", err.Error(), "Run fahscan init.")
	}
	if !info.IsDir() {
		return fail("health.data_directory", "Data directory", "path exists but is not a directory", "Move the file and run fahscan init.")
	}
	return pass("health.data_directory", "Data directory", dir)
}

func (r Runner) permissions() Check {
	dir := filepath.Dir(r.Config.ConfigPath)
	testPath := filepath.Join(dir, ".fahscan_write_test")
	if err := os.WriteFile(testPath, []byte("ok"), 0o600); err != nil {
		return fail("health.permissions", "Write permissions", err.Error(), "Grant write permissions to the FahScan data directory.")
	}
	_ = os.Remove(testPath)
	return pass("health.permissions", "Write permissions", "data directory is writable")
}

func (r Runner) releaseFiles() Check {
	required := []string{"go.mod", "README.md", ".goreleaser.yaml"}
	var missing []string
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return warn("health.release_files", "Release files", "missing "+strings.Join(missing, ", "), "Restore release metadata before publishing.")
	}
	return pass("health.release_files", "Release files", "release metadata present")
}

func timed(fn func() Check) Check {
	start := time.Now()
	check := fn()
	check.Duration = time.Since(start) / time.Millisecond
	return check
}

func pass(id, title, message string) Check {
	return Check{ID: id, Title: title, Status: Pass, Message: message}
}

func warn(id, title, message, remediation string) Check {
	return Check{ID: id, Title: title, Status: Warn, Message: message, Remediation: remediation}
}

func fail(id, title, message, remediation string) Check {
	return Check{ID: id, Title: title, Status: Fail, Message: message, Remediation: remediation}
}

func worse(a, b Status) Status {
	if weight(b) > weight(a) {
		return b
	}
	return a
}

func weight(status Status) int {
	switch status {
	case Fail:
		return 3
	case Warn:
		return 2
	default:
		return 1
	}
}
