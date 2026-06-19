package app

import (
	"context"
	"embed"
	"encoding/json"
	"time"

	"fahscan/internal/config"
	"fahscan/internal/cve"
	"fahscan/internal/database"
	"fahscan/internal/risk"
	"fahscan/internal/scanner"
	"fahscan/internal/validate"
	"fahscan/pkg/types"
)

//go:embed cves.seed.json
var seedFS embed.FS

type App struct {
	Config types.Config
	DB     *database.DB
}

func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a := &App{Config: cfg, DB: db}
	_ = a.ImportSeedCVEs()
	return a, nil
}

func Init() (*App, error) {
	cfg, err := config.Init()
	if err != nil {
		return nil, err
	}
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a := &App{Config: cfg, DB: db}
	_ = a.ImportSeedCVEs()
	return a, nil
}

func (a *App) Close() error {
	if a.DB != nil {
		return a.DB.Close()
	}
	return nil
}

func (a *App) ImportSeedCVEs() error {
	data, err := seedFS.ReadFile("cves.seed.json")
	if err != nil {
		return err
	}
	var records []types.CVERecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	return a.DB.ImportCVEs(records)
}

func (a *App) RunScan(ctx context.Context, target string, profile string, customPorts string, authorized bool) (types.Scan, []types.Service, []types.Finding, error) {
	info, err := validate.Target(target, a.Config, authorized)
	if err != nil {
		return types.Scan{}, nil, nil, err
	}
	var ports []int
	if customPorts != "" {
		ports, err = scanner.ParseCustomPorts(customPorts, a.Config.MaxCustomPorts)
	} else {
		if profile == "" {
			profile = a.Config.DefaultProfile
		}
		ports, err = scanner.ProfilePorts(profile)
	}
	if err != nil {
		return types.Scan{}, nil, nil, err
	}
	if _, err := scanner.NewPlan(info.Value, profileName(profile, customPorts), ports, a.Config.MaxConcurrency, time.Duration(a.Config.ConnectTimeoutMS)*time.Millisecond); err != nil {
		return types.Scan{}, nil, nil, err
	}
	start := time.Now()
	result := scanner.Run(ctx, info.Value, ports, scanner.Options{
		MaxConcurrency:  a.Config.MaxConcurrency,
		ConnectTimeout:  time.Duration(a.Config.ConnectTimeoutMS) * time.Millisecond,
		BannerTimeout:   time.Duration(a.Config.BannerTimeoutMS) * time.Millisecond,
		HTTPTimeout:     time.Duration(a.Config.HTTPTimeoutMS) * time.Millisecond,
		TLSTimeout:      time.Duration(a.Config.TLSTimeoutMS) * time.Millisecond,
		SaveRawEvidence: a.Config.SaveRawEvidence,
	})
	records, _ := a.DB.CVEs("")
	for _, svc := range result.Services {
		result.Findings = append(result.Findings, cve.Match(svc, records)...)
	}
	score := risk.Score(result.Services, result.Findings)
	finished := time.Now()
	scan := types.Scan{Target: info.Value, Profile: profileName(profile, customPorts), Ports: ports, Status: "completed", RiskScore: score, StartedAt: start, FinishedAt: finished, DurationMS: finished.Sub(start).Milliseconds()}
	id, err := a.DB.SaveScan(scan, result.Services, result.Findings)
	if err != nil {
		return scan, result.Services, result.Findings, err
	}
	scan.ID = id
	_ = a.DB.AddAudit("scan.run", map[string]any{"target": scan.Target, "profile": scan.Profile, "scan_id": scan.ID})
	return scan, result.Services, result.Findings, nil
}

func profileName(profile, customPorts string) string {
	if customPorts != "" {
		return "custom"
	}
	if profile == "" {
		return "quick"
	}
	return profile
}
