package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"fahscan/internal/advisor"
	"fahscan/internal/app"
	"fahscan/internal/audit"
	"fahscan/internal/compare"
	"fahscan/internal/config"
	"fahscan/internal/cve"
	"fahscan/internal/database"
	"fahscan/internal/exporter"
	"fahscan/internal/health"
	"fahscan/internal/history"
	"fahscan/internal/inventory"
	"fahscan/internal/knowledge"
	"fahscan/internal/metrics"
	"fahscan/internal/output"
	"fahscan/internal/profile"
	"fahscan/internal/report"
	"fahscan/internal/scanner"
	"fahscan/internal/schedule"
	"fahscan/internal/validate"
	"fahscan/pkg/types"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error {
	return rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "fahscan",
		Short:         "CLI-only defensive vulnerability scanner",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd(), healthCmd(), targetCmd(), scanCmd(), reportCmd(), adviceCmd(), inventoryCmd(), historyCmd(), metricsCmd(), scheduleCmd(), compareCmd(), cveCmd(), portsCmd(), profileCmd(), knowledgeCmd(), dbCmd(), auditCmd())
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version", Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(cmd.OutOrStdout(), "fahscan "+version)
	}}
}

func initCmd() *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Initialize local config and database", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.Init()
		if err != nil {
			return err
		}
		defer a.Close()
		audit.Log(a.DB, "init", map[string]string{"config": a.Config.ConfigPath, "database": a.Config.DBPath})
		fmt.Fprintf(cmd.OutOrStdout(), "initialized\nconfig: %s\ndatabase: %s\n", a.Config.ConfigPath, a.Config.DBPath)
		return nil
	}}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Manage configuration"}
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		keys := config.KnownKeys()
		sort.Strings(keys)
		for _, k := range keys {
			output.KV(cmd.OutOrStdout(), k, config.Map(cfg)[k])
		}
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "get <key>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		val, ok := config.Map(cfg)[args[0]]
		if !ok {
			return fmt.Errorf("unknown config key %q", args[0])
		}
		fmt.Fprintln(cmd.OutOrStdout(), val)
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "set <key> <value>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if err := config.Set(&cfg, args[0], args[1]); err != nil {
			return err
		}
		if err := config.Validate(cfg); err != nil {
			return err
		}
		if err := config.Save(cfg); err != nil {
			return err
		}
		a, err := app.New()
		if err == nil {
			defer a.Close()
			audit.Log(a.DB, "config.set", map[string]string{"key": args[0]})
		}
		fmt.Fprintln(cmd.OutOrStdout(), "updated")
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "reset", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Reset()
		if err != nil {
			return err
		}
		db, err := database.Open(cfg.DBPath)
		if err == nil {
			defer db.Close()
			audit.Log(db, "config.reset", nil)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "reset")
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "schema", Run: func(cmd *cobra.Command, args []string) {
		var rows [][]string
		for _, field := range config.Schema() {
			rows = append(rows, []string{field.Key, field.Type, fmt.Sprint(field.Default), field.Description})
		}
		output.Table(cmd.OutOrStdout(), []string{"Key", "Type", "Default", "Description"}, rows)
	}})
	return cmd
}

func healthCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "health", Short: "Run local FahScan readiness checks", RunE: func(cmd *cobra.Command, args []string) error {
		report := health.Run()
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), report)
		}
		output.KV(cmd.OutOrStdout(), "overall", report.Overall)
		var rows [][]string
		for _, check := range report.Checks {
			rows = append(rows, []string{check.ID, string(check.Status), check.Message, check.Remediation})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Status", "Message", "Remediation"}, rows)
		if report.Overall == health.Fail {
			return fmt.Errorf("one or more health checks failed")
		}
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	return cmd
}

func targetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Manage authorized targets"}
	cmd.AddCommand(&cobra.Command{Use: "add <target>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		info, err := validate.ParseTarget(args[0], a.Config)
		if err != nil {
			return err
		}
		id, err := a.DB.AddTarget(info.Value, info.Type)
		if err != nil {
			return err
		}
		audit.Log(a.DB, "target.add", map[string]any{"target": info.Value, "id": id})
		fmt.Fprintf(cmd.OutOrStdout(), "added target %d\n", id)
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		targets, err := a.DB.ListTargets()
		if err != nil {
			return err
		}
		var rows [][]string
		for _, t := range targets {
			rows = append(rows, []string{fmt.Sprint(t.ID), t.Value, t.Type, strings.Join(t.Tags, ",")})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Target", "Type", "Tags"}, rows)
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "show <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		t, err := a.DB.Target(id)
		if err != nil {
			return err
		}
		output.KV(cmd.OutOrStdout(), "id", t.ID)
		output.KV(cmd.OutOrStdout(), "value", t.Value)
		output.KV(cmd.OutOrStdout(), "type", t.Type)
		output.KV(cmd.OutOrStdout(), "tags", strings.Join(t.Tags, ","))
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "remove <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.RemoveTarget(id); err != nil {
			return err
		}
		audit.Log(a.DB, "target.remove", map[string]int64{"id": id})
		fmt.Fprintln(cmd.OutOrStdout(), "removed")
		return nil
	}})
	cmd.AddCommand(tagCommand("tag", true), tagCommand("untag", false))
	return cmd
}

func tagCommand(name string, add bool) *cobra.Command {
	return &cobra.Command{Use: name + " <id> <tag>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		t, err := a.DB.Target(id)
		if err != nil {
			return err
		}
		if add {
			t.Tags = append(t.Tags, args[1])
		} else {
			var kept []string
			for _, tag := range t.Tags {
				if tag != args[1] {
					kept = append(kept, tag)
				}
			}
			t.Tags = kept
		}
		if err := a.DB.SetTargetTags(id, t.Tags); err != nil {
			return err
		}
		audit.Log(a.DB, "target."+name, map[string]any{"id": id, "tag": args[1]})
		fmt.Fprintln(cmd.OutOrStdout(), "updated")
		return nil
	}}
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan", Short: "Run and inspect scans"}
	run := &cobra.Command{Use: "run <target>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		profile, _ := cmd.Flags().GetString("profile")
		ports, _ := cmd.Flags().GetString("ports")
		authorized, _ := cmd.Flags().GetBool("i-am-authorized")
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		scan, services, findings, err := a.RunScan(context.Background(), args[0], profile, ports, authorized)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "scan %d completed\nrisk score: %d\nopen ports: %d\nfindings: %d\n", scan.ID, scan.RiskScore, len(services), len(findings))
		return nil
	}}
	run.Flags().String("profile", "", "scan profile")
	run.Flags().String("ports", "", "comma-separated custom TCP ports")
	run.Flags().Bool("i-am-authorized", false, "confirm authorization to scan the target")
	cmd.AddCommand(run)
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		scans, err := a.DB.ListScans()
		if err != nil {
			return err
		}
		var rows [][]string
		for _, s := range scans {
			rows = append(rows, []string{fmt.Sprint(s.ID), s.Target, s.Profile, s.Status, fmt.Sprint(s.RiskScore), s.FinishedAt.Format("2006-01-02 15:04:05")})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Target", "Profile", "Status", "Risk", "Finished"}, rows)
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "show <id>", Args: cobra.ExactArgs(1), RunE: showScan})
	cmd.AddCommand(&cobra.Command{Use: "delete <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.DeleteScan(id); err != nil {
			return err
		}
		audit.Log(a.DB, "scan.delete", map[string]int64{"id": id})
		fmt.Fprintln(cmd.OutOrStdout(), "deleted")
		return nil
	}})
	return cmd
}

func showScan(cmd *cobra.Command, args []string) error {
	a, id, err := appWithID(args[0])
	if err != nil {
		return err
	}
	defer a.Close()
	scan, services, findings, err := a.DB.Scan(id)
	if err != nil {
		return err
	}
	output.KV(cmd.OutOrStdout(), "id", scan.ID)
	output.KV(cmd.OutOrStdout(), "target", scan.Target)
	output.KV(cmd.OutOrStdout(), "profile", scan.Profile)
	output.KV(cmd.OutOrStdout(), "risk_score", scan.RiskScore)
	var serviceRows [][]string
	for _, s := range services {
		serviceRows = append(serviceRows, []string{fmt.Sprint(s.Port), s.Protocol, s.Service, s.Product})
	}
	fmt.Fprintln(cmd.OutOrStdout(), "\nservices")
	output.Table(cmd.OutOrStdout(), []string{"Port", "Protocol", "Service", "Product"}, serviceRows)
	var findingRows [][]string
	for _, f := range findings {
		findingRows = append(findingRows, []string{f.Severity, f.Title, f.Confidence})
	}
	fmt.Fprintln(cmd.OutOrStdout(), "\nfindings")
	output.Table(cmd.OutOrStdout(), []string{"Severity", "Title", "Confidence"}, findingRows)
	return nil
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "report", Short: "View and export reports"}
	cmd.AddCommand(&cobra.Command{Use: "view <scan-id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		scan, services, findings, err := a.DB.Scan(id)
		if err != nil {
			return err
		}
		body, err := report.Render(report.Data(scan, services, findings), "txt")
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), string(body))
		return nil
	}})
	export := &cobra.Command{Use: "export <scan-id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		out, _ := cmd.Flags().GetString("out")
		if out == "" {
			return fmt.Errorf("--out is required")
		}
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		scan, services, findings, err := a.DB.Scan(id)
		if err != nil {
			return err
		}
		if err := report.Write(out, format, report.Data(scan, services, findings)); err != nil {
			return err
		}
		_ = a.DB.AddReport(id, format, out)
		audit.Log(a.DB, "report.export", map[string]any{"scan_id": id, "format": format, "path": out})
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	}}
	export.Flags().String("format", "json", "json, sarif, html, markdown, or txt")
	export.Flags().String("out", "", "output path")
	cmd.AddCommand(export)
	return cmd
}

func adviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "advice <scan-id>", Short: "Generate prioritized remediation advice for a scan", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, id, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		scan, services, findings, err := a.DB.Scan(id)
		if err != nil {
			return err
		}
		strict, _ := cmd.Flags().GetBool("strict")
		accepted, _ := cmd.Flags().GetStringSlice("accept")
		book := advisor.Build(advisor.Context{Scan: scan, Services: services, Findings: findings, Config: a.Config, Accepted: accepted, Strict: strict})
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), book)
		}
		output.KV(cmd.OutOrStdout(), "target", book.Target)
		output.KV(cmd.OutOrStdout(), "risk_score", book.RiskScore)
		output.KV(cmd.OutOrStdout(), "highest", book.Highest)
		output.KV(cmd.OutOrStdout(), "next_best_step", book.NextBestStep)
		var rows [][]string
		for _, item := range book.Advice {
			rows = append(rows, []string{item.ID, fmt.Sprint(item.Priority), item.Category, item.Title})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Priority", "Category", "Title"}, rows)
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	cmd.Flags().Bool("strict", false, "include strict-environment advice")
	cmd.Flags().StringSlice("accept", nil, "accepted advice IDs to suppress")
	return cmd
}

func inventoryCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "inventory", Short: "Summarize retained scan inventory"}
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		snapshot, err := inventorySnapshot(a.DB)
		if err != nil {
			return err
		}
		var rows [][]string
		for _, asset := range snapshot.Assets {
			rows = append(rows, []string{asset.Target, fmt.Sprint(asset.ScanCount), joinInts(asset.OpenPorts), strings.Join(asset.Services, ","), asset.HighestSeverity, asset.Exposure})
		}
		output.Table(cmd.OutOrStdout(), []string{"Target", "Scans", "Ports", "Services", "Highest", "Exposure"}, rows)
		return nil
	}})
	export := &cobra.Command{Use: "export", RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("out")
		format, _ := cmd.Flags().GetString("format")
		if out == "" {
			return fmt.Errorf("--out is required")
		}
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		snapshot, err := inventorySnapshot(a.DB)
		if err != nil {
			return err
		}
		var body []byte
		switch strings.ToLower(format) {
		case "json":
			body, err = json.MarshalIndent(snapshot, "", "  ")
		case "csv":
			body, err = exporter.InventoryCSV(snapshot)
		default:
			err = fmt.Errorf("unsupported inventory format %q", format)
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, body, 0o600); err != nil {
			return err
		}
		audit.Log(a.DB, "inventory.export", map[string]string{"format": format, "path": out})
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	}}
	export.Flags().String("format", "json", "json or csv")
	export.Flags().String("out", "", "output path")
	cmd.AddCommand(export)
	return cmd
}

func historyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "history", Short: "Analyze retained scan history", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		timeline, err := historyTimeline(a.DB)
		if err != nil {
			return err
		}
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), timeline)
		}
		output.KV(cmd.OutOrStdout(), "targets", timeline.Overall.TargetCount)
		output.KV(cmd.OutOrStdout(), "scans", timeline.Overall.ScanCount)
		output.KV(cmd.OutOrStdout(), "average_risk", fmt.Sprintf("%.1f", timeline.Overall.AverageRisk))
		var rows [][]string
		for _, target := range timeline.Targets {
			rows = append(rows, []string{
				target.Target,
				fmt.Sprint(target.ScanCount),
				fmt.Sprint(target.LatestRiskScore),
				target.RiskTrend,
				target.OpenPortTrend.Trend,
				target.FindingTrend.Trend,
			})
		}
		output.Table(cmd.OutOrStdout(), []string{"Target", "Scans", "Latest Risk", "Risk", "Ports", "Findings"}, rows)
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	return cmd
}

func metricsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "metrics", Short: "Show aggregate scan metrics", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		scans, err := a.DB.ListScans()
		if err != nil {
			return err
		}
		servicesByScan := map[int64][]types.Service{}
		findingsByScan := map[int64][]types.Finding{}
		for _, scan := range scans {
			servicesByScan[scan.ID], _ = a.DB.Services(scan.ID)
			findingsByScan[scan.ID], _ = a.DB.Findings(scan.ID)
		}
		m := metrics.Build(scans, servicesByScan, findingsByScan)
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), m)
		}
		output.KV(cmd.OutOrStdout(), "scans", m.Scans)
		output.KV(cmd.OutOrStdout(), "targets", m.Targets)
		output.KV(cmd.OutOrStdout(), "services", m.Services)
		output.KV(cmd.OutOrStdout(), "findings", m.Findings)
		output.KV(cmd.OutOrStdout(), "average_risk", fmt.Sprintf("%.1f", m.AverageRisk))
		output.KV(cmd.OutOrStdout(), "riskiest_target", m.RiskiestTarget)
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	return cmd
}

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Inspect and compose scan profiles"}
	cmd.AddCommand(&cobra.Command{Use: "list", Run: func(cmd *cobra.Command, args []string) {
		var rows [][]string
		for _, def := range profile.List() {
			rows = append(rows, []string{def.Name, fmt.Sprint(len(def.Ports)), strings.Join(def.Families, ","), def.Description})
		}
		output.Table(cmd.OutOrStdout(), []string{"Name", "Ports", "Families", "Description"}, rows)
	}})
	compose := &cobra.Command{Use: "compose", RunE: func(cmd *cobra.Command, args []string) error {
		names, _ := cmd.Flags().GetStringSlice("include")
		families, _ := cmd.Flags().GetStringSlice("family")
		includePorts, _ := cmd.Flags().GetIntSlice("port")
		excludePorts, _ := cmd.Flags().GetIntSlice("exclude-port")
		maxPorts, _ := cmd.Flags().GetInt("max")
		result, err := profile.Compose(profile.ComposeRequest{IncludeProfiles: names, IncludeFamilies: families, IncludePorts: includePorts, ExcludePorts: excludePorts, MaxPorts: maxPorts})
		if err != nil {
			return err
		}
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), result)
		}
		output.KV(cmd.OutOrStdout(), "name", result.Name)
		output.KV(cmd.OutOrStdout(), "ports", joinInts(result.Ports))
		output.KV(cmd.OutOrStdout(), "sources", strings.Join(result.Sources, ","))
		for _, warning := range result.Warnings {
			fmt.Fprintln(cmd.OutOrStdout(), "warning:", warning)
		}
		return nil
	}}
	compose.Flags().StringSlice("include", []string{"quick"}, "profiles to include")
	compose.Flags().StringSlice("family", nil, "families to include")
	compose.Flags().IntSlice("port", nil, "additional ports")
	compose.Flags().IntSlice("exclude-port", nil, "ports to exclude")
	compose.Flags().Int("max", 100, "maximum ports")
	compose.Flags().String("format", "table", "table or json")
	cmd.AddCommand(compose)
	return cmd
}

func scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "schedule", Short: "Preview conservative local scan schedules"}
	preview := &cobra.Command{Use: "preview", RunE: func(cmd *cobra.Command, args []string) error {
		profiles, _ := cmd.Flags().GetStringSlice("profile")
		frequency, _ := cmd.Flags().GetString("frequency")
		horizonRaw, _ := cmd.Flags().GetDuration("horizon")
		format, _ := cmd.Flags().GetString("format")
		plan := schedule.ConservativePlan()
		if len(profiles) > 0 {
			plan.Profiles = profiles
		}
		if frequency != "" {
			plan.Frequency = schedule.Frequency(frequency)
		}
		eval := schedule.Evaluate(plan, time.Now(), horizonRaw)
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), eval)
		}
		output.KV(cmd.OutOrStdout(), "allowed_now", eval.AllowedNow)
		output.KV(cmd.OutOrStdout(), "active_window", eval.ActiveWindow)
		if eval.Next != nil {
			output.KV(cmd.OutOrStdout(), "next", eval.Next.At.Format(time.RFC3339))
		}
		var rows [][]string
		for _, occ := range eval.Candidates {
			rows = append(rows, []string{occ.At.Format(time.RFC3339), occ.Window, occ.Profile, occ.Reason})
		}
		output.Table(cmd.OutOrStdout(), []string{"At", "Window", "Profile", "Reason"}, rows)
		return nil
	}}
	preview.Flags().StringSlice("profile", []string{"quick"}, "profiles to include")
	preview.Flags().String("frequency", string(schedule.Weekly), "once, hourly, daily, weekly, or monthly")
	preview.Flags().Duration("horizon", 30*24*time.Hour, "preview horizon")
	preview.Flags().String("format", "table", "table or json")
	cmd.AddCommand(preview)
	return cmd
}

func compareCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "compare <base-scan-id> <new-scan-id>", Short: "Compare two saved scans", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		a, baseID, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		newID, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid id %q", args[1])
		}
		base, baseServices, baseFindings, err := a.DB.Scan(baseID)
		if err != nil {
			return err
		}
		next, nextServices, nextFindings, err := a.DB.Scan(newID)
		if err != nil {
			return err
		}
		delta := compare.Scans(base, baseServices, baseFindings, next, nextServices, nextFindings)
		format, _ := cmd.Flags().GetString("format")
		if strings.EqualFold(format, "json") {
			return output.JSON(cmd.OutOrStdout(), delta)
		}
		output.KV(cmd.OutOrStdout(), "base_scan", delta.BaseScanID)
		output.KV(cmd.OutOrStdout(), "new_scan", delta.NewScanID)
		output.KV(cmd.OutOrStdout(), "risk_trend", delta.Risk.Trend)
		for _, item := range delta.Summary {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", item.Kind, item.Message)
		}
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	return cmd
}

func inventorySnapshot(db *database.DB) (inventory.Snapshot, error) {
	scans, err := db.ListScans()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	servicesByScan := map[int64][]types.Service{}
	findingsByScan := map[int64][]types.Finding{}
	for _, scan := range scans {
		services, err := db.Services(scan.ID)
		if err != nil {
			return inventory.Snapshot{}, err
		}
		findings, err := db.Findings(scan.ID)
		if err != nil {
			return inventory.Snapshot{}, err
		}
		servicesByScan[scan.ID] = services
		findingsByScan[scan.ID] = findings
	}
	return inventory.Build(scans, servicesByScan, findingsByScan), nil
}

func historyTimeline(db *database.DB) (history.Timeline, error) {
	scans, err := db.ListScans()
	if err != nil {
		return history.Timeline{}, err
	}
	servicesByScan := map[int64][]types.Service{}
	findingsByScan := map[int64][]types.Finding{}
	for _, scan := range scans {
		services, err := db.Services(scan.ID)
		if err != nil {
			return history.Timeline{}, err
		}
		findings, err := db.Findings(scan.ID)
		if err != nil {
			return history.Timeline{}, err
		}
		servicesByScan[scan.ID] = services
		findingsByScan[scan.ID] = findings
	}
	return history.Build(scans, servicesByScan, findingsByScan), nil
}

func cveCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cve", Short: "Manage local CVE records"}
	cmd.AddCommand(&cobra.Command{Use: "import <file>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		records, err := cve.LoadFile(args[0])
		if err != nil {
			return err
		}
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.ImportCVEs(records); err != nil {
			return err
		}
		audit.Log(a.DB, "cve.import", map[string]any{"file": args[0], "count": len(records)})
		fmt.Fprintf(cmd.OutOrStdout(), "imported %d CVE records\n", len(records))
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error { return cveSearch(cmd, "") }})
	cmd.AddCommand(&cobra.Command{Use: "search <query>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return cveSearch(cmd, args[0]) }})
	cmd.AddCommand(&cobra.Command{Use: "stats", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		records, err := a.DB.CVEs("")
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "cves: %d\n", len(records))
		return nil
	}})
	return cmd
}

func cveSearch(cmd *cobra.Command, query string) error {
	a, err := app.New()
	if err != nil {
		return err
	}
	defer a.Close()
	records, err := a.DB.CVEs(query)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, rec := range records {
		rows = append(rows, []string{rec.CVEID, rec.Product, rec.AffectedVersion, fmt.Sprint(rec.CVSS), rec.Severity})
	}
	output.Table(cmd.OutOrStdout(), []string{"CVE", "Product", "Version", "CVSS", "Severity"}, rows)
	return nil
}

func portsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ports", Short: "Inspect port profiles"}
	cmd.AddCommand(&cobra.Command{Use: "list", Run: func(cmd *cobra.Command, args []string) {
		names := make([]string, 0, len(scanner.Profiles))
		for name := range scanner.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintln(cmd.OutOrStdout(), name)
		}
	}})
	cmd.AddCommand(&cobra.Command{Use: "profile <name>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ports, err := scanner.ProfilePorts(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), joinInts(ports))
		return nil
	}})
	return cmd
}

func knowledgeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "knowledge", Short: "Inspect local passive-rule knowledge base"}
	rules := &cobra.Command{Use: "rules", Short: "Search passive defensive rules", Run: func(cmd *cobra.Command, args []string) {
		text, _ := cmd.Flags().GetString("query")
		category, _ := cmd.Flags().GetString("category")
		severity, _ := cmd.Flags().GetString("severity")
		tag, _ := cmd.Flags().GetString("tag")
		matches := knowledge.SearchRules(knowledge.Query{Text: text, Category: category, Severity: severity, Tag: tag})
		limit, _ := cmd.Flags().GetInt("limit")
		if limit <= 0 || limit > len(matches) {
			limit = len(matches)
		}
		var rows [][]string
		for _, rule := range matches[:limit] {
			rows = append(rows, []string{rule.ID, rule.Category, rule.Severity, rule.Title, strings.Join(rule.Tags, ",")})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Category", "Severity", "Title", "Tags"}, rows)
	}}
	rules.Flags().String("query", "", "search text")
	rules.Flags().String("category", "", "category filter")
	rules.Flags().String("severity", "", "severity filter")
	rules.Flags().String("tag", "", "tag filter")
	rules.Flags().Int("limit", 25, "maximum rows")
	ports := &cobra.Command{Use: "ports", Short: "Search TCP service reference entries", Run: func(cmd *cobra.Command, args []string) {
		text, _ := cmd.Flags().GetString("query")
		category, _ := cmd.Flags().GetString("category")
		tag, _ := cmd.Flags().GetString("tag")
		matches := knowledge.SearchPorts(knowledge.Query{Text: text, Category: category, Tag: tag})
		limit, _ := cmd.Flags().GetInt("limit")
		if limit <= 0 || limit > len(matches) {
			limit = len(matches)
		}
		var rows [][]string
		for _, port := range matches[:limit] {
			rows = append(rows, []string{fmt.Sprint(port.Port), port.Protocol, port.Service, port.Category, strings.Join(port.Tags, ",")})
		}
		output.Table(cmd.OutOrStdout(), []string{"Port", "Protocol", "Service", "Category", "Tags"}, rows)
	}}
	ports.Flags().String("query", "", "search text")
	ports.Flags().String("category", "", "category filter")
	ports.Flags().String("tag", "", "tag filter")
	ports.Flags().Int("limit", 25, "maximum rows")
	stats := &cobra.Command{Use: "stats", Short: "Show local knowledge base stats", Run: func(cmd *cobra.Command, args []string) {
		output.KV(cmd.OutOrStdout(), "rules", knowledge.RuleStats()["total"])
		output.KV(cmd.OutOrStdout(), "ports", knowledge.PortStats()["total"])
	}}
	cmd.AddCommand(rules, ports, stats)
	return cmd
}

func dbCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Manage local database"}
	cmd.AddCommand(&cobra.Command{Use: "stats", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		stats, err := a.DB.Stats()
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(stats))
		for key := range stats {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			output.KV(cmd.OutOrStdout(), key, stats[key])
		}
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "vacuum", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.Vacuum(); err != nil {
			return err
		}
		audit.Log(a.DB, "db.vacuum", nil)
		fmt.Fprintln(cmd.OutOrStdout(), "vacuumed")
		return nil
	}})
	backup := &cobra.Command{Use: "backup", RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("out")
		if out == "" {
			return fmt.Errorf("--out is required")
		}
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.Backup(out); err != nil {
			return err
		}
		audit.Log(a.DB, "db.backup", map[string]string{"out": out})
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	}}
	backup.Flags().String("out", "", "backup path")
	cmd.AddCommand(backup)
	cmd.AddCommand(&cobra.Command{Use: "restore <backup.db>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		audit.Log(a.DB, "db.restore", map[string]string{"from": args[0]})
		if err := a.DB.Restore(args[0]); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "restored")
		return nil
	}})
	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect audit log"}
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		logs, err := a.DB.AuditLogs()
		if err != nil {
			return err
		}
		var rows [][]string
		for _, log := range logs {
			rows = append(rows, []string{fmt.Sprint(log.ID), log.Action, log.Metadata, log.CreatedAt.Format("2006-01-02 15:04:05")})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Action", "Metadata", "Created"}, rows)
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "clear", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		if err := a.DB.ClearAudit(); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "cleared")
		return nil
	}})
	return cmd
}

func appWithID(raw string) (*app.App, int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid id %q", raw)
	}
	a, err := app.New()
	return a, id, err
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func init() {
	cobra.EnableCommandSorting = false
	_ = os.Stdout
}
