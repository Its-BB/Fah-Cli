package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"fahscan/internal/advisor"
	"fahscan/internal/app"
	"fahscan/internal/config"
	"fahscan/internal/health"
	"fahscan/internal/metrics"
	"fahscan/internal/output"
	"fahscan/internal/profile"
	"fahscan/internal/schedule"
	"fahscan/pkg/types"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error { return rootCmd().Execute() }

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "fahscan", Short: "Defensive scanner operations and advice", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd(), healthCmd(), profileCmd(), scheduleCmd(), metricsCmd(), adviceCmd())
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Run: func(cmd *cobra.Command, args []string) { fmt.Fprintln(cmd.OutOrStdout(), "fahscan "+version) }}
}

func initCmd() *cobra.Command {
	return &cobra.Command{Use: "init", RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.Init()
		if err != nil {
			return err
		}
		defer a.Close()
		fmt.Fprintf(cmd.OutOrStdout(), "initialized\nconfig: %s\ndatabase: %s\n", a.Config.ConfigPath, a.Config.DBPath)
		return nil
	}}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config"}
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		keys := config.KnownKeys()
		sort.Strings(keys)
		for _, key := range keys {
			output.KV(cmd.OutOrStdout(), key, config.Map(cfg)[key])
		}
		return nil
	}})
	return cmd
}

func healthCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "health", RunE: func(cmd *cobra.Command, args []string) error {
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

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "profile"}
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
		return output.JSON(cmd.OutOrStdout(), result)
	}}
	compose.Flags().StringSlice("include", []string{"quick"}, "profiles to include")
	compose.Flags().StringSlice("family", nil, "families to include")
	compose.Flags().IntSlice("port", nil, "additional ports")
	compose.Flags().IntSlice("exclude-port", nil, "ports to exclude")
	compose.Flags().Int("max", 100, "maximum ports")
	cmd.AddCommand(compose)
	return cmd
}

func scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "schedule"}
	preview := &cobra.Command{Use: "preview", RunE: func(cmd *cobra.Command, args []string) error {
		plan := schedule.ConservativePlan()
		eval := schedule.Evaluate(plan, time.Now(), 30*24*time.Hour)
		return output.JSON(cmd.OutOrStdout(), eval)
	}}
	cmd.AddCommand(preview)
	return cmd
}

func metricsCmd() *cobra.Command {
	return &cobra.Command{Use: "metrics", RunE: func(cmd *cobra.Command, args []string) error {
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
		return output.JSON(cmd.OutOrStdout(), metrics.Build(scans, servicesByScan, findingsByScan))
	}}
}

func adviceCmd() *cobra.Command {
	return &cobra.Command{Use: "advice <scan-id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		id, err := parseID(args[0])
		if err != nil {
			return err
		}
		scan, services, findings, err := a.DB.Scan(id)
		if err != nil {
			return err
		}
		return output.JSON(cmd.OutOrStdout(), advisor.Build(advisor.Context{Scan: scan, Services: services, Findings: findings, Config: a.Config}))
	}}
}

func parseID(raw string) (int64, error) {
	var id int64
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid id %q", raw)
		}
		id = id*10 + int64(r-'0')
	}
	return id, nil
}
