package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"fahscan/internal/app"
	"fahscan/internal/compare"
	"fahscan/internal/config"
	"fahscan/internal/database"
	"fahscan/internal/exporter"
	"fahscan/internal/history"
	"fahscan/internal/inventory"
	"fahscan/internal/output"
	"fahscan/pkg/types"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error { return rootCmd().Execute() }

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "fahscan", Short: "Defensive scanner inventory and history", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd(), inventoryCmd(), historyCmd(), compareCmd())
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

func inventoryCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "inventory"}
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
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	}}
	export.Flags().String("format", "json", "json or csv")
	export.Flags().String("out", "", "output path")
	cmd.AddCommand(export)
	return cmd
}

func historyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "history", RunE: func(cmd *cobra.Command, args []string) error {
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
		return nil
	}}
	cmd.Flags().String("format", "table", "table or json")
	return cmd
}

func compareCmd() *cobra.Command {
	return &cobra.Command{Use: "compare <base-scan-id> <new-scan-id>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		a, baseID, err := appWithID(args[0])
		if err != nil {
			return err
		}
		defer a.Close()
		newID, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return err
		}
		base, baseServices, baseFindings, err := a.DB.Scan(baseID)
		if err != nil {
			return err
		}
		next, nextServices, nextFindings, err := a.DB.Scan(newID)
		if err != nil {
			return err
		}
		return output.JSON(cmd.OutOrStdout(), compare.Scans(base, baseServices, baseFindings, next, nextServices, nextFindings))
	}}
}

func inventorySnapshot(db *database.DB) (inventory.Snapshot, error) {
	scans, err := db.ListScans()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	servicesByScan := map[int64][]types.Service{}
	findingsByScan := map[int64][]types.Finding{}
	for _, scan := range scans {
		servicesByScan[scan.ID], _ = db.Services(scan.ID)
		findingsByScan[scan.ID], _ = db.Findings(scan.ID)
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
		servicesByScan[scan.ID], _ = db.Services(scan.ID)
		findingsByScan[scan.ID], _ = db.Findings(scan.ID)
	}
	return history.Build(scans, servicesByScan, findingsByScan), nil
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
