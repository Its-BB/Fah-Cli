package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"fahscan/internal/app"
	"fahscan/internal/config"
	"fahscan/internal/output"
	"fahscan/internal/report"
	"fahscan/internal/scanner"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error { return rootCmd().Execute() }

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "fahscan", Short: "Defensive scanner with reporting", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd(), portsCmd(), scanCmd(), reportCmd())
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

func portsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ports"}
	cmd.AddCommand(&cobra.Command{Use: "profile <name>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ports, err := scanner.ProfilePorts(args[0])
		if err != nil {
			return err
		}
		parts := make([]string, len(ports))
		for i, port := range ports {
			parts[i] = fmt.Sprint(port)
		}
		fmt.Fprintln(cmd.OutOrStdout(), strings.Join(parts, ","))
		return nil
	}})
	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan"}
	run := &cobra.Command{Use: "run <target>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		profile, _ := cmd.Flags().GetString("profile")
		ports, _ := cmd.Flags().GetString("ports")
		auth, _ := cmd.Flags().GetBool("i-am-authorized")
		a, err := app.New()
		if err != nil {
			return err
		}
		defer a.Close()
		scan, services, findings, err := a.RunScan(context.Background(), args[0], profile, ports, auth)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "scan %d completed\nrisk score: %d\nopen ports: %d\nfindings: %d\n", scan.ID, scan.RiskScore, len(services), len(findings))
		return nil
	}}
	run.Flags().String("profile", "quick", "scan profile")
	run.Flags().String("ports", "", "comma-separated custom TCP ports")
	run.Flags().Bool("i-am-authorized", false, "confirm authorization")
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
			rows = append(rows, []string{strconv.FormatInt(s.ID, 10), s.Target, s.Profile, strconv.Itoa(s.RiskScore)})
		}
		output.Table(cmd.OutOrStdout(), []string{"ID", "Target", "Profile", "Risk"}, rows)
		return nil
	}})
	return cmd
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "report"}
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
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	}}
	export.Flags().String("format", "json", "json, sarif, html, markdown, or txt")
	export.Flags().String("out", "", "output path")
	cmd.AddCommand(export)
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

func init() { _ = os.Stdout }
