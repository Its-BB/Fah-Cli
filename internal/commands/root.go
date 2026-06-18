package commands

import (
	"fmt"
	"sort"
	"strings"

	"fahscan/internal/config"
	"fahscan/internal/output"
	"fahscan/internal/scanner"
	"fahscan/internal/validate"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error { return rootCmd().Execute() }

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "fahscan", Short: "Defensive scanner validation and profile CLI", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd(), targetCmd(), portsCmd())
	return cmd
}
func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Run: func(cmd *cobra.Command, args []string) { fmt.Fprintln(cmd.OutOrStdout(), "fahscan "+version) }}
}
func initCmd() *cobra.Command {
	return &cobra.Command{Use: "init", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Init()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "initialized\nconfig: %s\ndatabase: %s\n", cfg.ConfigPath, cfg.DBPath)
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
	cmd.AddCommand(&cobra.Command{Use: "schema", Run: func(cmd *cobra.Command, args []string) {
		var rows [][]string
		for _, field := range config.Schema() {
			rows = append(rows, []string{field.Key, field.Type, fmt.Sprint(field.Default), field.Description})
		}
		output.Table(cmd.OutOrStdout(), []string{"Key", "Type", "Default", "Description"}, rows)
	}})
	return cmd
}
func targetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "target"}
	cmd.AddCommand(&cobra.Command{Use: "validate <target>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		info, err := validate.ParseTarget(args[0], cfg)
		if err != nil {
			return err
		}
		output.KV(cmd.OutOrStdout(), "target", info.Value)
		output.KV(cmd.OutOrStdout(), "type", info.Type)
		return nil
	}})
	return cmd
}
func portsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ports"}
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
		parts := make([]string, len(ports))
		for i, port := range ports {
			parts[i] = fmt.Sprint(port)
		}
		fmt.Fprintln(cmd.OutOrStdout(), strings.Join(parts, ","))
		return nil
	}})
	return cmd
}
