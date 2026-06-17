package commands

import (
	"fmt"
	"sort"

	"fahscan/internal/config"
	"fahscan/internal/output"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

func Execute() error { return rootCmd().Execute() }

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "fahscan", Short: "CLI-only defensive scanner foundation", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(versionCmd(), initCmd(), configCmd())
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