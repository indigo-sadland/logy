package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/indigo-sadland/logy/internal/modules/tracking"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:     "holdmy",
	Short:   "Track external command executions",
	GroupID: "tracking",
}

var runExecCmd = &cobra.Command{
	Use:   "exec --domain example.com -- <command>",
	Short: "Execute a command and save its run metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTrackedCommand(cmd, args)
	},
}

var runShowCmd = &cobra.Command{
	Use:   "show --domain example.com",
	Short: "Show tracked command executions",
	RunE: func(cmd *cobra.Command, args []string) error {
		return showTrackedCommands()
	},
}

var trackedRun trackedRunOptions

type trackedRunOptions struct {
	Domain       string
	Target       string
	Tool         string
	Wordlist     string
	Notes        string
	ConfigPath   string
	RecordOutput bool
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.AddCommand(runExecCmd)
	runCmd.AddCommand(runShowCmd)

	runExecCmd.Flags().StringVarP(&trackedRun.Domain, "domain", "d", "", "root domain label for this run")
	runExecCmd.Flags().StringVarP(&trackedRun.Target, "target", "t", "", "specific target this command was run against; inferred when possible")
	runExecCmd.Flags().StringVar(&trackedRun.Tool, "tool", "", "tool name; defaults to the command executable")
	runExecCmd.Flags().StringVarP(&trackedRun.Wordlist, "wordlist", "w", "", "wordlist used by this command")
	runExecCmd.Flags().StringVar(&trackedRun.Notes, "notes", "", "free-form notes for this command run")
	runExecCmd.Flags().BoolVar(&trackedRun.RecordOutput, "record-output", false, "record terminal output to a transcript file using script(1)")
	runExecCmd.Flags().StringVar(&trackedRun.ConfigPath, "config", defaultConfigPath(), "path to logy's config yaml")

	runShowCmd.Flags().StringVarP(&trackedRun.Domain, "domain", "d", "", "root domain label to show runs for")
	runShowCmd.Flags().StringVarP(&trackedRun.Target, "target", "t", "", "filter by target")
	runShowCmd.Flags().StringVar(&trackedRun.Tool, "tool", "", "filter by tool")
	runShowCmd.Flags().StringVar(&trackedRun.ConfigPath, "config", defaultConfigPath(), "path to logy's config yaml")
}

func runTrackedCommand(cmd *cobra.Command, args []string) error {
	opts := normalizeTrackedRunOptions(trackedRun)
	domain, err := requireDomainLabel(opts.Domain)
	if err != nil {
		return err
	}

	service := tracking.Service{TranscriptDir: defaultTranscriptDirPath()}
	result, runErr := service.Execute(cmd.Context(), tracking.ExecOptions{
		Domain:       domain,
		Target:       opts.Target,
		Tool:         opts.Tool,
		Wordlist:     opts.Wordlist,
		Notes:        opts.Notes,
		ConfigPath:   opts.ConfigPath,
		RecordOutput: opts.RecordOutput,
	}, args)

	if err := writeTrackingJSON(result); err != nil {
		return err
	}
	return runErr
}

func showTrackedCommands() error {
	opts := normalizeTrackedRunOptions(trackedRun)
	domain, err := requireDomainLabel(opts.Domain)
	if err != nil {
		return err
	}

	service := tracking.Service{TranscriptDir: defaultTranscriptDirPath()}
	result, err := service.Show(tracking.ShowOptions{
		Domain:     domain,
		Target:     opts.Target,
		Tool:       opts.Tool,
		ConfigPath: opts.ConfigPath,
	})
	if err != nil {
		return err
	}
	return writeTrackingJSON(result)
}

func normalizeTrackedRunOptions(opts trackedRunOptions) trackedRunOptions {
	opts.Domain = strings.TrimSpace(opts.Domain)
	opts.Target = strings.TrimSpace(opts.Target)
	opts.Tool = strings.TrimSpace(opts.Tool)
	opts.Wordlist = strings.TrimSpace(opts.Wordlist)
	opts.Notes = strings.TrimSpace(opts.Notes)
	opts.ConfigPath = strings.TrimSpace(opts.ConfigPath)
	return opts
}

func writeTrackingJSON(v any) error {
	raw, err := tracking.MarshalIndented(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprint(os.Stdout, string(raw)); err != nil {
		return err
	}
	return nil
}
