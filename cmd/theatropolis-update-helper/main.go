// theatropolis-update-helper is the only project binary intended to run as
// root. It has no listener or control-plane client: systemd invokes one fixed
// subcommand after an unprivileged service writes a bounded request file.
package main

import (
	"context"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
)

const defaultHelperInstallPath = "/usr/local/libexec/theatropolis/theatropolis-update-helper"

const theatropolisModulePath = "github.com/masterauguste/theatropolis"

var (
	version   = "development"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("update helper stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return errors.New("the update helper must run as root")
	}
	if len(arguments) == 0 {
		return errors.New("expected apply-theatropolis, apply-sing-box, or version")
	}
	switch arguments[0] {
	case "apply-theatropolis":
		return applyTheatropolis(arguments[1:])
	case "apply-sing-box":
		return applySingBox(arguments[1:])
	case "version":
		fmt.Printf("%s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func applyTheatropolis(arguments []string) error {
	flags := flag.NewFlagSet("apply-theatropolis", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String("state-dir", "", "component state directory")
	installPath := flags.String("install-path", "", "installed component binary")
	helperInstallPath := flags.String(
		"helper-install-path",
		defaultHelperInstallPath,
		"installed root update helper",
	)
	component := flags.String("component", "", "agent or master")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*component != "agent" && *component != "master") {
		return errors.New("component must be agent or master and positional arguments are not accepted")
	}
	runningVersion, err := installedComponentVersion(*installPath, *component)
	if err != nil {
		return fmt.Errorf("inspect installed %s version: %w", *component, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return agentupdate.Apply(ctx, agentupdate.ApplyOptions{
		StateDirectory:    *stateDirectory,
		InstallPath:       *installPath,
		HelperInstallPath: *helperInstallPath,
		Component:         *component,
		Architecture:      runtime.GOARCH,
		RunningVersion:    runningVersion,
	})
}

func installedComponentVersion(path, component string) (string, error) {
	if component != "agent" && component != "master" {
		return "", errors.New("component is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	const maximumComponentSize = 128 << 20
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumComponentSize {
		return "", errors.New("installed component is not a bounded regular file")
	}
	metadata, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", errors.New("installed component has no readable Go build information")
	}
	return componentVersionFromBuildInfo(metadata, component)
}

func componentVersionFromBuildInfo(metadata *buildinfo.BuildInfo, component string) (string, error) {
	if metadata == nil ||
		metadata.Path != theatropolisModulePath+"/cmd/theatropolis-"+component ||
		metadata.Main.Path != theatropolisModulePath ||
		!agentupdate.ValidVersion(metadata.Main.Version) {
		return "", errors.New("installed component build identity is invalid")
	}
	return metadata.Main.Version, nil
}

func applySingBox(arguments []string) error {
	flags := flag.NewFlagSet("apply-sing-box", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String("state-dir", "", "agent state directory")
	installPath := flags.String("install-path", "", "installed sing-box binary")
	libraryPath := flags.String("library-path", "", "installed libcronet library")
	validationUser := flags.String(
		"validation-user",
		"theatropolis-agent",
		"unprivileged account used to execute candidate code",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("apply-sing-box does not accept positional arguments")
	}
	runningVersion, _ := singbox.ExecutableVersion(context.Background(), *installPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return singboxupdate.Apply(ctx, singboxupdate.ApplyOptions{
		StateDirectory: *stateDirectory,
		InstallPath:    *installPath,
		LibraryPath:    *libraryPath,
		Architecture:   runtime.GOARCH,
		RunningVersion: runningVersion,
		ValidationUser: *validationUser,
	})
}
