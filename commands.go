package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jfrog/frogbot/v2/scanpullrequest"
	"github.com/jfrog/frogbot/v2/scanrepository"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	clitool "github.com/urfave/cli/v2"
)

type FrogbotCommand interface {
	// Run the command
	Run(config utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker, sarifPath string) error
}

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    utils.ScanPullRequest,
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanPullRequestCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanRepository,
			Aliases: []string{"cfpr", "create-fix-pull-requests"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanRepositoryCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanAllPullRequests,
			Aliases: []string{"sprs", "scan-pull-requests"},
			Usage:   "Scans all the open pull requests within a single or multiple repositories with JFrog Xray for security vulnerabilities",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanAllPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanMultipleRepositories,
			Aliases: []string{"scan-and-fix-repos", "safr"},
			Usage:   "Scan single or multiple repositories and create pull requests with fixes if any security vulnerabilities are found",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanMultipleRepositories{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
	}
}

func Exec(command FrogbotCommand, commandName string) (err error) {
	// Get frogbotDetails that contains the config, server, and VCS client
	log.Info("Frogbot version:", utils.FrogbotVersion)
	frogbotDetails, err := utils.GetFrogbotDetails(commandName)
	if err != nil {
		return err
	}
	// Check if the user has access to the frogbot repository (to access the resources needed)
	frogbotRepoConnection := utils.CheckConnection(outputwriter.FrogbotRepoUrl)

	// Build the server configuration file
	originalJfrogHomeDir, tempJFrogHomeDir, err := utils.BuildServerConfigFile(frogbotDetails.ServerDetails)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, os.Setenv(utils.JfrogHomeDirEnv, originalJfrogHomeDir), fileutils.RemoveTempDir(tempJFrogHomeDir))
	}()

	// Set releases remote repository env if needed
	previousReleasesRepoEnv := os.Getenv(coreutils.ReleasesRemoteEnv)
	if frogbotDetails.ReleasesRepo != "" {
		if err = os.Setenv(coreutils.ReleasesRemoteEnv, fmt.Sprintf("frogbot/%s", frogbotDetails.ReleasesRepo)); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, os.Setenv(coreutils.ReleasesRemoteEnv, previousReleasesRepoEnv))
		}()
	}

	// Send a usage report
	waitForUsageResponse := utils.ReportUsageOnCommand(commandName, frogbotDetails.ServerDetails, frogbotDetails.Repositories)

	// Invoke the command interface
	log.Info(fmt.Sprintf("Running Frogbot %q command", commandName))
	err = command.Run(frogbotDetails.Repositories, frogbotDetails.GitClient, frogbotRepoConnection, frogbotDetails.SarifPath)

	// Wait for usage reporting to finish.
	waitForUsageResponse()

	if err != nil && usage.ShouldReportUsage() {
		if reportError := xsc.ReportError(frogbotDetails.ServerDetails, err, "frogbot"); reportError != nil {
			log.Debug(reportError)
		}
	} else {
		log.Info(fmt.Sprintf("Frogbot %q command finished successfully", commandName))
	}
	return err
}
