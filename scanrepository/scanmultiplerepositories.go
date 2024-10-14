package scanrepository

import (
	"errors"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

type ScanMultipleRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

func (saf *ScanMultipleRepositories) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker, sarifPath string) (err error) {
	scanRepositoryCmd := &ScanRepositoryCmd{dryRun: saf.dryRun, dryRunRepoPath: saf.dryRunRepoPath, baseWd: saf.dryRunRepoPath}
	for repoNum := range repoAggregator {
		repoAggregator[repoNum].OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
		if e := scanRepositoryCmd.scanAndFixRepository(&repoAggregator[repoNum], client, sarifPath); e != nil {
			err = errors.Join(err, e)
		}
	}
	return
}
