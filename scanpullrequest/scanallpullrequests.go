package scanpullrequest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/froggit-go/vcsclient"
)

var errPullRequestScan = "pull request #%d scan in the '%s' repository returned the following error:\n%s"

type ScanAllPullRequestsCmd struct {
}

func (cmd ScanAllPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker, sarifPath string) error {
	for _, config := range configAggregator {
		log.Info("Scanning all open pull requests for repository:", config.RepoName)
		log.Info("-----------------------------------------------------------")
		config.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
		err := scanAllPullRequests(config, client, sarifPath)
		if err != nil {
			return err
		}
	}
	return nil
}

// Scan pull requests as follows:
// a. Retrieve all open pull requests
// b. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// c. Audit the dependencies of the source and the target branches.
// d. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func scanAllPullRequests(repo utils.Repository, client vcsclient.VcsClient, sarifPath string) (err error) {
	openPullRequests, err := client.ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName)
	if err != nil {
		return err
	}
	for _, pr := range openPullRequests {
		shouldScan, e := shouldScanPullRequest(repo, client, int(pr.ID))
		if e != nil {
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
		if !shouldScan {
			log.Info("Pull Request", pr.ID, "has already been scanned before. If you wish to scan it again, please comment \"rescan\".")
			continue
		}
		repo.PullRequestDetails = pr
		if e = scanPullRequest(&repo, client, sarifPath); e != nil {
			// If error, write it in errList and continue to the next PR.
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
	}
	return
}

func shouldScanPullRequest(repo utils.Repository, client vcsclient.VcsClient, prID int) (shouldScan bool, err error) {
	pullRequestsComments, err := utils.GetSortedPullRequestComments(client, repo.RepoOwner, repo.RepoName, prID)
	if err != nil {
		return
	}

	for _, comment := range pullRequestsComments {
		// If this a 're-scan' request comment
		if utils.IsFrogbotRescanComment(comment.Content) {
			return true, nil
		}
		// if this is a Frogbot 'scan results' comment and not 're-scan' request comment, do not scan this pull request.
		if outputwriter.IsFrogbotComment(comment.Content) {
			return false, nil
		}
	}
	// This is a new pull request, and it therefore should be scanned.
	return true, nil
}
