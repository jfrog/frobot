package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/frogbot/commands/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/datastructures"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
)

const (
	securityIssueFoundErr   = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	noGitHubEnvErr          = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	frogbotCommentNotFound  = -1
)

type ScanPullRequestCmd struct{}

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) (err error) {
	if err = utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err = verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return
		}
	}

	if repoConfig.PullRequestDetails, err = client.GetPullRequestByID(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, int(repoConfig.PullRequestDetails.ID)); err != nil {
		return
	}

	return scanPullRequest(repoConfig, client)
}

// Verify that the 'frogbot' GitHub environment was properly configured on the repository
func verifyGitHubFrogbotEnvironment(client vcsclient.VcsClient, repoConfig *utils.Repository) error {
	if repoConfig.APIEndpoint != "" && repoConfig.APIEndpoint != "https://api.github.com" {
		// Don't verify 'frogbot' environment on GitHub on-prem
		return nil
	}
	if _, exist := os.LookupEnv(utils.GitHubActionsEnv); !exist {
		// Don't verify 'frogbot' environment on non GitHub Actions CI
		return nil
	}

	// If the repository is not public, using 'frogbot' environment is not mandatory
	repoInfo, err := client.GetRepositoryInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName)
	if err != nil {
		return err
	}
	if repoInfo.RepositoryVisibility != vcsclient.Public {
		return nil
	}

	// Get the 'frogbot' environment info and make sure it exists and includes reviewers
	repoEnvInfo, err := client.GetRepositoryEnvironmentInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, "frogbot")
	if err != nil {
		return errors.New(err.Error() + "/n" + noGitHubEnvErr)
	}
	if len(repoEnvInfo.Reviewers) == 0 {
		return errors.New(noGitHubEnvReviewersErr)
	}

	return nil
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(repo *utils.Repository, client vcsclient.VcsClient) (err error) {
	pullRequestDetails := repo.PullRequestDetails
	log.Info(fmt.Sprintf("Scanning Pull Request #%d (from source branch: <%s/%s/%s> to target branch: <%s/%s/%s>)",
		pullRequestDetails.ID,
		pullRequestDetails.Source.Owner, pullRequestDetails.Source.Repository, pullRequestDetails.Source.Name,
		pullRequestDetails.Target.Owner, pullRequestDetails.Target.Repository, pullRequestDetails.Target.Name))
	log.Info("-----------------------------------------------------------")

	// Audit PR code
	vulnerabilitiesRows, iacRows, secretsRows, err := auditPullRequest(repo, client, pullRequestDetails)
	if err != nil {
		return
	}

	shouldSendExposedSecretsEmail := len(secretsRows) > 0 && repo.SmtpServer != ""
	if shouldSendExposedSecretsEmail {
		prSourceDetails := pullRequestDetails.Source
		secretsEmailDetails := utils.NewSecretsEmailDetails(
			client, repo.GitProvider,
			prSourceDetails.Owner, prSourceDetails.Repository,
			prSourceDetails.Name, pullRequestDetails.URL,
			secretsRows, repo.EmailDetails)
		if err = utils.AlertSecretsExposed(secretsEmailDetails); err != nil {
			return
		}
	}

	// Delete previous Frogbot pull request message if exists
	if err = deleteExistingPullRequestComment(repo, client); err != nil {
		return
	}

	// Create a pull request message
	message := createPullRequestMessage(vulnerabilitiesRows, iacRows, repo.OutputWriter)

	// Add comment to the pull request
	if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, message, int(pullRequestDetails.ID)); err != nil {
		err = errors.New("couldn't add pull request comment: " + err.Error())
		return
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if repo.FailOnSecurityIssues != nil && *repo.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	return
}

// Downloads Pull Requests branches code and audits them
func auditPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient, pullRequestDetails vcsclient.PullRequestInfo) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, iacRows []formats.IacSecretsRow, secretsRows []formats.IacSecretsRow, err error) {
	// Download source branch
	sourceBranchInfo := pullRequestDetails.Source
	sourceBranchWd, cleanupSource, err := utils.DownloadRepoToTempDir(client, sourceBranchInfo.Owner, sourceBranchInfo.Repository, sourceBranchInfo.Name)
	if err != nil {
		return
	}

	// Download target branch (if needed)
	targetBranchWd := ""
	cleanupTarget := func() error { return nil }
	if !repoConfig.IncludeAllVulnerabilities {
		targetBranchInfo := pullRequestDetails.Target
		targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(client, targetBranchInfo.Owner, targetBranchInfo.Repository, targetBranchInfo.Name)
		if err != nil {
			return
		}
	}
	defer func() {
		err = errors.Join(err, cleanupSource(), cleanupTarget())
	}()

	scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
		SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey).
		SetMinSeverity(repoConfig.MinSeverity).
		SetFixableOnly(repoConfig.FixableOnly).
		SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues)

	for i := range repoConfig.Projects {
		scanDetails.SetProject(&repoConfig.Projects[i])

		// Audit source branch
		var sourceResults *audit.Results
		workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)
		sourceResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
		if err != nil {
			return
		}

		// Set JAS output flags
		sourceScanResults := sourceResults.ExtendedScanResults
		repoConfig.OutputWriter.SetJasOutputFlags(sourceScanResults.EntitledForJas, len(sourceScanResults.ApplicabilityScanResults) > 0)

		// Get all issues that were found in the source branch
		if repoConfig.IncludeAllVulnerabilities {
			log.Info("Frogbot is configured to show all vulnerabilities")
			var allIssuesRows []formats.VulnerabilityOrViolationRow
			allIssuesRows, err = getScanVulnerabilitiesRows(sourceResults)
			if err != nil {
				return
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
			iacRows = append(iacRows, xrayutils.PrepareIacs(sourceScanResults.IacScanResults)...)
			secretsRows = append(secretsRows, xrayutils.PrepareSecrets(sourceScanResults.SecretsScanResults)...)
			continue
		}

		// Set target branch scan details
		var targetResults *audit.Results
		workingDirs = utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)
		targetResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
		if err != nil {
			return
		}

		// Get new issues
		var newVulnerabilities []formats.VulnerabilityOrViolationRow
		var newIacs, newSecrets []formats.IacSecretsRow
		if newVulnerabilities, newIacs, newSecrets, err = getNewIssues(targetResults, sourceResults); err != nil {
			return
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newVulnerabilities...)
		iacRows = append(iacRows, newIacs...)
		secretsRows = append(secretsRows, newSecrets...)
	}
	return
}

func getNewIssues(targetResults, sourceResults *audit.Results) ([]formats.VulnerabilityOrViolationRow, []formats.IacSecretsRow, []formats.IacSecretsRow, error) {
	var newVulnerabilities []formats.VulnerabilityOrViolationRow
	var err error
	if len(sourceResults.ExtendedScanResults.XrayResults) > 0 {
		if newVulnerabilities, err = createNewVulnerabilitiesRows(targetResults, sourceResults); err != nil {
			return nil, nil, nil, err
		}
	}

	var newIacs []formats.IacSecretsRow
	if len(sourceResults.ExtendedScanResults.IacScanResults) > 0 {
		targetIacRows := xrayutils.PrepareIacs(targetResults.ExtendedScanResults.IacScanResults)
		sourceIacRows := xrayutils.PrepareIacs(sourceResults.ExtendedScanResults.IacScanResults)
		newIacs = createNewIacOrSecretsRows(targetIacRows, sourceIacRows)
	}

	var newSecrets []formats.IacSecretsRow
	if len(sourceResults.ExtendedScanResults.SecretsScanResults) > 0 {
		targetSecretsRows := xrayutils.PrepareSecrets(targetResults.ExtendedScanResults.SecretsScanResults)
		sourceSecretsRows := xrayutils.PrepareSecrets(sourceResults.ExtendedScanResults.SecretsScanResults)
		newSecrets = createNewIacOrSecretsRows(targetSecretsRows, sourceSecretsRows)
	}

	return newVulnerabilities, newIacs, newSecrets, nil
}

func createNewIacOrSecretsRows(targetResults, sourceResults []formats.IacSecretsRow) []formats.IacSecretsRow {
	targetIacOrSecretsVulnerabilitiesKeys := datastructures.MakeSet[string]()
	for _, row := range targetResults {
		targetIacOrSecretsVulnerabilitiesKeys.Add(row.File + row.Text)
	}
	var addedIacOrSecretsVulnerabilities []formats.IacSecretsRow
	for _, row := range sourceResults {
		if !targetIacOrSecretsVulnerabilitiesKeys.Exists(row.File + row.Text) {
			addedIacOrSecretsVulnerabilities = append(addedIacOrSecretsVulnerabilities, row)
		}
	}
	return addedIacOrSecretsVulnerabilities
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createNewVulnerabilitiesRows(targetResults, sourceResults *audit.Results) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetScanAggregatedResults := aggregateScanResults(targetResults.ExtendedScanResults.XrayResults)
	sourceScanAggregatedResults := aggregateScanResults(sourceResults.ExtendedScanResults.XrayResults)

	if len(sourceScanAggregatedResults.Violations) > 0 {
		newViolations, err := getNewViolations(targetScanAggregatedResults, sourceScanAggregatedResults, sourceResults)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newViolations...)
	} else if len(sourceScanAggregatedResults.Vulnerabilities) > 0 {
		newVulnerabilities, err := getNewVulnerabilities(targetScanAggregatedResults, sourceScanAggregatedResults, sourceResults)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newVulnerabilities...)
	}

	return vulnerabilitiesRows, nil
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
	}
	return aggregateResults
}

// Create vulnerability rows. The rows should contain all the issues that were found in this module scan.
func getScanVulnerabilitiesRows(auditResults *audit.Results) ([]formats.VulnerabilityOrViolationRow, error) {
	violations, vulnerabilities, _ := xrayutils.SplitScanResults(auditResults.ExtendedScanResults.XrayResults)
	if len(violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
		return violationsRows, err
	}
	if len(vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

func getNewViolations(targetScan, sourceScan services.ScanResponse, auditResults *audit.Results) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(targetScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[utils.GetUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(sourceScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newViolationsRows, err
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[utils.GetUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(targetScan, sourceScan services.ScanResponse, auditResults *audit.Results) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	targetVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(targetScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range targetVulnerabilitiesRows {
		targetVulnerabilitiesMap[utils.GetUniqueID(vulnerability)] = vulnerability
	}
	sourceVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(sourceScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range sourceVulnerabilitiesRows {
		if _, exists := targetVulnerabilitiesMap[utils.GetUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return
}

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, iacRows []formats.IacSecretsRow, writer outputwriter.OutputWriter) string {
	if len(vulnerabilitiesRows) == 0 && len(iacRows) == 0 {
		return writer.NoVulnerabilitiesTitle() + writer.UntitledForJasMsg() + writer.Footer()
	}
	return writer.VulnerabilitiesTitle(true) + writer.VulnerabilitiesContent(vulnerabilitiesRows) + writer.IacContent(iacRows) + writer.UntitledForJasMsg() + writer.Footer()
}

func deleteExistingPullRequestComment(repository *utils.Repository, client vcsclient.VcsClient) error {
	log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
	prDetails := repository.PullRequestDetails
	comments, err := utils.GetSortedPullRequestComments(client, prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID))
	if err != nil {
		return fmt.Errorf(
			"failed to get comments. the following details were used in order to fetch the comments: <%s/%s> pull request #%d. the error received: %s",
			repository.RepoOwner, repository.RepoName, int(repository.PullRequestDetails.ID), err.Error())
	}

	commentID := frogbotCommentNotFound
	for _, comment := range comments {
		if repository.OutputWriter.IsFrogbotResultComment(comment.Content) {
			log.Debug("Found previous Frogbot comment with the id:", comment.ID)
			commentID = int(comment.ID)
			break
		}
	}

	if commentID != frogbotCommentNotFound {
		err = client.DeletePullRequestComment(context.Background(), prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID), commentID)
	}

	return err
}
