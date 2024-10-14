package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/formats"
	securityutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	SecurityIssueFoundErr   = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	noGitHubEnvErr          = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	analyticsScanPrScanType = "PR"
)

type ScanPullRequestCmd struct{}

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker, sarifPath string) (err error) {
	if err = utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err = verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return
		}
	}
	repoConfig.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
	if repoConfig.PullRequestDetails, err = client.GetPullRequestByID(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, int(repoConfig.PullRequestDetails.ID)); err != nil {
		return
	}
	return scanPullRequest(repoConfig, client, sarifPath)
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
		return errors.New(err.Error() + "\n" + noGitHubEnvErr)
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
func scanPullRequest(repo *utils.Repository, client vcsclient.VcsClient, sarifPath string) (err error) {
	pullRequestDetails := repo.PullRequestDetails
	log.Info(fmt.Sprintf("Scanning Pull Request #%d (from source branch: <%s/%s/%s> to target branch: <%s/%s/%s>)",
		pullRequestDetails.ID,
		pullRequestDetails.Source.Owner, pullRequestDetails.Source.Repository, pullRequestDetails.Source.Name,
		pullRequestDetails.Target.Owner, pullRequestDetails.Target.Repository, pullRequestDetails.Target.Name))
	log.Info("-----------------------------------------------------------")

	analyticsService := utils.AddAnalyticsGeneralEvent(nil, &repo.Server, analyticsScanPrScanType)
	defer func() {
		analyticsService.UpdateAndSendXscAnalyticsGeneralEventFinalize(err)
	}()

	// Audit PR code
	issues, err := auditPullRequest(repo, client, analyticsService, sarifPath)
	if err != nil {
		return
	}

	// Output results
	shouldSendExposedSecretsEmail := issues.SecretsExists() && repo.SmtpServer != ""
	if shouldSendExposedSecretsEmail {
		secretsEmailDetails := utils.NewSecretsEmailDetails(client, repo, issues.Secrets)
		if err = utils.AlertSecretsExposed(secretsEmailDetails); err != nil {
			return
		}
	}

	// Handle PR comments for scan output
	if err = utils.HandlePullRequestCommentsAfterScan(issues, repo, client, int(pullRequestDetails.ID)); err != nil {
		return
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if toFailTaskStatus(repo, issues) {
		err = errors.New(SecurityIssueFoundErr)
		return
	}
	return
}

func toFailTaskStatus(repo *utils.Repository, issues *utils.IssuesCollection) bool {
	failFlagSet := repo.FailOnSecurityIssues != nil && *repo.FailOnSecurityIssues
	return failFlagSet && issues.IssuesExists()
}

// Downloads Pull Requests branches code and audits them
func auditPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient, analyticsService *xsc.AnalyticsMetricsService, sarifPath string) (issuesCollection *utils.IssuesCollection, err error) {
	scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
		SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey, len(repoConfig.AllowedLicenses) > 0).
		SetFixableOnly(repoConfig.FixableOnly).
		SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues).
		SetConfigProfile(repoConfig.ConfigProfile).
		SetSkipAutoInstall(repoConfig.SkipAutoInstall)
	if scanDetails, err = scanDetails.SetMinSeverity(repoConfig.MinSeverity); err != nil {
		return
	}

	// If MSI exists we always need to report events
	if analyticsService.GetMsi() != "" {
		// MSI is passed to XrayGraphScanParams, so it can be later used by other analytics events in the scan phase
		scanDetails.XrayGraphScanParams.MultiScanId = analyticsService.GetMsi()
	}

	issuesCollection = &utils.IssuesCollection{}
	for i := range repoConfig.Projects {
		scanDetails.SetProject(&repoConfig.Projects[i])
		var projectIssues *utils.IssuesCollection
		if projectIssues, err = auditPullRequestInProject(repoConfig, scanDetails, sarifPath); err != nil {
			return
		}
		issuesCollection.Append(projectIssues)
	}
	if analyticsService.ShouldReportEvents() {
		analyticsService.AddScanFindingsToXscAnalyticsGeneralEventFinalize(issuesCollection.CountIssuesCollectionFindings())
	}
	return
}

// Generate and write SARIF report to sarifPath
func generateAndWriteSarifReport(sourceResults *securityutils.Results, repoConfig *utils.Repository, sarifPath string) error {
	// Generate SARIF report
	log.Info("Generating SARIF report...")
	sarifReportStr, err := utils.GenerateFrogbotSarifReport(sourceResults, sourceResults.IsMultipleProject(), repoConfig.AllowedLicenses)
	if err != nil {
		log.Error("Error generating SARIF report: ", err)
		return err
	}

	// Write the SARIF report to a file
	log.Info("Writing SARIF report to file: ", sarifPath)
	err = ioutil.WriteFile(sarifPath, []byte(sarifReportStr), 0644)
	if err != nil {
		log.Error("Error writing SARIF report to file: ", err)
		return err
	}

	log.Info("SARIF report successfully written to file: ", sarifPath)
	return nil
}

func auditPullRequestInProject(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sarifPath string) (auditIssues *utils.IssuesCollection, err error) {
	// Download source branch
	sourcePullRequestInfo := scanDetails.PullRequestDetails.Source
	sourceBranchWd, cleanupSource, err := utils.DownloadRepoToTempDir(scanDetails.Client(), sourcePullRequestInfo.Owner, sourcePullRequestInfo.Repository, sourcePullRequestInfo.Name)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanupSource())
	}()

	// Audit source branch
	var sourceResults *securityutils.Results
	workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)
	log.Info("Scanning source branch...")
	sourceResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
	if err != nil {
		return
	}

	// If sarifPath is provided, generate and write SARIF report
	if sarifPath != "" {
		if err = generateAndWriteSarifReport(sourceResults, repoConfig, sarifPath); err != nil {
			return
		}
	}

	// Set JAS output flags
	sourceScanResults := sourceResults.ExtendedScanResults
	repoConfig.OutputWriter.SetJasOutputFlags(sourceScanResults.EntitledForJas, len(sourceScanResults.ApplicabilityScanResults) > 0)

	// Get all issues that exist in the source branch
	if repoConfig.IncludeAllVulnerabilities {
		if auditIssues, err = getAllIssues(sourceResults, repoConfig.AllowedLicenses); err != nil {
			return
		}
		utils.ConvertSarifPathsToRelative(auditIssues, sourceBranchWd)
		return
	}

	var targetBranchWd string
	if auditIssues, targetBranchWd, err = auditTargetBranch(repoConfig, scanDetails, sourceResults); err != nil {
		return
	}
	utils.ConvertSarifPathsToRelative(auditIssues, sourceBranchWd, targetBranchWd)
	return
}

func auditTargetBranch(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceScanResults *securityutils.Results) (newIssues *utils.IssuesCollection, targetBranchWd string, err error) {
	// Download target branch (if needed)
	cleanupTarget := func() error { return nil }
	if !repoConfig.IncludeAllVulnerabilities {
		targetBranchInfo := repoConfig.PullRequestDetails.Target
		if targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(scanDetails.Client(), targetBranchInfo.Owner, targetBranchInfo.Repository, targetBranchInfo.Name); err != nil {
			return
		}
	}
	defer func() {
		err = errors.Join(err, cleanupTarget())
	}()

	// Set target branch scan details
	var targetResults *securityutils.Results
	workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)
	log.Info("Scanning target branch...")
	targetResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
	if err != nil {
		return
	}

	// Get newly added issues
	newIssues, err = getNewlyAddedIssues(targetResults, sourceScanResults, repoConfig.AllowedLicenses)
	return
}

func getAllIssues(results *securityutils.Results, allowedLicenses []string) (*utils.IssuesCollection, error) {
	log.Info("Frogbot is configured to show all vulnerabilities")
	scanResults := results.ExtendedScanResults
	xraySimpleJson, err := securityutils.ConvertXrayScanToSimpleJson(results, results.IsMultipleProject(), false, true, allowedLicenses)
	if err != nil {
		return nil, err
	}
	return &utils.IssuesCollection{
		Vulnerabilities: append(xraySimpleJson.Vulnerabilities, xraySimpleJson.SecurityViolations...),
		Iacs:            securityutils.PrepareIacs(scanResults.IacScanResults),
		Secrets:         securityutils.PrepareSecrets(scanResults.SecretsScanResults),
		Sast:            securityutils.PrepareSast(scanResults.SastScanResults),
		Licenses:        xraySimpleJson.LicensesViolations,
	}, nil
}

// Returns all the issues found in the source branch that didn't exist in the target branch.
func getNewlyAddedIssues(targetResults, sourceResults *securityutils.Results, allowedLicenses []string) (*utils.IssuesCollection, error) {
	var newVulnerabilitiesOrViolations []formats.VulnerabilityOrViolationRow
	var newLicenses []formats.LicenseRow
	var err error
	if len(sourceResults.GetScaScansXrayResults()) > 0 {
		if newVulnerabilitiesOrViolations, newLicenses, err = createNewVulnerabilitiesRows(targetResults, sourceResults, allowedLicenses); err != nil {
			return nil, err
		}
	}

	var newIacs []formats.SourceCodeRow
	if len(sourceResults.ExtendedScanResults.IacScanResults) > 0 {
		targetIacRows := securityutils.PrepareIacs(targetResults.ExtendedScanResults.IacScanResults)
		sourceIacRows := securityutils.PrepareIacs(sourceResults.ExtendedScanResults.IacScanResults)
		newIacs = createNewSourceCodeRows(targetIacRows, sourceIacRows)
	}

	var newSecrets []formats.SourceCodeRow
	if len(sourceResults.ExtendedScanResults.SecretsScanResults) > 0 {
		targetSecretsRows := securityutils.PrepareIacs(targetResults.ExtendedScanResults.SecretsScanResults)
		sourceSecretsRows := securityutils.PrepareIacs(sourceResults.ExtendedScanResults.SecretsScanResults)
		newSecrets = createNewSourceCodeRows(targetSecretsRows, sourceSecretsRows)
	}

	var newSast []formats.SourceCodeRow
	if len(targetResults.ExtendedScanResults.SastScanResults) > 0 {
		targetSastRows := securityutils.PrepareSast(targetResults.ExtendedScanResults.SastScanResults)
		sourceSastRows := securityutils.PrepareSast(sourceResults.ExtendedScanResults.SastScanResults)
		newSast = createNewSourceCodeRows(targetSastRows, sourceSastRows)
	}

	return &utils.IssuesCollection{
		Vulnerabilities: newVulnerabilitiesOrViolations,
		Iacs:            newIacs,
		Secrets:         newSecrets,
		Sast:            newSast,
		Licenses:        newLicenses,
	}, nil
}

func createNewSourceCodeRows(targetResults, sourceResults []formats.SourceCodeRow) []formats.SourceCodeRow {
	targetSourceCodeVulnerabilitiesKeys := datastructures.MakeSet[string]()
	for _, row := range targetResults {
		if row.Fingerprint != "" {
			targetSourceCodeVulnerabilitiesKeys.Add(row.Fingerprint)
		} else {
			targetSourceCodeVulnerabilitiesKeys.Add(row.File + row.Snippet)
		}
	}
	var addedSourceCodeVulnerabilities []formats.SourceCodeRow
	for _, row := range sourceResults {
		if !targetSourceCodeVulnerabilitiesKeys.Exists(row.File+row.Snippet) && !targetSourceCodeVulnerabilitiesKeys.Exists(row.Fingerprint) {
			addedSourceCodeVulnerabilities = append(addedSourceCodeVulnerabilities, row)
		}
	}
	return addedSourceCodeVulnerabilities
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createNewVulnerabilitiesRows(targetResults, sourceResults *securityutils.Results, allowedLicenses []string) (vulnerabilityOrViolationRows []formats.VulnerabilityOrViolationRow, licenseRows []formats.LicenseRow, err error) {
	targetScanAggregatedResults := aggregateScanResults(targetResults.GetScaScansXrayResults())
	sourceScanAggregatedResults := aggregateScanResults(sourceResults.GetScaScansXrayResults())

	if len(sourceScanAggregatedResults.Violations) > 0 {
		return getNewViolations(&targetScanAggregatedResults, &sourceScanAggregatedResults, sourceResults)
	}
	if len(sourceScanAggregatedResults.Vulnerabilities) > 0 {
		if vulnerabilityOrViolationRows, err = getNewSecurityVulnerabilities(&targetScanAggregatedResults, &sourceScanAggregatedResults, sourceResults); err != nil {
			return
		}
	}
	var newLicenses []formats.LicenseRow
	if newLicenses, err = getNewLicenseRows(&targetScanAggregatedResults, &sourceScanAggregatedResults); err != nil {
		return
	}
	licenseRows = securityutils.GetViolatedLicenses(allowedLicenses, newLicenses)
	return
}

func getNewSecurityVulnerabilities(targetScan, sourceScan *services.ScanResponse, auditResults *securityutils.Results) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetVulnerabilitiesRows, err := securityutils.PrepareVulnerabilities(targetScan.Vulnerabilities, auditResults, auditResults.IsMultipleProject(), true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	sourceVulnerabilitiesRows, err := securityutils.PrepareVulnerabilities(sourceScan.Vulnerabilities, auditResults, auditResults.IsMultipleProject(), true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	newVulnerabilitiesRows = getUniqueVulnerabilityOrViolationRows(targetVulnerabilitiesRows, sourceVulnerabilitiesRows)
	return
}

func getUniqueVulnerabilityOrViolationRows(targetRows, sourceRows []formats.VulnerabilityOrViolationRow) []formats.VulnerabilityOrViolationRow {
	existingRows := make(map[string]formats.VulnerabilityOrViolationRow)
	var newRows []formats.VulnerabilityOrViolationRow
	for _, row := range targetRows {
		existingRows[utils.GetVulnerabiltiesUniqueID(row)] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingRows[utils.GetVulnerabiltiesUniqueID(row)]; !exists {
			newRows = append(newRows, row)
		}
	}
	return newRows
}

func getNewViolations(targetScan, sourceScan *services.ScanResponse, auditResults *securityutils.Results) (newSecurityViolationsRows []formats.VulnerabilityOrViolationRow, newLicenseViolationsRows []formats.LicenseRow, err error) {
	targetSecurityViolationsRows, targetLicenseViolationsRows, _, err := securityutils.PrepareViolations(targetScan.Violations, auditResults, auditResults.IsMultipleProject(), true)
	if err != nil {
		return
	}
	sourceSecurityViolationsRows, sourceLicenseViolationsRows, _, err := securityutils.PrepareViolations(sourceScan.Violations, auditResults, auditResults.IsMultipleProject(), true)
	if err != nil {
		return
	}
	newSecurityViolationsRows = getUniqueVulnerabilityOrViolationRows(targetSecurityViolationsRows, sourceSecurityViolationsRows)
	if len(sourceLicenseViolationsRows) > 0 {
		newLicenseViolationsRows = getUniqueLicenseRows(targetLicenseViolationsRows, sourceLicenseViolationsRows)
	}
	return
}

func getNewLicenseRows(targetScan, sourceScan *services.ScanResponse) (newLicenses []formats.LicenseRow, err error) {
	targetLicenses, err := securityutils.PrepareLicenses(targetScan.Licenses)
	if err != nil {
		return
	}
	sourceLicenses, err := securityutils.PrepareLicenses(sourceScan.Licenses)
	if err != nil {
		return
	}
	newLicenses = getUniqueLicenseRows(targetLicenses, sourceLicenses)
	return
}

func getUniqueLicenseRows(targetRows, sourceRows []formats.LicenseRow) []formats.LicenseRow {
	existingLicenses := make(map[string]formats.LicenseRow)
	var newLicenses []formats.LicenseRow
	for _, row := range targetRows {
		existingLicenses[getUniqueLicenseKey(row)] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingLicenses[getUniqueLicenseKey(row)]; !exists {
			newLicenses = append(newLicenses, row)
		}
	}
	return newLicenses
}

func getUniqueLicenseKey(license formats.LicenseRow) string {
	return license.LicenseKey + license.ImpactedDependencyName + license.ImpactedDependencyType
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
		Licenses:        []services.License{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
		aggregateResults.Licenses = append(aggregateResults.Licenses, scanResult.Licenses...)
	}
	return aggregateResults
}
