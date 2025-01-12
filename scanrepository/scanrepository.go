package scanrepository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/frogbot/v2/packagehandlers"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const analyticsScanRepositoryScanType = "monitor"

type ScanRepositoryCmd struct {
	// The interface that Frogbot utilizes to format and style the displayed messages on the Git providers
	outputwriter.OutputWriter
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The scanDetails of the current scan
	scanDetails *utils.ScanDetails
	// The base working directory
	baseWd string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
	// Determines whether to open a pull request for each vulnerability fix or to aggregate all fixes into one pull request
	aggregateFixes bool
	// The current project technology
	projectTech []techutils.Technology
	// Stores all package manager handlers for detected issues
	handlers map[techutils.Technology]packagehandlers.PackageHandler

	XrayVersion string
	XscVersion  string
}

func (cfp *ScanRepositoryCmd) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker) (err error) {
	if err = utils.ValidateSingleRepoConfiguration(&repoAggregator); err != nil {
		return err
	}
	repository := repoAggregator[0]
	repository.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
	cfp.XrayVersion = repository.XrayVersion
	cfp.XscVersion = repository.XscVersion
	return cfp.scanAndFixRepository(&repository, client)
}

func (cfp *ScanRepositoryCmd) scanAndFixRepository(repository *utils.Repository, client vcsclient.VcsClient) (err error) {
	if err = cfp.setCommandPrerequisites(repository, client); err != nil {
		return
	}
	for _, branch := range repository.Branches {
		cfp.scanDetails.SetBaseBranch(branch)
		cfp.scanDetails.SetXscGitInfoContext(branch, repository.Project, client)
		if err = cfp.scanAndFixBranch(repository); err != nil {
			return
		}
	}
	return
}

func (cfp *ScanRepositoryCmd) scanAndFixBranch(repository *utils.Repository) (err error) {
	repoDir, restoreBaseDir, err := cfp.cloneRepositoryOrUseLocalAndCheckoutToBranch()
	if err != nil {
		return
	}
	cfp.baseWd = repoDir
	defer func() {
		// On dry run don't delete the folder as we want to validate results
		if cfp.dryRun {
			return
		}
		err = errors.Join(err, restoreBaseDir(), fileutils.RemoveTempDir(repoDir))
	}()

	cfp.scanDetails.MultiScanId, cfp.scanDetails.StartTime = xsc.SendNewScanEvent(
		cfp.scanDetails.XrayVersion,
		cfp.scanDetails.XscVersion,
		cfp.scanDetails.ServerDetails,
		utils.CreateScanEvent(cfp.scanDetails.ServerDetails, cfp.scanDetails.XscGitInfoContext, analyticsScanRepositoryScanType),
	)

	totalFindings := 0

	defer func() {
		xsc.SendScanEndedEvent(cfp.scanDetails.XrayVersion, cfp.scanDetails.XscVersion, cfp.scanDetails.ServerDetails, cfp.scanDetails.MultiScanId, cfp.scanDetails.StartTime, totalFindings, &cfp.scanDetails.ResultContext, err)
	}()

	for i := range repository.Projects {
		cfp.scanDetails.Project = &repository.Projects[i]
		cfp.projectTech = []techutils.Technology{}
		if findings, e := cfp.scanAndFixProject(repository); e != nil {
			return e
		} else {
			totalFindings += findings
		}
	}

	return
}

func (cfp *ScanRepositoryCmd) setCommandPrerequisites(repository *utils.Repository, client vcsclient.VcsClient) (err error) {
	repositoryCloneUrl, err := repository.Git.GetRepositoryHttpsCloneUrl(client)
	if err != nil {
		return
	}
	// Set the scan details
	cfp.scanDetails = utils.NewScanDetails(client, &repository.Server, &repository.Git).
		SetJfrogVersions(cfp.XrayVersion, cfp.XscVersion).
		SetResultsContext(repositoryCloneUrl, repository.Watches, repository.JFrogProjectKey, repository.IncludeVulnerabilities, len(repository.AllowedLicenses) > 0).
		SetFailOnInstallationErrors(*repository.FailOnSecurityIssues).
		SetFixableOnly(repository.FixableOnly).
		SetConfigProfile(repository.ConfigProfile).
		SetSkipAutoInstall(repository.SkipAutoInstall).
		SetAllowPartialResults(repository.AllowPartialResults).
		SetDisableJas(repository.DisableJas)

	if cfp.scanDetails, err = cfp.scanDetails.SetMinSeverity(repository.MinSeverity); err != nil {
		return
	}

	// Set the flag for aggregating fixes to generate a unified pull request for fixing vulnerabilities
	cfp.aggregateFixes = repository.Git.AggregateFixes
	// Set the outputwriter interface for the relevant vcs git provider
	cfp.OutputWriter = outputwriter.GetCompatibleOutputWriter(repository.GitProvider)
	cfp.OutputWriter.SetSizeLimit(client)
	// Set the git client to perform git operations
	cfp.gitManager, err = utils.NewGitManager().
		SetAuth(cfp.scanDetails.Username, cfp.scanDetails.Token).
		SetDryRun(cfp.dryRun, cfp.dryRunRepoPath).
		SetRemoteGitUrl(repositoryCloneUrl)
	if err != nil {
		return
	}
	_, err = cfp.gitManager.SetGitParams(cfp.scanDetails.Git)
	return
}

func (cfp *ScanRepositoryCmd) scanAndFixProject(repository *utils.Repository) (int, error) {
	var fixNeeded bool
	totalFindings := 0
	// A map that contains the full project paths as a keys
	// The value is a map of vulnerable package names -> the scanDetails of the vulnerable packages.
	// That means we have a map of all the vulnerabilities that were found in a specific folder, along with their full scanDetails.
	vulnerabilitiesByPathMap := make(map[string]map[string]*utils.VulnerabilityDetails)
	projectFullPathWorkingDirs := utils.GetFullPathWorkingDirs(cfp.scanDetails.Project.WorkingDirs, cfp.baseWd)
	for _, fullPathWd := range projectFullPathWorkingDirs {
		scanResults, err := cfp.scan(fullPathWd)
		if err != nil {
			if err = utils.CreateErrorIfPartialResultsDisabled(cfp.scanDetails.AllowPartialResults(), fmt.Sprintf("An error occurred during Audit execution for '%s' working directory. Fixes will be skipped for this working directory", fullPathWd), err); err != nil {
				return totalFindings, err
			}
			continue
		}
		if summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: scanResults.IncludesVulnerabilities(), HasViolationContext: scanResults.HasViolationContext()}).ConvertToSummary(scanResults); err != nil {
			return totalFindings, err
		} else {
			findingCount := summary.GetTotalViolations()
			if findingCount == 0 {
				findingCount = summary.GetTotalVulnerabilities()
			}
			totalFindings += findingCount
		}

		if scanResults.EntitledForJas && repository.GitProvider.String() == vcsutils.GitHub.String() {
			// Uploads Sarif results to GitHub in order to view the scan in the code scanning UI
			// Currently available on GitHub only and JFrog Advance Security package
			// Only if Jas entitlement is available
			if err = utils.UploadSarifResultsToGithubSecurityTab(scanResults, repository, cfp.scanDetails.BaseBranch(), cfp.scanDetails.Client()); err != nil {
				log.Warn(err)
			}
		}
		if repository.DetectionOnly {
			continue
		}
		// Prepare the vulnerabilities map for each working dir path
		currPathVulnerabilities, err := cfp.getVulnerabilitiesMap(scanResults)
		if err != nil {
			if err = utils.CreateErrorIfPartialResultsDisabled(cfp.scanDetails.AllowPartialResults(), fmt.Sprintf("An error occurred while preparing the vulnerabilities map for '%s' working directory. Fixes will be skipped for this working directory", fullPathWd), err); err != nil {
				return totalFindings, err
			}
			continue
		}
		if len(currPathVulnerabilities) > 0 {
			fixNeeded = true
		}
		vulnerabilitiesByPathMap[fullPathWd] = currPathVulnerabilities
	}
	if repository.DetectionOnly {
		log.Info(fmt.Sprintf("This command is running in detection mode only. To enable automatic fixing of issues, set the '%s' environment variable to 'false'.", utils.DetectionOnlyEnv))
	} else if fixNeeded {
		return totalFindings, cfp.fixVulnerablePackages(repository, vulnerabilitiesByPathMap)
	}
	return totalFindings, nil
}

// Audit the dependencies of the current commit.
func (cfp *ScanRepositoryCmd) scan(currentWorkingDir string) (*results.SecurityCommandResults, error) {
	// Audit commit code
	auditResults := cfp.scanDetails.RunInstallAndAudit(currentWorkingDir)
	if err := auditResults.GetErrors(); err != nil {
		return nil, err
	}
	log.Info("Xray scan completed")
	cfp.OutputWriter.SetJasOutputFlags(auditResults.EntitledForJas, auditResults.HasJasScansResults(jasutils.Applicability))
	cfp.projectTech = auditResults.GetTechnologies(cfp.projectTech...)
	return auditResults, nil
}

func (cfp *ScanRepositoryCmd) getVulnerabilitiesMap(scanResults *results.SecurityCommandResults) (map[string]*utils.VulnerabilityDetails, error) {
	vulnerabilitiesMap, err := cfp.createVulnerabilitiesMap(scanResults)
	if err != nil {
		return nil, err
	}

	// Nothing to fix, return
	if len(vulnerabilitiesMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.scanDetails.RepoName)
	}
	return vulnerabilitiesMap, nil
}

func (cfp *ScanRepositoryCmd) fixVulnerablePackages(repository *utils.Repository, vulnerabilitiesByWdMap map[string]map[string]*utils.VulnerabilityDetails) (err error) {
	if cfp.aggregateFixes {
		err = cfp.fixIssuesSinglePR(repository, vulnerabilitiesByWdMap)
	} else {
		err = cfp.fixIssuesSeparatePRs(repository, vulnerabilitiesByWdMap)
	}
	if err != nil {
		return utils.CreateErrorIfPartialResultsDisabled(cfp.scanDetails.AllowPartialResults(), fmt.Sprintf("failed to fix vulnerable dependencies: %s", err.Error()), err)
	}
	return
}

func (cfp *ScanRepositoryCmd) fixIssuesSeparatePRs(repository *utils.Repository, vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails) error {
	var err error
	for fullPath, vulnerabilities := range vulnerabilitiesMap {
		if e := cfp.fixProjectVulnerabilities(repository, fullPath, vulnerabilities); e != nil {
			err = errors.Join(err, fmt.Errorf("the following errors occured while fixing vulnerabilities in '%s':\n%s", fullPath, e))
		}
	}
	return err
}

func (cfp *ScanRepositoryCmd) fixProjectVulnerabilities(repository *utils.Repository, fullProjectPath string, vulnerabilities map[string]*utils.VulnerabilityDetails) (err error) {
	// Update the working directory to the project's current working directory
	projectWorkingDir := utils.GetRelativeWd(fullProjectPath, cfp.baseWd)

	// 'CD' into the relevant working directory
	if projectWorkingDir != "" {
		var restoreDirFunc func() error
		if restoreDirFunc, err = utils.Chdir(projectWorkingDir); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, restoreDirFunc())
		}()
	}

	// Fix every vulnerability in a separate pull request and branch
	for _, vulnerability := range vulnerabilities {
		if e := cfp.fixSinglePackageAndCreatePR(repository, vulnerability); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
		}

		// After fixing the current vulnerability, checkout to the base branch to start fixing the next vulnerability
		if e := cfp.gitManager.Checkout(cfp.scanDetails.BaseBranch()); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
			return
		}
	}

	return
}

func (cfp *ScanRepositoryCmd) fixMultiplePackages(fullProjectPath string, vulnerabilities map[string]*utils.VulnerabilityDetails) (fixedVulnerabilities []*utils.VulnerabilityDetails, err error) {
	// Update the working directory to the project's current working directory
	projectWorkingDir := utils.GetRelativeWd(fullProjectPath, cfp.baseWd)

	// 'CD' into the relevant working directory
	if projectWorkingDir != "" {
		var restoreDir func() error
		restoreDir, err = utils.Chdir(projectWorkingDir)
		if err != nil {
			return nil, err
		}
		defer func() {
			err = errors.Join(err, restoreDir())
		}()
	}
	for _, vulnDetails := range vulnerabilities {
		if e := cfp.updatePackageToFixedVersion(vulnDetails); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
			continue
		}
		fixedVulnerabilities = append(fixedVulnerabilities, vulnDetails)
		log.Info(fmt.Sprintf("Updated dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	}
	return
}

// Fixes all the vulnerabilities in a single aggregated pull request.
// If an existing aggregated fix is present, it checks for different scan results.
// If the scan results are the same, no action is taken.
// Otherwise, it performs a force push to the same branch and reopens the pull request if it was closed.
// Only one aggregated pull request should remain open at all times.
func (cfp *ScanRepositoryCmd) fixIssuesSinglePR(repository *utils.Repository, vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails) (err error) {
	aggregatedFixBranchName := cfp.gitManager.GenerateAggregatedFixBranchName(cfp.scanDetails.BaseBranch(), cfp.projectTech)
	existingPullRequestDetails, err := cfp.getOpenPullRequestBySourceBranch(aggregatedFixBranchName)
	if err != nil {
		return
	}
	return cfp.aggregateFixAndOpenPullRequest(repository, vulnerabilitiesMap, aggregatedFixBranchName, existingPullRequestDetails)
}

// Handles possible error of update package operation
// When the expected custom error occurs, log to debug.
// else, return the error
func (cfp *ScanRepositoryCmd) handleUpdatePackageErrors(err error) error {
	var errUnsupportedFix *utils.ErrUnsupportedFix
	var errNoChangesToCommit *utils.ErrNothingToCommit

	switch {
	case errors.As(err, &errUnsupportedFix):
		log.Debug(strings.TrimSpace(err.Error()))
	case errors.As(err, &errNoChangesToCommit):
		log.Info(err.Error())
	default:
		return err
	}
	return nil
}

// Creates a branch for the fixed package and open pull request against the target branch.
// In case a branch already exists on remote, we skip it.
func (cfp *ScanRepositoryCmd) fixSinglePackageAndCreatePR(repository *utils.Repository, vulnDetails *utils.VulnerabilityDetails) (err error) {
	fixVersion := vulnDetails.SuggestedFixedVersion
	log.Debug("Attempting to fix", fmt.Sprintf("%s:%s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion), "with", fixVersion)
	fixBranchName, err := cfp.gitManager.GenerateFixBranchName(cfp.scanDetails.BaseBranch(), vulnDetails.ImpactedDependencyName, fixVersion)
	if err != nil {
		return
	}
	existsInRemote, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	if existsInRemote {
		log.Info(fmt.Sprintf("A pull request updating the dependency '%s' to version '%s' already exists. Skipping...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
		return
	}

	workTreeIsClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if !workTreeIsClean {
		// If there are local changes, such as files generated after running an 'install' command, we aim to preserve them in the new branch
		err = cfp.gitManager.CreateBranchAndCheckout(fixBranchName, true)
	} else {
		err = cfp.gitManager.CreateBranchAndCheckout(fixBranchName, false)
	}
	if err != nil {
		return
	}

	if err = cfp.updatePackageToFixedVersion(vulnDetails); err != nil {
		return
	}
	if err = cfp.openFixingPullRequest(repository, fixBranchName, vulnDetails); err != nil {
		return errors.Join(fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: ", vulnDetails.ImpactedDependencyName, fixVersion), err)
	}
	log.Info(fmt.Sprintf("Created Pull Request updating dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	return
}

func (cfp *ScanRepositoryCmd) openFixingPullRequest(repository *utils.Repository, fixBranchName string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		// In instances where a fix is required that Frogbot does not support, the worktree will remain clean, and there will be nothing to push
		return &utils.ErrNothingToCommit{PackageName: vulnDetails.ImpactedDependencyName}
	}
	commitMessage := cfp.gitManager.GenerateCommitMessage(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err = cfp.cleanNewFilesMissingInRemote(); err != nil {
		log.Warn(fmt.Sprintf("failed fo clean untracked files from '%s' due to the following errors: %s", cfp.baseWd, err.Error()))
	}
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	if err = cfp.gitManager.Push(false, fixBranchName); err != nil {
		return
	}
	return cfp.handleFixPullRequestContent(repository, fixBranchName, nil, vulnDetails)
}

func (cfp *ScanRepositoryCmd) handleFixPullRequestContent(repository *utils.Repository, fixBranchName string, pullRequestInfo *vcsclient.PullRequestInfo, vulnerabilities ...*utils.VulnerabilityDetails) (err error) {
	pullRequestTitle, prBody, extraComments, err := cfp.preparePullRequestDetails(vulnerabilities...)
	if err != nil {
		return
	}
	// Update PR description
	if pullRequestInfo, err = cfp.createOrUpdatePullRequest(repository, pullRequestInfo, fixBranchName, pullRequestTitle, prBody); err != nil {
		return
	}
	// Update PR extra comments
	client := cfp.scanDetails.Client()
	for _, comment := range extraComments {
		if err = client.AddPullRequestComment(context.Background(), cfp.scanDetails.RepoOwner, cfp.scanDetails.RepoName, comment, int(pullRequestInfo.ID)); err != nil {
			err = errors.New("couldn't add pull request comment: " + err.Error())
			return
		}
	}
	return
}

func (cfp *ScanRepositoryCmd) createOrUpdatePullRequest(repository *utils.Repository, pullRequestInfo *vcsclient.PullRequestInfo, fixBranchName, pullRequestTitle, prBody string) (prInfo *vcsclient.PullRequestInfo, err error) {
	if pullRequestInfo == nil {
		log.Info("Creating Pull Request from:", fixBranchName, "to:", cfp.scanDetails.BaseBranch())
		if err = cfp.scanDetails.Client().CreatePullRequest(context.Background(), cfp.scanDetails.RepoOwner, cfp.scanDetails.RepoName, fixBranchName, cfp.scanDetails.BaseBranch(), pullRequestTitle, prBody); err != nil {
			return
		}
		return cfp.getOpenPullRequestBySourceBranch(fixBranchName)
	}
	log.Info("Updating Pull Request from:", fixBranchName, "to:", cfp.scanDetails.BaseBranch())
	if err = cfp.scanDetails.Client().UpdatePullRequest(context.Background(), cfp.scanDetails.RepoOwner, cfp.scanDetails.RepoName, pullRequestTitle, prBody, pullRequestInfo.Target.Name, int(pullRequestInfo.ID), vcsutils.Open); err != nil {
		return
	}
	// Delete old extra comments
	return pullRequestInfo, utils.DeletePullRequestComments(repository, cfp.scanDetails.Client(), int(pullRequestInfo.ID))
}

// Handles the opening or updating of a pull request when the aggregate mode is active.
// If a pull request is already open, Frogbot will update the branch and the pull request body.
func (cfp *ScanRepositoryCmd) openAggregatedPullRequest(repository *utils.Repository, fixBranchName string, pullRequestInfo *vcsclient.PullRequestInfo, vulnerabilities []*utils.VulnerabilityDetails) (err error) {
	commitMessage := cfp.gitManager.GenerateAggregatedCommitMessage(cfp.projectTech)
	if err = cfp.cleanNewFilesMissingInRemote(); err != nil {
		return
	}
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	if err = cfp.gitManager.Push(true, fixBranchName); err != nil {
		return
	}
	return cfp.handleFixPullRequestContent(repository, fixBranchName, pullRequestInfo, vulnerabilities...)
}

func (cfp *ScanRepositoryCmd) cleanNewFilesMissingInRemote() error {
	// Open the local repository
	localRepo, err := git.PlainOpen(cfp.baseWd)
	if err != nil {
		return err
	}

	// Getting the repository working tree
	worktree, err := localRepo.Worktree()
	if err != nil {
		return err
	}

	// Getting the working tree status
	gitStatus, err := worktree.Status()
	if err != nil {
		return err
	}

	for relativeFilePath, status := range gitStatus {
		if status.Worktree == git.Untracked {
			log.Debug(fmt.Sprintf("Untracking file '%s' that was created locally during the scan/fix process", relativeFilePath))
			fileDeletionErr := os.Remove(filepath.Join(cfp.baseWd, relativeFilePath))
			if fileDeletionErr != nil {
				err = errors.Join(err, fmt.Errorf("file '%s': %s\n", relativeFilePath, fileDeletionErr.Error()))
				continue
			}
		}
	}
	return err
}

func (cfp *ScanRepositoryCmd) preparePullRequestDetails(vulnerabilitiesDetails ...*utils.VulnerabilityDetails) (prTitle, prBody string, otherComments []string, err error) {
	if cfp.dryRun && cfp.aggregateFixes {
		// For testings, don't compare pull request body as scan results order may change.
		return cfp.gitManager.GenerateAggregatedPullRequestTitle(cfp.projectTech), "", []string{}, nil
	}
	vulnerabilitiesRows := utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilitiesDetails)

	prBody, extraComments := utils.GenerateFixPullRequestDetails(vulnerabilitiesRows, cfp.OutputWriter)

	if cfp.aggregateFixes {
		var scanHash string
		if scanHash, err = utils.VulnerabilityDetailsToMD5Hash(vulnerabilitiesRows...); err != nil {
			return
		}
		return cfp.gitManager.GenerateAggregatedPullRequestTitle(cfp.projectTech), prBody + outputwriter.MarkdownComment(fmt.Sprintf("Checksum: %s", scanHash)), extraComments, nil
	}
	// In separate pull requests there is only one vulnerability
	vulnDetails := vulnerabilitiesDetails[0]
	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	return pullRequestTitle, prBody, extraComments, nil
}

func (cfp *ScanRepositoryCmd) cloneRepositoryOrUseLocalAndCheckoutToBranch() (tempWd string, restoreDir func() error, err error) {
	if cfp.dryRun {
		tempWd = filepath.Join(cfp.dryRunRepoPath, cfp.scanDetails.RepoName)
	} else {
		// Create temp working directory
		if tempWd, err = fileutils.CreateTempDir(); err != nil {
			return
		}
	}
	log.Debug("Created temp working directory:", tempWd)

	if cfp.scanDetails.UseLocalRepository {
		var curDir string
		if curDir, err = os.Getwd(); err != nil {
			return
		}
		if err = biutils.CopyDir(curDir, tempWd, true, nil); err != nil {
			return
		}
		// 'CD' into the temp working directory
		restoreDir, err = utils.Chdir(tempWd)
		if err != nil {
			return
		}
		// Set the current copied local dir as the local git repository we are working with
		err = cfp.gitManager.SetLocalRepository()
	} else {
		// Clone the content of the repo to the new working directory
		if err = cfp.gitManager.Clone(tempWd, cfp.scanDetails.BaseBranch()); err != nil {
			return
		}
		// 'CD' into the temp working directory
		restoreDir, err = utils.Chdir(tempWd)
	}
	return
}

// Create a vulnerabilities map - a map with 'impacted package' as a key and all the necessary information of this vulnerability as value.
func (cfp *ScanRepositoryCmd) createVulnerabilitiesMap(scanResults *results.SecurityCommandResults) (map[string]*utils.VulnerabilityDetails, error) {
	vulnerabilitiesMap := map[string]*utils.VulnerabilityDetails{}
	simpleJsonResult, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: scanResults.IncludesVulnerabilities(), HasViolationContext: scanResults.HasViolationContext()}).ConvertToSimpleJson(scanResults)
	if err != nil {
		return nil, err
	}
	if len(simpleJsonResult.Vulnerabilities) > 0 {
		for i := range simpleJsonResult.Vulnerabilities {
			if err = cfp.addVulnerabilityToFixVersionsMap(&simpleJsonResult.Vulnerabilities[i], vulnerabilitiesMap); err != nil {
				return nil, err
			}
		}
	} else if len(simpleJsonResult.SecurityViolations) > 0 {
		for i := range simpleJsonResult.SecurityViolations {
			if err = cfp.addVulnerabilityToFixVersionsMap(&simpleJsonResult.SecurityViolations[i], vulnerabilitiesMap); err != nil {
				return nil, err
			}
		}
	}
	if len(vulnerabilitiesMap) > 0 {
		log.Debug("Frogbot will attempt to resolve the following vulnerable dependencies:\n", strings.Join(maps.Keys(vulnerabilitiesMap), ",\n"))
	}
	return vulnerabilitiesMap, nil
}

func (cfp *ScanRepositoryCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	if len(cfp.projectTech) == 0 {
		cfp.projectTech = []techutils.Technology{vulnerability.Technology}
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}
	if vulnDetails, exists := vulnerabilitiesMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above-impacted package, we select the maximum fix version.
		vulnDetails.UpdateFixVersionIfMax(vulnFixVersion)
	} else {
		isDirectDependency, err := utils.IsDirectDependency(vulnerability.ImpactPaths)
		if err != nil {
			if cfp.scanDetails.AllowPartialResults() {
				log.Warn(fmt.Sprintf("An error occurred while determining if the dependency '%s' is direct: %s.\nAs partial results are permitted, the vulnerability will not be fixed", vulnerability.ImpactedDependencyName, err.Error()))
			} else {
				return err
			}
		}
		// First appearance of a version that fixes the current impacted package
		newVulnDetails := utils.NewVulnerabilityDetails(*vulnerability, vulnFixVersion)
		newVulnDetails.SetIsDirectDependency(isDirectDependency)
		vulnerabilitiesMap[vulnerability.ImpactedDependencyName] = newVulnDetails
	}
	// Set the fixed version array to the relevant fixed version so that only that specific fixed version will be displayed
	vulnerability.FixedVersions = []string{vulnerabilitiesMap[vulnerability.ImpactedDependencyName].SuggestedFixedVersion}
	return nil
}

// Updates impacted package, can return ErrUnsupportedFix.
func (cfp *ScanRepositoryCmd) updatePackageToFixedVersion(vulnDetails *utils.VulnerabilityDetails) (err error) {
	if err = isBuildToolsDependency(vulnDetails); err != nil {
		return
	}

	if cfp.handlers == nil {
		cfp.handlers = make(map[techutils.Technology]packagehandlers.PackageHandler)
	}

	handler := cfp.handlers[vulnDetails.Technology]
	if handler == nil {
		handler = packagehandlers.GetCompatiblePackageHandler(vulnDetails, cfp.scanDetails)
		cfp.handlers[vulnDetails.Technology] = handler
	} else if _, unsupported := handler.(*packagehandlers.UnsupportedPackageHandler); unsupported {
		return
	}

	return cfp.handlers[vulnDetails.Technology].UpdateDependency(vulnDetails)
}

// The getRemoteBranchScanHash function extracts the checksum written inside the pull request body and returns it.
func (cfp *ScanRepositoryCmd) getRemoteBranchScanHash(prBody string) string {
	// The pattern matches the string "Checksum: <checksum>", followed by one or more word characters (letters, digits, or underscores).
	re := regexp.MustCompile(`Checksum: (\w+)`)
	match := re.FindStringSubmatch(prBody)

	// The first element is the entire matched string, and the second element is the checksum value.
	// If the length of match is not equal to 2, it means that the pattern was not found or the captured group is missing.
	if len(match) != 2 {
		log.Debug("Checksum not found in the aggregated pull request. Frogbot will proceed to update the existing pull request.")
		return ""
	}

	return match[1]
}

func (cfp *ScanRepositoryCmd) getOpenPullRequestBySourceBranch(branchName string) (prInfo *vcsclient.PullRequestInfo, err error) {
	list, err := cfp.scanDetails.Client().ListOpenPullRequestsWithBody(context.Background(), cfp.scanDetails.RepoOwner, cfp.scanDetails.RepoName)
	if err != nil {
		return
	}
	for _, pr := range list {
		if pr.Source.Name == branchName {
			log.Debug("Found pull request from source branch ", branchName)
			return &pr, nil
		}
	}
	log.Debug("No pull request found from source branch ", branchName)
	return
}

func (cfp *ScanRepositoryCmd) aggregateFixAndOpenPullRequest(repository *utils.Repository, vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails, aggregatedFixBranchName string, existingPullRequestInfo *vcsclient.PullRequestInfo) (err error) {
	log.Info("-----------------------------------------------------------------")
	log.Info("Starting aggregated dependencies fix")

	workTreeIsClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if !workTreeIsClean {
		// If there are local changes, such as files generated after running an 'install' command, we aim to preserve them in the new branch
		err = cfp.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName, true)
	} else {
		err = cfp.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName, false)
	}
	if err != nil {
		return
	}

	// Fix all packages in the same branch if expected error accrued, log and continue.
	var fixedVulnerabilities []*utils.VulnerabilityDetails
	for fullPath, vulnerabilities := range vulnerabilitiesMap {
		currentFixes, e := cfp.fixMultiplePackages(fullPath, vulnerabilities)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("the following errors occurred while fixing vulnerabilities in %s:\n%s", fullPath, e))
			continue
		}
		fixedVulnerabilities = append(fixedVulnerabilities, currentFixes...)
	}
	updateRequired, e := cfp.isUpdateRequired(fixedVulnerabilities, existingPullRequestInfo)
	if e != nil {
		err = errors.Join(err, e)
		return
	}
	if !updateRequired {
		err = errors.Join(err, cfp.gitManager.Checkout(cfp.scanDetails.BaseBranch()))
		log.Info("The existing pull request is in sync with the latest scan, and no further updates are required.")
		return
	}
	if len(fixedVulnerabilities) > 0 {
		if e = cfp.openAggregatedPullRequest(repository, aggregatedFixBranchName, existingPullRequestInfo, fixedVulnerabilities); e != nil {
			err = errors.Join(err, fmt.Errorf("failed while creating aggregated pull request. Error: \n%s", e.Error()))
		}
	}
	log.Info("-----------------------------------------------------------------")
	err = errors.Join(err, cfp.gitManager.Checkout(cfp.scanDetails.BaseBranch()))
	return
}

// Determines whether an update is necessary:
// First, checks if the working tree is clean. If so, no update is required.
// Second, checks if there is an already open pull request for the fix. If so, no update is needed.
// Lastly, performs a comparison of Xray scan result hashes between an existing pull request's remote source branch and the current source branch to identify any differences.
func (cfp *ScanRepositoryCmd) isUpdateRequired(fixedVulnerabilities []*utils.VulnerabilityDetails, prInfo *vcsclient.PullRequestInfo) (updateRequired bool, err error) {
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		log.Info("There were no changes to commit after fixing vulnerabilities.\nNote: Frogbot currently cannot address certain vulnerabilities in some package managers, which may result in the absence of changes")
		updateRequired = false
		return
	}

	if prInfo == nil {
		updateRequired = true
		return
	}
	log.Info("Aggregated pull request already exists, verifying if update is needed...")
	log.Debug("Comparing current scan results to existing", prInfo.Target.Name, "scan results")
	fixedVulnerabilitiesRows := utils.ExtractVulnerabilitiesDetailsToRows(fixedVulnerabilities)
	currentScanHash, err := utils.VulnerabilityDetailsToMD5Hash(fixedVulnerabilitiesRows...)
	if err != nil {
		return
	}
	remoteBranchScanHash := cfp.getRemoteBranchScanHash(prInfo.Body)
	updateRequired = currentScanHash != remoteBranchScanHash
	if updateRequired {
		log.Info("The existing pull request is not in sync with the latest scan, updating pull request...")
	}
	return
}

// getMinimalFixVersion find the minimal version that fixes the current impactedPackage;
// fixVersions is a sorted array. The function returns the first version in the array, that is larger than impactedPackageVersion.
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) string {
	// Trim 'v' prefix in case of Go package
	currVersionStr := strings.TrimPrefix(impactedPackageVersion, "v")
	currVersion := version.NewVersion(currVersionStr)
	for _, fixVersion := range fixVersions {
		fixVersionCandidate := parseVersionChangeString(fixVersion)
		if currVersion.Compare(fixVersionCandidate) > 0 {
			return fixVersionCandidate
		}
	}
	return ""
}

// 1.0         --> 1.0 ≤ x
// (,1.0]      --> x ≤ 1.0
// (,1.0)      --> x < 1.0
// [1.0]       --> x == 1.0
// (1.0,)      --> 1.0 >= x
// (1.0, 2.0)  --> 1.0 < x < 2.0
// [1.0, 2.0]  --> 1.0 ≤ x ≤ 2.0
func parseVersionChangeString(fixVersion string) string {
	latestVersion := strings.Split(fixVersion, ",")[0]
	if latestVersion[0] == '(' {
		return ""
	}
	latestVersion = strings.Trim(latestVersion, "[")
	latestVersion = strings.Trim(latestVersion, "]")
	return latestVersion
}

// Skip build tools dependencies (for example, pip)
// that are not defined in the descriptor file and cannot be fixed by a PR.
func isBuildToolsDependency(vulnDetails *utils.VulnerabilityDetails) error {
	//nolint:typecheck // Ignoring typecheck error: The linter fails to deduce the returned type as []string from utils.BuildToolsDependenciesMap, despite its declaration in utils/utils.go as map[coreutils.Technology][]string.
	if slices.Contains(utils.BuildToolsDependenciesMap[vulnDetails.Technology], vulnDetails.ImpactedDependencyName) {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.BuildToolsDependencyFixNotSupported,
		}
	}
	return nil
}
