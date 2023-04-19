package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/frogbot/commands/utils/packagehandlers"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"strings"
)

type CreateFixPullRequestsCmd struct {
	// mavenDepToPropertyMap holds a map of direct dependencies found in pom.xml.
	// Keys values are only set if the key version is a property.
	mavenDepToPropertyMap map[string][]string
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The details of the current scan
	details *utils.ScanDetails
	// The current project working directory
	projectWorkingDir string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
}

func (cfp *CreateFixPullRequestsCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repository := configAggregator[0]
	for _, branch := range repository.Branches {
		err := cfp.scanAndFixRepository(&repository, branch, client)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repository *utils.FrogbotRepoConfig, branch string, client vcsclient.VcsClient) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfp.details = &utils.ScanDetails{
		XrayGraphScanParams:      createXrayScanParams(repository.Watches, repository.JFrogProjectKey),
		ServerDetails:            &repository.Server,
		Git:                      &repository.Git,
		Client:                   client,
		FailOnInstallationErrors: *repository.FailOnSecurityIssues,
		Branch:                   branch,
		ReleasesRepo:             repository.JfrogReleasesRepo,
	}
	for _, project := range repository.Projects {
		cfp.details.Project = project
		projectFullPathWorkingDirs := getFullPathWorkingDirs(project.WorkingDirs, baseWd)
		for _, fullPathWd := range projectFullPathWorkingDirs {
			scanResults, isMultipleRoots, err := cfp.scan(cfp.details, fullPathWd)
			if err != nil {
				return err
			}

			err = utils.UploadScanToGitProvider(scanResults, repository, cfp.details.Branch, cfp.details.Client, isMultipleRoots)
			if err != nil {
				log.Warn(err)
			}

			// Update the working directory to the project current working directory
			cfp.projectWorkingDir = utils.GetRelativeWd(fullPathWd, baseWd)
			// Fix and create PRs
			if err = cfp.fixImpactedPackagesAndCreatePRs(scanResults, isMultipleRoots); err != nil {
				return err
			}
		}
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(scanSetup *utils.ScanDetails, currentWorkingDir string) ([]services.ScanResponse, bool, error) {
	// Audit commit code
	scanResults, isMultipleRoots, err := runInstallAndAudit(scanSetup, currentWorkingDir)
	if err != nil {
		return nil, false, err
	}
	log.Info("Xray scan completed")
	return scanResults, isMultipleRoots, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(scanResults []services.ScanResponse, isMultipleRoots bool) (err error) {
	fixVersionsMap, err := cfp.createFixVersionsMap(scanResults, isMultipleRoots)
	if err != nil {
		return err
	}

	// Nothing to fix, return
	if len(fixVersionsMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.details.RepoName)
		return nil
	}

	log.Info("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")
	return cfp.fixVulnerablePackages(fixVersionsMap)
}

func (cfp *CreateFixPullRequestsCmd) fixVulnerablePackages(fixVersionsMap map[string]*utils.FixVersionInfo) (err error) {
	cfp.gitManager, err = utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", cfp.details.Token, cfp.details.Username, cfp.details.Git)
	if err != nil {
		return
	}

	clonedRepoDir, restoreBaseDir, err := cfp.cloneRepository()
	if err != nil {
		return
	}
	defer func() {
		e1 := restoreBaseDir()
		e2 := fileutils.RemoveTempDir(clonedRepoDir)
		if err == nil {
			err = e1
			if err == nil {
				err = e2
			}
		}
	}()

	// Fix all impacted packages
	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		if err = cfp.fixSinglePackage(impactedPackage, fixVersionInfo); err != nil {
			log.Warn(err)
		}
		// After finishing to work on the current vulnerability, we go back to the base branch to start the next vulnerability fix
		log.Info("Running git checkout to base branch:", cfp.details.Branch)
		if err = cfp.gitManager.Checkout(cfp.details.Branch); err != nil {
			return
		}
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) fixSinglePackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (err error) {
	log.Info("-----------------------------------------------------------------")
	log.Info("Start fixing", impactedPackage, "with", fixVersionInfo.FixVersion)
	fixBranchName, err := cfp.createFixingBranch(impactedPackage, fixVersionInfo)
	if err != nil {
		return fmt.Errorf("failed while creating new branch: \n%s", err.Error())
	}

	if err = cfp.updatePackageToFixedVersion(impactedPackage, fixVersionInfo); err != nil {
		return fmt.Errorf("failed while fixing %s with version: %s with error: \n%s", impactedPackage, fixVersionInfo.FixVersion, err.Error())
	}

	if err = cfp.openFixingPullRequest(impactedPackage, fixBranchName, fixVersionInfo); err != nil {
		return fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: \n%s",
			impactedPackage, fixVersionInfo.FixVersion, err.Error())
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) openFixingPullRequest(impactedPackage, fixBranchName string, fixVersionInfo *utils.FixVersionInfo) (err error) {
	log.Info("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", impactedPackage)
	}

	commitMessage := cfp.gitManager.GenerateCommitMessage(impactedPackage, fixVersionInfo.FixVersion)
	log.Info("Running git add all and commit...")
	err = cfp.gitManager.AddAllAndCommit(commitMessage)
	if err != nil {
		return
	}

	log.Info("Pushing fix branch:", fixBranchName, "...")
	err = cfp.gitManager.Push()
	if err != nil {
		return
	}

	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(impactedPackage, fixVersionInfo.FixVersion)
	log.Info("Creating Pull Request form:", fixBranchName, " to:", cfp.details.Branch)
	prBody := commitMessage + "\n\n" + utils.WhatIsFrogbotMd
	return cfp.details.Client.CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch, pullRequestTitle, prBody)
}

func (cfp *CreateFixPullRequestsCmd) createFixingBranch(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (fixBranchName string, err error) {
	fixBranchName, err = cfp.gitManager.GenerateFixBranchName(cfp.details.Branch, impactedPackage, fixVersionInfo.FixVersion)
	if err != nil {
		return
	}

	exists, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	log.Info("Creating branch", fixBranchName, "...")
	if exists {
		return "", fmt.Errorf("branch %s already exists in the remote git repository", fixBranchName)
	}

	return fixBranchName, cfp.gitManager.CreateBranchAndCheckout(fixBranchName)
}

func (cfp *CreateFixPullRequestsCmd) cloneRepository() (tempWd string, restoreDir func() error, err error) {
	// Create temp working directory
	tempWd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	log.Debug("Created temp working directory:", tempWd)

	// Clone the content of the repo to the new working directory
	err = cfp.gitManager.Clone(tempWd, cfp.details.Branch)
	if err != nil {
		return
	}

	// 'CD' into the temp working directory
	restoreDir, err = utils.Chdir(tempWd)
	return
}

// Create fixVersionMap - a map with 'impacted package' as key and 'fix version' as value.
func (cfp *CreateFixPullRequestsCmd) createFixVersionsMap(scanResults []services.ScanResponse, isMultipleRoots bool) (map[string]*utils.FixVersionInfo, error) {
	fixVersionsMap := map[string]*utils.FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, isMultipleRoots, true)
			if err != nil {
				return nil, err
			}
			for i := range vulnerabilities {
				if err = cfp.addVulnerabilityToFixVersionsMap(&vulnerabilities[i], fixVersionsMap); err != nil {
					return nil, err
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func (cfp *CreateFixPullRequestsCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*utils.FixVersionInfo) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}
	if fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
		fixVersionInfo.UpdateFixVersionIfMax(vulnFixVersion)
	} else {
		isDirectDependency, err := utils.IsDirectDependency(vulnerability.ImpactPaths)
		if err != nil {
			return err
		}
		// First appearance of a version that fixes the current impacted package
		fixVersionsMap[vulnerability.ImpactedDependencyName] = utils.NewFixVersionInfo(vulnFixVersion, vulnerability.Technology, isDirectDependency)
	}
	return nil
}

// getMinimalFixVersion that fixes the current impactedPackage
// fixVersions array is sorted, so we take the first index, unless it's version is older than what we have now.
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) string {
	// Trim 'v' prefix in case of Go package
	currVersionStr := strings.TrimPrefix(impactedPackageVersion, "v")
	currVersion := version.NewVersion(currVersionStr)
	for _, fixVersion := range fixVersions {
		fixVersionCandidate := parseVersionChangeString(fixVersion)
		// Don't allow major version changes
		majorChanged := utils.IsMajorVersionChange(fixVersionCandidate, currVersionStr)
		if majorChanged {
			return ""
		}
		if currVersion.Compare(fixVersionCandidate) > 0 {
			return fixVersionCandidate
		}
	}
	return ""
}

func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (err error) {
	// 'CD' into the relevant working directory
	if cfp.projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(cfp.projectWorkingDir)
		if err != nil {
			return err
		}
		defer func() {
			e := restoreDir()
			if err == nil {
				err = e
			} else if e != nil {
				err = fmt.Errorf("%s\n%s", err.Error(), e.Error())
			}
		}()
	}
	packageHandler := packagehandlers.GetCompatiblePackageHandler(fixVersionInfo, cfp.details, &cfp.mavenDepToPropertyMap)
	return packageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
}

// 1.0         --> 1.0 ≤ x
// (,1.0]      --> x ≤ 1.0
// (,1.0)      --> x &lt; 1.0
// [1.0]       --> x == 1.0
// (1.0,)      --> 1.0 &lt; x
// (1.0, 2.0)  --> 1.0 &lt; x &lt; 2.0
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
