package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Package names are case-insensitive with this prefix
var pythonPackageRegexPrefix = "(?i)"

// Match all possible operators and versions syntax
var pythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"

type CreateFixPullRequestsCmd struct {
	// mavenDepToPropertyMap holds a map of dependencies to their version properties for maven vulnerabilities
	mavenDepToPropertyMap map[string][]string
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

func (cfp CreateFixPullRequestsCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repoConfig := &configAggregator[0]
	for _, branch := range repoConfig.Branches {
		err := cfp.scanAndFixRepository(repoConfig, client, branch)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient, branch string) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	xrayScanParams := createXrayScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey)
	for projectIndex, project := range repoConfig.Projects {
		projectFullPathWorkingDirs := getFullPathWorkingDirs(&repoConfig.Projects[projectIndex], baseWd)
		for _, fullPathWd := range projectFullPathWorkingDirs {
			scanResults, err := cfp.scan(project, &repoConfig.Server, xrayScanParams, *repoConfig.FailOnSecurityIssues, fullPathWd)
			if err != nil {
				return err
			}

			// Upload scan results to the relevant Git provider code scanning UI
			scanResults = utils.SimplifyScanResults(scanResults)
			err = utils.UploadScanToGitProvider(scanResults, repoConfig, branch, client)
			if err != nil {
				clientLog.Warn(err)
			}

			// Fix and create PRs
			relativeCurrentWd := utils.GetRelativeWd(fullPathWd, baseWd)
			if err = cfp.fixImpactedPackagesAndCreatePRs(project, &repoConfig.Git, branch, client, scanResults, relativeCurrentWd); err != nil {
				return err
			}
		}
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(project utils.Project, server *coreconfig.ServerDetails, xrayScanParams services.XrayGraphScanParams,
	failOnSecurityIssues bool, currentWorkingDir string) ([]services.ScanResponse, error) {
	// Audit commit code
	scanResults, err := runInstallAndAudit(xrayScanParams, &project, server, failOnSecurityIssues, currentWorkingDir)
	if err != nil {
		return nil, err
	}
	clientLog.Info("Xray scan completed")
	return scanResults, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(project utils.Project, repoGitParams *utils.Git, branch string,
	client vcsclient.VcsClient, scanResults []services.ScanResponse, currentWd string) (err error) {
	fixVersionsMap, err := cfp.createFixVersionsMap(&project, scanResults)
	if err != nil {
		return err
	}
	// Nothing to fix, return
	if len(fixVersionsMap) == 0 {
		clientLog.Info("Didn't find vulnerable dependencies with existing fix versions for", repoGitParams.RepoName)
		return nil
	}
	clientLog.Info("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")

	// Create temp working directory
	wd, err := fileutils.CreateTempDir()
	if err != nil {
		return err
	}
	defer func() {
		e := fileutils.RemoveTempDir(wd)
		if err == nil {
			err = e
		}
	}()
	clientLog.Debug("Created temp working directory:", wd)

	// Clone the content of the repo to the new working directory
	gitManager, err := utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", repoGitParams.Token, repoGitParams.RepoOwner)
	if err != nil {
		return err
	}

	err = gitManager.Clone(wd, branch)
	if err != nil {
		return err
	}

	// 'CD' into the temp working directory
	restoreDir, err := utils.Chdir(wd)
	if err != nil {
		return
	}
	defer func() {
		e := restoreDir()
		if err == nil {
			err = e
		}
	}()

	// Fix all impacted packages
	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		clientLog.Info("-----------------------------------------------------------------")
		clientLog.Info("Start fixing", impactedPackage, "with", fixVersionInfo.fixVersion)
		err = cfp.fixSinglePackageAndCreatePR(impactedPackage, *fixVersionInfo, &project, branch, repoGitParams, client, gitManager, currentWd)
		if err != nil {
			clientLog.Error("failed while trying to fix and create PR for:", impactedPackage, "with version:", fixVersionInfo.fixVersion, "with error:", err.Error())
		}
		// After finishing to work on the current vulnerability we go back to the base branch to start the next vulnerability fix
		clientLog.Info("Running git checkout to base branch:", branch)
		err = gitManager.Checkout(branch)
		if err != nil {
			return err
		}

	}
	return nil
}

// Create fixVersionMap - a map between impacted packages and their fix version
func (cfp *CreateFixPullRequestsCmd) createFixVersionsMap(project *utils.Project, scanResults []services.ScanResponse) (map[string]*FixVersionInfo, error) {
	fixVersionsMap := map[string]*FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, false)
			if err != nil {
				return nil, err
			}
			for _, vulnerability := range vulnerabilities {
				if vulnerability.FixedVersions != nil && len(vulnerability.FixedVersions) > 0 {
					fixVulnerability, err := cfp.shouldFixVulnerability(project, vulnerability)
					if err != nil {
						return nil, err
					}
					if !fixVulnerability {
						continue
					}
					vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedPackageVersion, vulnerability.FixedVersions)
					if vulnFixVersion == "" {
						continue
					}

					fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedPackageName]
					if exists {
						// More than one vulnerability can exist on the same impacted package.
						// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
						fixVersionInfo.UpdateFixVersion(vulnFixVersion)
					} else {
						// First appearance of a version that fixes the current impacted package
						fixVersionsMap[vulnerability.ImpactedPackageName] = NewFixVersionInfo(vulnFixVersion, vulnerability.Technology)
					}
				}
			}
		}
	}
	return fixVersionsMap, nil
}

// getMinimalFixVersion that fixes the current impactedPackage
// fixVersions array is sorted, so we take the first index, unless it's version is older than what we have now.
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

func (cfp *CreateFixPullRequestsCmd) shouldFixVulnerability(project *utils.Project, vulnerability formats.VulnerabilityOrViolationRow) (bool, error) {
	// In Maven, fix only direct dependencies
	if vulnerability.Technology == coreutils.Maven {
		if cfp.mavenDepToPropertyMap == nil {
			cfp.mavenDepToPropertyMap = make(map[string][]string)
			for _, workingDir := range project.WorkingDirs {
				if workingDir == utils.RootDir {
					workingDir = ""
				}
				err := utils.GetVersionProperties(workingDir, cfp.mavenDepToPropertyMap)
				if err != nil {
					return false, err
				}
			}
		}
		if _, exist := cfp.mavenDepToPropertyMap[vulnerability.ImpactedPackageName]; !exist {
			return false, nil
		}
	}
	return true, nil
}

func (cfp *CreateFixPullRequestsCmd) fixSinglePackageAndCreatePR(impactedPackage string, fixVersionInfo FixVersionInfo, project *utils.Project,
	branch string, repoGitParams *utils.Git, client vcsclient.VcsClient, gitManager *utils.GitManager, currentWd string) (err error) {
	fixBranchName, err := generateFixBranchName(branch, impactedPackage, fixVersionInfo.fixVersion)
	if err != nil {
		return err
	}

	exists, err := gitManager.BranchExistsOnRemote(fixBranchName)
	if err != nil {
		return err
	}
	if exists {
		clientLog.Info("Branch:", fixBranchName, "already exists on remote.")
		return
	}

	clientLog.Info("Creating branch:", fixBranchName)
	err = gitManager.CreateBranchAndCheckout(fixBranchName)
	if err != nil {
		return err
	}

	err = cfp.updatePackageToFixedVersion(fixVersionInfo.packageType, impactedPackage, fixVersionInfo.fixVersion, project.PipRequirementsFile, currentWd)
	if err != nil {
		return err
	}

	clientLog.Info("Checking if there are changes to commit")
	isClean, err := gitManager.IsClean()
	if err != nil {
		return err
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", impactedPackage)
	}

	clientLog.Info("Running git add all and commit")
	commitString := fmt.Sprintf("[🐸 Frogbot] Upgrade %s to %s", impactedPackage, fixVersionInfo.fixVersion)
	err = gitManager.AddAllAndCommit(commitString)
	if err != nil {
		return err
	}
	clientLog.Info("Pushing fix branch:", fixBranchName)
	err = gitManager.Push()
	if err != nil {
		return err
	}
	clientLog.Info("Creating Pull Request form:", fixBranchName, " to:", branch)
	prBody := commitString + "\n\n" + utils.WhatIsFrogbotMd
	err = client.CreatePullRequest(context.Background(), repoGitParams.RepoOwner, repoGitParams.RepoName, fixBranchName, branch, commitString, prBody)
	return
}

func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(packageType coreutils.Technology, impactedPackage, fixVersion, requirementsFile string, workingDir string) (err error) {
	// 'CD' into the relevant working directory
	if workingDir != "" {
		restoreDir, err := utils.Chdir(workingDir)
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

	switch packageType {
	case coreutils.Go:
		commandArgs := []string{"get"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@v")
	case coreutils.Npm:
		commandArgs := []string{"install"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@")
	case coreutils.Maven:
		err = fixPackageVersionMaven(cfp, impactedPackage, fixVersion)
	case coreutils.Yarn:
		commandArgs := []string{"up"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@")
	case coreutils.Pip:
		err = fixPackageVersionPip(impactedPackage, fixVersion, requirementsFile)
	case coreutils.Pipenv:
		commandArgs := []string{"install"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "==")
	case coreutils.Poetry:
		err = fixPackageVersionPoetry(impactedPackage, fixVersion)
	default:
		return fmt.Errorf("package type: %s is currently not supported", string(packageType))
	}

	return
}

// The majority of package managers already support upgrading specific package versions and update the dependency files automatically.
// In other cases, we had to handle the upgrade process
// commandName - Name of the package manager
// commandArgs - Package manager upgrade command
// impactedPackage - Vulnerable package to upgrade
// fixVersion - The version that fixes the vulnerable package
// operator - The operator between the impactedPackage to the fixVersion
func fixPackageVersionGeneric(commandName string, commandArgs []string, impactedPackage, fixVersion, operator string) error {
	fixedPackage := impactedPackage + operator + fixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(commandName, commandArgs)
}

func runPackageMangerCommand(commandName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	clientLog.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("%s command failed: %s\n%s", fullCommand, err.Error(), output)
	}
	return nil
}

func fixPackageVersionMaven(cfp *CreateFixPullRequestsCmd, impactedPackage, fixVersion string) error {
	properties := cfp.mavenDepToPropertyMap[impactedPackage]
	// Update the package version. This command updates it only if the version is not a reference to a property.
	updateVersionArgs := []string{"-B", "versions:use-dep-version", "-Dincludes=" + impactedPackage, "-DdepVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	clientLog.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	updateVersionOutput, err := exec.Command("mvn", updateVersionArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updateVersionOutput)
	}

	// Update properties that represent this package's version.
	for _, property := range properties {
		updatePropertyArgs := []string{"-B", "versions:set-property", "-Dproperty=" + property, "-DnewVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
		updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
		clientLog.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
		updatePropertyOutput, err := exec.Command("mvn", updatePropertyArgs...).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updatePropertyOutput)
		}
	}

	return nil
}

func fixPackageVersionPip(impactedPackage, fixVersion, requirementsFile string) error {
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := impactedPackage + "==" + fixVersion
	if requirementsFile == "" {
		requirementsFile = "setup.py"
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	fullPath := filepath.Join(wd, requirementsFile)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return errors.New("wrong requirements file input")
	}
	data, err := os.ReadFile(filepath.Clean(requirementsFile))
	if err != nil {
		return err
	}
	currentFile := string(data)
	// This regex will match the impactedPackage with it's pinned version e.g. PyJWT==1.7.1
	re := regexp.MustCompile(pythonPackageRegexPrefix + impactedPackage + pythonPackageRegexSuffix)
	packageToReplace := re.FindString(currentFile)
	if packageToReplace == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", packageToReplace)
	}
	fixedFile := strings.Replace(currentFile, packageToReplace, fixedPackage, 1)
	err = os.WriteFile(requirementsFile, []byte(fixedFile), 0600)
	if err != nil {
		return err
	}

	return nil
}

func fixPackageVersionPoetry(impactedPackage, fixVersion string) error {
	// Install the desired fixed version
	err := fixPackageVersionGeneric(coreutils.Poetry.GetExecCommandName(), []string{"add"}, impactedPackage, fixVersion, "==")
	if err != nil {
		return err
	}
	// Update Poetry lock file as well
	return runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
}

func generateFixBranchName(baseBranch, impactedPackage, fixVersion string) (string, error) {
	uniqueString, err := utils.Md5Hash("frogbot", baseBranch, impactedPackage, fixVersion)
	if err != nil {
		return "", err
	}
	// Package names in Maven usually contain colons, which are not allowed in a branch name
	fixedPackageName := strings.ReplaceAll(impactedPackage, ":", "_")
	// fixBranchName example: 'frogbot-gopkg.in/yaml.v3-cedc1e5462e504fc992318d24e343e48'
	return fmt.Sprintf("%s-%s-%s", "frogbot", fixedPackageName, uniqueString), nil
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

type FixVersionInfo struct {
	fixVersion  string
	packageType coreutils.Technology
}

func NewFixVersionInfo(newFixVersion string, packageType coreutils.Technology) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	// Update fvi.fixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if fvi.fixVersion == "" || version.NewVersion(fvi.fixVersion).Compare(newFixVersion) > 0 {
		fvi.fixVersion = newFixVersion
	}
}
